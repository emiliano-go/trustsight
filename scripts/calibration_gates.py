"""- the calibration gates, enforced.

`rebaseline.py` records what the fire rates *are*; this script decides
whether they are *allowed*. Every gate here is one line of the plan's
list turned into a number and a comparison, so a rule that drifts into
noise, a weight-0 annotation that quietly starts scoring, or a detection
that stops detecting fails the build instead of being noticed a month later
in a drift issue.

Usage:
    python scripts/calibration_gates.py
    python scripts/calibration_gates.py --sample 4 --json gates.json

Exit code is 1 if any gate fails, 0 otherwise.  `--sample N` scans every
Nth benign diff, which the test suite uses to keep a full corpus replay out
of the default run; the CI job runs it whole.
"""

from __future__ import annotations

import argparse
import json
import math
import multiprocessing
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import trustsight.config as config_module
import trustsight.db as db_module
from trustsight.analysis import scan_diff
from trustsight.analysis.base import _GLOBAL_URL_KEY
from trustsight.analysis.pipeline import scored_source_urls
from trustsight.config import ensure_default_configs, load_config
from trustsight.novelty import normalize_url
from trustsight.rules import (
    load_rules,
    precompile_patterns,
    precompile_structural_patterns,
    resolve_generated_patterns,
)
from trustsight.sandbox.client import reset_after_fork
from trustsight.sandbox.git_client import reset_after_fork as reset_git_after_fork
# Bootstrap the import path before reaching the ``scripts.calibration`` package.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

import scripts.calibration._core as _calib_core

def _write_scan_rows(path: Path, benign: list[dict],
                     malicious: list[dict]) -> None:
    """The fired rule ids per diff, in scan order.

    ``h_reduction_audit`` needs exactly this and nothing else from the
    scan, so re-scanning the corpus to rebuild it is a duplicated five
    minutes.  Writing it here lets the audit read it instead.  Only the
    whole corpus is meaningful (a sample moves the indices), so callers
    pass ``--sample 1``.
    """
    path.write_text(json.dumps({
        "benign": [[e["rule_id"] for e in row["entries"]] for row in benign],
        "benign_packages": [row.get("package", "") for row in benign],
        "benign_paths": [str(row.get("path", "")) for row in benign],
        "malicious": [sorted(row["fired"]) for row in malicious],
    }) + "\n")

def _gate_list(benign: list[dict], malicious: list[dict],
               warm_root: Path, sample: int) -> list[Gate]:
    """Every gate over already-scanned rows.

    Split out of ``run_gates`` so a merged shard scan is evaluated by the
    exact same rules as a single-process run.
    """
    gates = _evaluate(benign, malicious)
    if warm_root.exists():
        gates.append(gate_d_series_warm(warm_root))
    # The published distribution can only be compared against a whole
    # corpus: a sample moves every percentile.  `_evaluate` stays the
    # ten plan gates the sampled test run checks; this one rides the CI
    # job, which replays the corpus whole.
    if sample == 1:
        gates.append(gate_published_figures(benign, malicious))
        gates.append(gate_x_series_rate_stability(benign))
    return gates

def run_gates(corpus: Path = _calib_core.FIXTURES / "benign-corpus",
              malicious_root: Path = _calib_core.FIXTURES / "malicious",
              sample: int = 1, jobs: int | None = None,
              rows: Path | None = None) -> list[Gate]:
    with shipped_config():
        benign = scan_corpus(corpus, sample=sample, jobs=jobs)
        malicious = (scan_malicious(malicious_root, jobs=jobs)
                     if malicious_root.exists() else [])
        if rows is not None and sample == 1:
            _write_scan_rows(rows, benign, malicious)
        return _gate_list(benign, malicious, malicious_root / "warm", sample)

def _json_row(row: dict, corpus: Path) -> dict:
    """A benign row with its path made corpus-relative and JSON-safe.

    The shard scan and the merge eponymous run on different runners, whose
    absolute checkout paths need not agree, so the artifact stores the path
    relative to the corpus the merge job fetches at the same layout.
    """
    path = Path(row["path"])
    try:
        stored = str(path.relative_to(corpus))
    except ValueError:
        stored = str(path)
    return {**row, "path": stored}

def scan_shard(corpus: Path, sample: int, jobs: int | None,
               shard: tuple[int, int], out: Path) -> None:
    """Scan one slice of the plan and write its rows for the merge step.

    The artifact keeps each task's plan index, so the merge restores the
    whole-corpus order regardless of how the shards were scheduled.
    """
    with shipped_config():
        tasks = scan_corpus_tasks(
            corpus, sample=sample, jobs=jobs, shard=shard)
    out.write_text(json.dumps({
        "shard": list(shard),
        "tasks": [
            [index, [_json_row(row, corpus) for row in rows]]
            for index, rows in tasks
        ],
    }) + "\n")

def merge_shard_rows(directory: Path, corpus: Path) -> list[dict]:
    """Concatenate ``shard-*.json`` artifacts into whole-corpus order."""
    pairs: list[tuple[int, dict]] = []
    for path in sorted(Path(directory).glob("shard-*.json")):
        data = json.loads(path.read_text())
        for index, rows in data["tasks"]:
            pairs.extend((int(index), row) for row in rows)
    pairs.sort(key=lambda pair: pair[0])
    # The gates read the path back, so re-root it at this job's corpus.
    return [{**row, "path": Path(corpus) / row["path"]}
            for _index, row in pairs]

def run_gates_from_rows(benign: list[dict],
                        malicious_root: Path = _calib_core.FIXTURES / "malicious",
                        sample: int = 1, jobs: int | None = None,
                        rows: Path | None = None) -> list[Gate]:
    """Evaluate a merged shard scan; only the malicious fixtures are scanned."""
    with shipped_config():
        malicious = (scan_malicious(malicious_root, jobs=jobs)
                     if malicious_root.exists() else [])
        if rows is not None and sample == 1:
            _write_scan_rows(rows, benign, malicious)
        return _gate_list(benign, malicious, malicious_root / "warm", sample)

def _evaluate(benign: list[dict], malicious: list[dict]) -> list[Gate]:

    gates = [
        gate_benign_fire_rates(benign),
        gate_score_not_size(benign),
        gate_weight_zero_annotations(benign),
        gate_h035_position(benign),
        gate_stateful_rules_stay_out(benign),
        gate_ioc_exact_match(benign),
        gate_homograph_single_script(),
        gate_meta_escalation_below_cap(benign),
        gate_manifest_benign_corpus(),
        gate_coverage_ledger_complete(),
        gate_artifact_corpus(),
    ]
    if malicious:
        gates.append(gate_separation(benign, malicious))
        gates.append(gate_malicious_recall(malicious))
        gates.append(gate_known_gaps_unchanged(malicious))
        gates.append(gate_s_series_fixture_pairs(benign, malicious))
        gates.append(gate_s_series_last_fired_coverage(benign, malicious))
    gates.append(gate_cluster_rate_below_members(benign))
    return gates

def main() -> int:
    parser = argparse.ArgumentParser(description="Run the calibration gates")
    parser.add_argument("--corpus", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--malicious", type=Path, default=FIXTURES / "malicious")
    parser.add_argument("--sample", type=int, default=1,
                        help="Scan every Nth benign diff (default: all)")
    parser.add_argument("--jobs", type=int, default=default_jobs(),
                        help="Analysis worker processes (default: min(8, CPUs))")
    parser.add_argument("--json", type=Path, help="Write the gate results here")
    parser.add_argument("--rows", type=Path,
                        help="Write the per-diff fired rule ids here "
                             "(whole-corpus runs only; the H-series audit "
                             "reads them instead of re-scanning)")
    parser.add_argument("--shard", metavar="I/N",
                        help="Scan only shard I of N (0-based) and write "
                             "--shard-rows for the merge step")
    parser.add_argument("--shard-rows", type=Path,
                        help="Partial rows artifact written by --shard")
    parser.add_argument("--merge-dir", type=Path,
                        help="Evaluate the shard-*.json artifacts in this "
                             "directory instead of scanning the corpus")
    parser.add_argument("--coverage-only", action="store_true",
                        help="Evaluate only the coverage-ledger gates, with no "
                             "corpus scan. Requires --coverage-ledger or uses "
                             "the committed ledger.")
    parser.add_argument("--coverage-ledger", type=Path,
                        help="The ledger to evaluate in --coverage-only mode")
    args = parser.parse_args()

    if args.coverage_only:
        ledger_path = args.coverage_ledger or (FIXTURES / "coverage-ledger.json")
        gates = [
            gate_coverage_ledger_complete(ledger_path),
            gate_coverage_expectations(ledger_path),
        ]
        width = max(len(g.name) for g in gates)
        for gate in gates:
            status = "PASS" if gate.passed else "FAIL"
            print(f"{status}  {gate.name:<{width}}  measured={gate.measured}")
            if gate.detail:
                print(f"        {gate.detail}")
        if args.json:
            args.json.write_text(
                json.dumps([g.as_dict() for g in gates], indent=2, default=str) + "\n")
        failed = [g for g in gates if not g.passed]
        print(f"\n{len(gates) - len(failed)}/{len(gates)} coverage gates passed")
        return 1 if failed else 0

    if not args.merge_dir and not args.corpus.exists():
        print(f"Corpus not found: {args.corpus}", file=sys.stderr)
        print("Reconstruct it with scripts/build_corpus.py --from-manifest",
              file=sys.stderr)
        return 2

    if args.shard:
        if not args.shard_rows:
            parser.error("--shard requires --shard-rows")
        try:
            index_text, total_text = args.shard.split("/")
            index, total = int(index_text), int(total_text)
        except ValueError:
            parser.error("--shard must be I/N, e.g. 0/4")
        if total < 1 or not 0 <= index < total:
            parser.error("--shard index must satisfy 0 <= I < N")
        scan_shard(args.corpus, args.sample, args.jobs, (index, total),
                   args.shard_rows)
        print(f"scanned shard {index}/{total} -> {args.shard_rows}")
        return 0

    if args.merge_dir:
        if not args.merge_dir.is_dir():
            print(f"Shard directory not found: {args.merge_dir}",
                  file=sys.stderr)
            return 2
        benign = merge_shard_rows(args.merge_dir, args.corpus)
        gates = run_gates_from_rows(benign, args.malicious,
                                    sample=args.sample, jobs=args.jobs,
                                    rows=args.rows)
    else:
        gates = run_gates(args.corpus, args.malicious, sample=args.sample,
                          jobs=args.jobs, rows=args.rows)

    width = max(len(g.name) for g in gates)
    for gate in gates:
        status = "PASS" if gate.passed else "FAIL"
        print(f"{status}  {gate.name:<{width}}  measured={gate.measured}")
        if gate.detail:
            print(f"        {gate.detail}")

    if args.json:
        args.json.write_text(
            json.dumps([g.as_dict() for g in gates], indent=2, default=str) + "\n"
        )

    failed = [g for g in gates if not g.passed]
    print(f"\n{len(gates) - len(failed)}/{len(gates)} gates passed")
    return 1 if failed else 0

from scripts.calibration._core import (
    CLASS_C_RULES,
    CLASS_D_RULES,
    CRITICAL_MIN_SCORE,
    FIXTURES,
    Gate,
    MANIFEST_CORPUS,
    MAX_BENIGN_FIRE_RATE,
    MAX_SCORE_SIZE_CORRELATION,
    MAX_X_RATE_DRIFT,
    ROOT,
    X_RULES,
    _GAP_PRIOR_RULES,
    _META_ESCALATORS,
    _NOT_RULES,
    _S_RULES,
    _WORKER_CONFIG,
    _WORKER_INCLUDE_LOCATION,
    _WORKER_RULES,
    _benign_plan,
    _benign_row,
    _diff_line_count,
    _fixture_failures,
    _gap_detected_by_another_rule,
    _init_worker,
    _is_attack_fixture,
    _malicious_row,
    _ordered_benign_packages,
    _precompile_patterns,
    _resolve_jobs,
    _scan_corpus_parallel,
    _scan_corpus_serial,
    _scan_malicious_task,
    _scan_package_task,
    default_jobs,
    pearson,
    percentile,
    scan_corpus,
    scan_corpus_tasks,
    scan_malicious,
    shipped_config,
    warm_dependency_corpus,
)
from scripts.calibration._gates import (
    gate_benign_fire_rates,
    gate_artifact_corpus,
    gate_cluster_rate_below_members,
    gate_coverage_expectations,
    gate_coverage_ledger_complete,
    gate_d_series_warm,
    gate_h035_position,
    gate_homograph_single_script,
    gate_ioc_exact_match,
    gate_known_gaps_unchanged,
    gate_malicious_recall,
    gate_manifest_benign_corpus,
    gate_meta_escalation_below_cap,
    gate_published_figures,
    gate_s_series_fixture_pairs,
    gate_s_series_last_fired_coverage,
    gate_score_not_size,
    gate_separation,
    gate_stateful_rules_stay_out,
    gate_weight_zero_annotations,
    gate_x_series_rate_stability,
)

__all__ = ['CLASS_C_RULES', 'CLASS_D_RULES', 'CRITICAL_MIN_SCORE', 'Counter', 'FIXTURES', 'Gate', 'MANIFEST_CORPUS', 'MAX_BENIGN_FIRE_RATE', 'MAX_SCORE_SIZE_CORRELATION', 'MAX_X_RATE_DRIFT', 'Path', 'ProcessPoolExecutor', 'ROOT', 'X_RULES', '_GAP_PRIOR_RULES', '_GLOBAL_URL_KEY', '_META_ESCALATORS', '_NOT_RULES', '_S_RULES', '_WORKER_CONFIG', '_WORKER_INCLUDE_LOCATION', '_WORKER_RULES', '_benign_plan', '_benign_row', '_diff_line_count', '_evaluate', '_fixture_failures', '_gap_detected_by_another_rule', '_init_worker', '_is_attack_fixture', '_malicious_row', '_ordered_benign_packages', '_precompile_patterns', '_resolve_jobs', '_scan_corpus_parallel', '_scan_corpus_serial', '_scan_malicious_task', '_scan_package_task', 'argparse', 'config_module', 'contextmanager', 'db_module', 'default_jobs', 'defaultdict', 'ensure_default_configs', 'gate_benign_fire_rates', 'gate_cluster_rate_below_members', 'gate_coverage_expectations', 'gate_d_series_warm', 'gate_h035_position', 'gate_homograph_single_script', 'gate_ioc_exact_match', 'gate_known_gaps_unchanged', 'gate_malicious_recall', 'gate_manifest_benign_corpus', 'gate_meta_escalation_below_cap', 'gate_published_figures', 'gate_s_series_fixture_pairs', 'gate_s_series_last_fired_coverage', 'gate_score_not_size', 'gate_separation', 'gate_stateful_rules_stay_out', 'gate_weight_zero_annotations', 'gate_x_series_rate_stability', 'json', 'load_config', 'load_rules', 'main', 'math', 'multiprocessing', 'normalize_url', 'os', 'pearson', 'percentile', 'precompile_patterns', 'precompile_structural_patterns', 'reset_after_fork', 'reset_git_after_fork', 'resolve_generated_patterns', 'merge_shard_rows', 'run_gates', 'run_gates_from_rows', 'scan_corpus', 'scan_corpus_tasks', 'scan_diff', 'scan_malicious', 'scan_shard', 'scored_source_urls', 'shipped_config', 'shutil', 'sys', 'tempfile', 'warm_dependency_corpus']


if __name__ == "__main__":
    sys.exit(main())
