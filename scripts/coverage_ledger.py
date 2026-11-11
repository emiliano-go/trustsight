#!/usr/bin/env python3
"""Build the per-rule coverage ledger from every benign source.

This is the corpus-expansion control panel.  It reuses the calibration scan,
so it costs one replay (shared with the gates when CI passes rows) and then
adds the sources a diff replay cannot cover: the history corpus, the manifest
corpus, the artifact corpus, the stateful T-series sample and the labelled
attack fixtures.

Every expected rule is reported as benign-measured or as a dispositioned gap.
``--check`` rebuilds and compares the committed ledger; ``--check-existing``
compares an already-built ledger without a second replay.

Usage:
    uv run python scripts/coverage_ledger.py
    uv run python scripts/coverage_ledger.py --jobs 8 \\
        --out tests/fixtures/coverage-ledger.json
    uv run python scripts/coverage_ledger.py --rows scan-rows.json \\
        --out coverage-ledger.json --check-existing \\
        tests/fixtures/coverage-ledger.json
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import calibration_gates as cg  # noqa: E402
from calibration._ledger import (  # noqa: E402
    Observation,
    build_ledger,
    expected_from_strata,
    observation_from_rows,
    write_ledger,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


def _stratum_map(manifest: Path) -> dict[str, str]:
    if not manifest.exists():
        return {}
    lock = json.loads(manifest.read_text())
    return {e["pkg"]: e["stratum"] for e in lock.get("entries", [])}


#: Fields that describe coverage and dispositions rather than prose or
#: timing.  ``--check`` compares these, so a stale committed ledger fails
#: without making a fire-count fluctuation look like a structural drift.
_FUNCTIONAL_FIELDS = (
    "state", "benign_state", "benign_sources", "benign_strata",
    "expected_strata", "expected_met", "expected_strata_met",
)


def _disposition_projection(disposition) -> dict | None:
    """The machine-relevant part of a disposition, not its prose note."""
    if not isinstance(disposition, dict):
        return None
    return {key: disposition.get(key) for key in ("status", "plan", "phase")}


def _canonical_ledger(ledger: dict) -> dict:
    rules = {}
    for rid, row in (ledger.get("rules") or {}).items():
        rules[rid] = {field: row.get(field) for field in _FUNCTIONAL_FIELDS}
        rules[rid]["disposition"] = _disposition_projection(row.get("disposition"))
    return {
        "version": ledger.get("version"),
        "corpus_content_sha256": ledger.get("corpus_content_sha256"),
        "catalog_size": ledger.get("catalog_size"),
        "counts": ledger.get("counts"),
        "rules": rules,
    }


def _ledger_drift(committed_path: Path, ledger: dict) -> list[str]:
    committed = _canonical_ledger(json.loads(committed_path.read_text()))
    current = _canonical_ledger(ledger)
    problems: list[str] = []
    for key in ("version", "corpus_content_sha256", "catalog_size", "counts"):
        if committed.get(key) != current.get(key):
            problems.append(
                f"{key}: committed {committed.get(key)!r} != current {current.get(key)!r}")
    old, new = committed.get("rules") or {}, current.get("rules") or {}
    missing = sorted(set(old) - set(new))
    extra = sorted(set(new) - set(old))
    if missing:
        problems.append(f"missing ids: {missing[:8]}")
    if extra:
        problems.append(f"unknown ids: {extra[:8]}")
    for rid in sorted(set(old) & set(new)):
        for field in (*_FUNCTIONAL_FIELDS, "disposition"):
            if old[rid].get(field) != new[rid].get(field):
                problems.append(
                    f"{rid}.{field}: committed {old[rid].get(field)!r} != "
                    f"current {new[rid].get(field)!r}")
    return problems


def _load_history() -> list[dict]:
    sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
    sys.path.insert(0, str(ROOT / "tests" / "harness"))
    try:
        from history_replay import replay
    except Exception as exc:  # pragma: no cover - a source is optional
        print(f"coverage: history corpus unavailable: {exc}", file=sys.stderr)
        return []
    return replay()


def _scan_manifest_corpus() -> list[dict]:
    if not cg.MANIFEST_CORPUS.exists():
        return []
    rows = cg.scan_corpus(cg.MANIFEST_CORPUS)
    for row in rows:
        row["stratum"] = "signed_sources"
    return rows


def _scan_artifact_corpus(directory: Path) -> list[dict]:
    """Load committed artifact manifests and run the A-series inspector."""
    if not directory.exists():
        return []
    from trustsight.analysis.artifact import inspect_manifest

    rows: list[dict] = []
    for path in sorted(directory.glob("*.json")):
        if path.name == "expected.json":
            continue
        doc = json.loads(path.read_text())
        findings = inspect_manifest(doc.get("manifest") or [], doc.get("declared") or {})
        rows.append({
            "name": path.stem,
            "stratum": doc.get("stratum", "artifact"),
            "fired": sorted({f["rule_id"] for f in findings}),
        })
    return rows


def _scan_t_series() -> list[dict]:
    """Exercise the stateful T rules the stateless diff replay cannot reach."""
    from trustsight.analysis.temporal import (
        t_domain_findings,
        t_key_findings,
        t_key_rotation,
    )
    from trustsight.db import (
        init_db,
        record_observed_domain,
        record_observed_key,
    )

    with cg.shipped_config():
        init_db()
        record_observed_key("KNOWNKEY")
        record_observed_domain("known.example", observed_at="2020-01-01 00:00:00")
        samples = (
            ("t001-signing-key", "signed_sources",
             t_key_findings({"pgp_keys": {"gained": ["NEWKEY"]}}, None)),
            ("t002-maintainer-domain", "maintainer_churn",
             t_domain_findings("Name <user@novel.example>", None)),
            ("t003-key-rotation", "signed_sources",
             t_key_rotation(
                 {"pgp_keys": {"gained": ["NEWKEY"], "lost": ["OLDKEY"]}})),
        )
        return [
            {
                "name": name,
                "stratum": stratum,
                "fired": sorted({finding["rule_id"] for finding in findings}),
            }
            for name, stratum, findings in samples
        ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the coverage ledger")
    parser.add_argument("--corpus", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--manifest", type=Path, default=FIXTURES / "corpus.lock")
    parser.add_argument("--strata", type=Path, default=ROOT / "scripts" / "strata.toml")
    parser.add_argument("--artifact-dir", type=Path,
                        default=FIXTURES / "artifact-corpus")
    parser.add_argument("--out", type=Path,
                        default=FIXTURES / "coverage-ledger.json")
    parser.add_argument("--dispositions", type=Path,
                        default=FIXTURES / "coverage-dispositions.json",
                        help="reviewed plans for rules not yet benign-measured")
    parser.add_argument("--check", type=Path, metavar="LEDGER",
                        help="rebuild, compare with this committed ledger, and "
                             "exit nonzero on coverage drift")
    parser.add_argument("--check-existing", type=Path, metavar="LEDGER",
                        help="compare the already-built --out ledger with this "
                             "committed ledger, without rescanning")
    parser.add_argument("--jobs", type=int, default=cg.default_jobs())
    parser.add_argument("--no-history", action="store_true")
    parser.add_argument("--no-manifest", action="store_true")
    parser.add_argument("--no-artifact", action="store_true")
    parser.add_argument("--no-malicious", action="store_true")
    parser.add_argument("--rows", type=Path,
                        help="reuse a calibration --rows artifact instead of rescanning")
    args = parser.parse_args()

    if args.check_existing:
        if not args.out.exists():
            print(f"coverage: ledger missing: {args.out}", file=sys.stderr)
            return 2
        problems = _ledger_drift(
            args.check_existing, json.loads(args.out.read_text()))
        if problems:
            print(f"coverage ledger drift: {args.check_existing}", file=sys.stderr)
            for problem in problems[:20]:
                print(f"  {problem}", file=sys.stderr)
            if len(problems) > 20:
                print(f"  ... {len(problems) - 20} more", file=sys.stderr)
            return 1
        print(f"coverage ledger matches: {args.check_existing}")
        return 0

    if not args.corpus.exists():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        return 2

    strata_cfg = tomllib.loads(args.strata.read_text()) if args.strata.exists() else {}
    strata_of = _stratum_map(args.manifest)
    expected = expected_from_strata(strata_cfg)

    if args.rows:
        doc = json.loads(args.rows.read_text())
        cold = []
        packages = doc.get("benign_packages") or [""] * len(doc.get("benign", []))
        for pkg, rules in zip(packages, doc.get("benign", [])):
            cold.append({
                "package": pkg,
                "stratum": strata_of.get(pkg, "unknown"),
                "entries": [{"rule_id": rid} for rid in rules],
            })
    else:
        with cg.shipped_config():
            cold = cg.scan_corpus(args.corpus, jobs=args.jobs)
        for row in cold:
            row["stratum"] = strata_of.get(row["package"], "unknown")
    observations: list[Observation] = [observation_from_rows(cold, "cold")]

    if not args.no_history:
        history = _load_history()
        for row in history:
            row.setdefault("stratum", row.get("stratum", "history"))
        observations.append(observation_from_rows(history, "history"))

    if not args.no_manifest:
        observations.append(observation_from_rows(_scan_manifest_corpus(), "manifest"))

    if not args.no_artifact:
        observations.append(observation_from_rows(
            _scan_artifact_corpus(args.artifact_dir), "artifact"))

    observations.append(observation_from_rows(_scan_t_series(), "t-series"))

    if not args.no_malicious:
        with cg.shipped_config():
            malicious = cg.scan_malicious(FIXTURES / "malicious", jobs=args.jobs)
        observations.append(observation_from_rows(malicious, "malicious"))

    baseline_path = FIXTURES / "baseline.json"
    if baseline_path.exists():
        baseline = json.loads(baseline_path.read_text())
        warm = (baseline.get("warm") or {}).get("strata") or {}
        warm_obs = Observation(source="warm")
        for stratum, row in warm.items():
            for rule_id, rate in (row.get("rules") or {}).items():
                if rate:
                    warm_obs.fires[rule_id] = warm_obs.fires.get(rule_id, 0) + 1
                    warm_obs.strata[rule_id].add(stratum)
        if warm_obs.fires:
            observations.append(warm_obs)

    dispositions: dict[str, dict] = {}
    if args.dispositions.exists():
        dispositions = json.loads(args.dispositions.read_text())
    elif args.check:
        print(f"coverage: dispositions file missing: {args.dispositions}",
              file=sys.stderr)

    digest = ""
    if (FIXTURES / "baseline.json").exists():
        digest = json.loads((FIXTURES / "baseline.json").read_text()).get(
            "corpus_content_sha256", "")
    ledger = build_ledger(
        observations, expected=expected, dispositions=dispositions,
        corpus_sha256=digest, version="2")
    write_ledger(args.out, ledger)

    print(f"coverage ledger: {args.out}")
    print(f"  catalog: {ledger['catalog_size']} ids")
    for state, count in ledger["counts"].items():
        print(f"  {state:16} {count}")
    unnamed = [rid for rid, row in ledger["rules"].items()
               if row["state"] != "measured" and not row["reason"]]
    if unnamed:
        print(f"  ERROR: {len(unnamed)} non-measured rules have no reason",
              file=sys.stderr)
        return 1

    if args.check:
        if args.check.resolve() == args.out.resolve():
            print("  ERROR: --check target must differ from --out", file=sys.stderr)
            return 2
        problems = _ledger_drift(args.check, ledger)
        if problems:
            print(f"coverage ledger drift: {args.check}", file=sys.stderr)
            for problem in problems[:20]:
                print(f"  {problem}", file=sys.stderr)
            if len(problems) > 20:
                print(f"  ... {len(problems) - 20} more", file=sys.stderr)
            return 1
        print(f"  matches committed ledger: {args.check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
