"""Rebaseline: regenerate baseline.json after rule changes.

Usage:
    python scripts/rebaseline.py [--corpus tests/fixtures/benign-corpus] \\
        [--manifest tests/fixtures/corpus.lock] \\
        [--baseline tests/fixtures/baseline.json]

Scans the stratified benign corpus, computes per-stratum FP rates,
p95, and zero% for every rule, and writes updated baseline.json.
"""

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from trustsight.analysis import scan_diff
from trustsight.config import load_config, ensure_default_configs
from trustsight.rules import load_rules

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _corpus_content_hash(corpus_dir: Path) -> str:
    """SHA-256 over the sorted concatenation of all diff file bytes."""
    h = hashlib.sha256()
    for dp in sorted(corpus_dir.rglob("*.diff")):
        h.update(dp.read_bytes())
    return h.hexdigest()


def _build_chain_index(entries: list[dict]) -> dict[str, list[str]]:
    """Return ``{pkg: [diff stem, ...]}`` in true commit order.

    Novelty is order-dependent: "first seen" is meaningless if diffs are
    replayed in an arbitrary sequence.  The manifest records each diff as
    an ``old_sha -> new_sha`` pair, and those pairs form a chain per
    package, so commit order can be recovered without the repository.
    """
    by_pkg: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        by_pkg[entry["pkg"]].append(entry)

    index: dict[str, list[str]] = {}
    for pkg, items in by_pkg.items():
        by_old = {e["old_sha"]: e for e in items}
        new_shas = {e["new_sha"] for e in items}
        starts = [e for e in items if e["old_sha"] not in new_shas]
        if len(starts) != 1:
            continue  # branched or incomplete history; caller falls back
        ordered, cur, seen = [], starts[0], set()
        while cur is not None and cur["new_sha"] not in seen:
            ordered.append(cur)
            seen.add(cur["new_sha"])
            cur = by_old.get(cur["new_sha"])
        if len(ordered) == len(items):
            index[pkg] = [
                f"{pkg}__{e['old_sha'][:12]}..{e['new_sha'][:12]}" for e in ordered
            ]
    return index


def _order_by_chain(diff_files: list[Path], stems: list[str]) -> tuple[list[Path], bool]:
    """Sort *diff_files* by *stems*; fall back to filename order if unusable."""
    if not stems:
        return sorted(diff_files, key=lambda p: p.stem), False
    rank = {stem: i for i, stem in enumerate(stems)}
    if any(p.stem not in rank for p in diff_files):
        return sorted(diff_files, key=lambda p: p.stem), False
    return sorted(diff_files, key=lambda p: rank[p.stem]), True


def main():
    parser = argparse.ArgumentParser(description="Rebaseline FP rates")
    parser.add_argument("--corpus", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--manifest", type=Path, default=FIXTURES / "corpus.lock")
    parser.add_argument("--baseline", type=Path, default=FIXTURES / "baseline.json")
    parser.add_argument(
        "--order", choices=["chain", "filename"], default="chain",
        help="Replay order within a package. 'chain' follows the manifest's "
             "old_sha -> new_sha links (true commit order); 'filename' is the "
             "legacy SHA-hex sort, kept only to reproduce older baselines.",
    )
    parser.add_argument(
        "--warm", action="store_true",
        help="Model database warm-up: pass a running observation count so "
             "tier C novelty is scored as it would be for a real user.",
    )
    args = parser.parse_args()

    if not args.corpus.exists():
        print(f"Corpus not found: {args.corpus}", file=sys.stderr)
        sys.exit(1)

    ensure_default_configs()
    config = load_config()
    rules = load_rules()

    strata_lookup = {}
    chain_index: dict[str, list[str]] = {}
    if args.manifest.exists():
        lock = json.loads(args.manifest.read_text())
        strata_lookup = {e["pkg"]: e["stratum"] for e in lock.get("entries", [])}
        chain_index = _build_chain_index(lock.get("entries", []))

    per_stratum = defaultdict(
        lambda: {"diffs": 0, "pkgs": set(), "scores": [], "rules": Counter()}
    )

    pkg_diffs: dict[str, list[Path]] = {}
    for diff_file in sorted(args.corpus.rglob("*.diff")):
        pkg = diff_file.name.split("__")[0]
        pkg_diffs.setdefault(pkg, []).append(diff_file)

    seen_urls: dict[str, set[str]] = {}
    observations = 0
    fallbacks = 0
    for pkg, diff_files in pkg_diffs.items():
        if args.order == "chain":
            ordered, ok = _order_by_chain(diff_files, chain_index.get(pkg, []))
            fallbacks += not ok
            diff_files = ordered
        else:
            diff_files.sort(key=lambda p: p.stem)
        for diff_file in diff_files:
            stratum = strata_lookup.get(pkg, "unknown")
            fact = scan_diff(diff_file.read_text(), rules=rules, config=config,
                             package_name=pkg, seen_urls=seen_urls,
                             observation_count=observations if args.warm else 0)
            observations += 1
            per_stratum[stratum]["diffs"] += 1
            per_stratum[stratum]["pkgs"].add(pkg)
            per_stratum[stratum]["scores"].append(fact.final_score)
            for entry in fact.score_breakdown:
                if entry.rule_id in ("SOURCE_BUCKET", "NOVELTY"):
                    key = f"{entry.rule_id}/{entry.weight}"
                else:
                    key = entry.rule_id
                per_stratum[stratum]["rules"][key] += 1

    baseline = {
        "generated": "2026-07-16",
        "corpus_content_sha256": _corpus_content_hash(args.corpus),
        "pipeline_version": "0.3.0",
        "strata": {},
    }

    for stratum, data in per_stratum.items():
        scores = sorted(data["scores"])
        n = data["diffs"]
        baseline["strata"][stratum] = {
            "n_diffs": n,
            "n_pkgs": len(data["pkgs"]),
            "p95": scores[int(n * 0.95)] if n else 0,
            "zero_pct": sum(1 for s in scores if s == 0) / n if n else 0,
            "rules": {
                rid: count / n for rid, count in data["rules"].items()
            },
        }

    baseline["replay_order"] = args.order
    baseline["warm_novelty"] = args.warm
    if args.order == "chain" and fallbacks:
        print(f"  note: {fallbacks} package(s) had an unusable commit chain "
              f"and fell back to filename order", file=sys.stderr)

    args.baseline.parent.mkdir(parents=True, exist_ok=True)
    args.baseline.write_text(json.dumps(baseline, indent=2) + "\n")
    print(f"Baseline written: {args.baseline}")
    for stratum, data in baseline["strata"].items():
        print(f"  {stratum}: {data['n_diffs']} diffs, p95={data['p95']}, zero={data['zero_pct']:.1%}")


if __name__ == "__main__":
    main()
