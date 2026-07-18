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


def main():
    parser = argparse.ArgumentParser(description="Rebaseline FP rates")
    parser.add_argument("--corpus", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--manifest", type=Path, default=FIXTURES / "corpus.lock")
    parser.add_argument("--baseline", type=Path, default=FIXTURES / "baseline.json")
    args = parser.parse_args()

    if not args.corpus.exists():
        print(f"Corpus not found: {args.corpus}", file=sys.stderr)
        sys.exit(1)

    ensure_default_configs()
    config = load_config()
    rules = load_rules()

    strata_lookup = {}
    if args.manifest.exists():
        lock = json.loads(args.manifest.read_text())
        strata_lookup = {e["pkg"]: e["stratum"] for e in lock.get("entries", [])}

    per_stratum = defaultdict(
        lambda: {"diffs": 0, "pkgs": set(), "scores": [], "rules": Counter()}
    )

    pkg_diffs: dict[str, list[Path]] = {}
    for diff_file in sorted(args.corpus.rglob("*.diff")):
        pkg = diff_file.name.split("__")[0]
        pkg_diffs.setdefault(pkg, []).append(diff_file)

    seen_urls: dict[str, set[str]] = {}
    for pkg, diff_files in pkg_diffs.items():
        diff_files.sort(key=lambda p: p.stem)  # stem = pkg__oldsha..newsha, sorts by sha
        for diff_file in diff_files:
            stratum = strata_lookup.get(pkg, "unknown")
            fact = scan_diff(diff_file.read_text(), rules=rules, config=config,
                             package_name=pkg, seen_urls=seen_urls)
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

    args.baseline.parent.mkdir(parents=True, exist_ok=True)
    args.baseline.write_text(json.dumps(baseline, indent=2) + "\n")
    print(f"Baseline written: {args.baseline}")
    for stratum, data in baseline["strata"].items():
        print(f"  {stratum}: {data['n_diffs']} diffs, p95={data['p95']}, zero={data['zero_pct']:.1%}")


if __name__ == "__main__":
    main()
