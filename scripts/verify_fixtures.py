#!/usr/bin/env python3
"""Verify the malicious fixture corpus is complete and self-consistent.

For every tests/fixtures/malicious/*/expected.json record:
  * every expected key must have a non-empty .diff body in the same dir
  * every .diff on disk must be referenced by expected.json (no orphans)

The .diff bodies are committed source now (spec §8 fallback), so this
script runs in CI to catch accidental drift between the curated records
and the fixture files. Exits non-zero listing every discrepancy.

Usage:
    python scripts/verify_fixtures.py [--root tests/fixtures/malicious]
"""

import argparse
import json
import sys
from pathlib import Path

CATEGORIES = ("historical", "holdout", "evasion", "synthetic", "campaign")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=None,
                        help="malicious fixtures root (default: tests/fixtures/malicious)")
    args = parser.parse_args()

    root = args.root or (Path(__file__).resolve().parent.parent
                         / "tests" / "fixtures" / "malicious")

    problems = []
    total_keys = 0
    total_diffs = 0
    print(f"{'category':<12} {'expected':>8} {'diffs':>6}  status")
    print("-" * 44)

    for category in CATEGORIES:
        cat_dir = root / category
        if not cat_dir.is_dir():
            problems.append(f"{category}: missing directory {cat_dir}")
            continue
        expected_path = cat_dir / "expected.json"
        if not expected_path.exists():
            problems.append(f"{category}: missing {expected_path.name}")
            continue
        expected = json.loads(expected_path.read_text())
        diffs = {p.name: p for p in cat_dir.glob("*.diff")}
        missing = [k for k in expected if k not in diffs]
        empty = [k for k in expected if k in diffs and diffs[k].stat().st_size == 0]
        orphans = [n for n in sorted(diffs) if n not in expected]
        total_keys += len(expected)
        total_diffs += len(diffs)
        status = "OK"
        if missing or empty or orphans:
            status = "PROBLEMS"
        print(f"{category:<12} {len(expected):>8} {len(diffs):>6}  {status}")
        for k in missing:
            problems.append(f"{category}: expected '{k}' has no .diff body")
        for k in empty:
            problems.append(f"{category}: expected '{k}' has an empty .diff body")
        for n in orphans:
            problems.append(f"{category}: orphan .diff '{n}' is not in expected.json")

    print("-" * 44)
    print(f"TOTAL: {total_keys} expected records, {total_diffs} .diff bodies")

    if problems:
        print(f"\nFAILED ({len(problems)}):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        raise SystemExit(1)
    print("All fixture records are complete and self-consistent.")


if __name__ == "__main__":
    main()
