#!/usr/bin/env python3
"""Scan the campaign fixture directory in one bounded parallel pass.

The ordinary ``analyze_diff`` loop starts a worker per file and repeats the
shared setup.  These fixtures are independent, so a process pool is the
smallest change that makes the check usable on every run.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _scan(item: tuple[str, str]) -> tuple[str, set[str], int]:
    from trustsight.analysis.pipeline import scan_diff

    name, text = item
    fact = scan_diff(text, package_name=Path(name).stem)
    fired = {entry.rule_id for entry in fact.score_breakdown}
    return name, fired, fact.final_score


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", nargs="?",
                        default="tests/fixtures/malicious/campaign/aur-2025-2026")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    directory = (ROOT / args.directory).resolve()
    expected = json.loads((directory / "expected.json").read_text())
    items = [
        (name, (directory / name).read_text())
        for name in expected
        if (directory / name).is_file()
    ]
    failures = 0
    with ProcessPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for name, fired, score in pool.map(_scan, items):
            want = expected[name]
            missing = set(want.get("must_fire", ())) - fired
            too_low = score < int(want.get("min_score", 0))
            if missing or too_low:
                failures += 1
                print(f"FAIL {name}: score={score} missing={sorted(missing)}")
            else:
                print(f"ok   {name}: score={score}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
