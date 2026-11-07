"""Replay the history-exercising corpus.

The locked benign corpus is stateless diffs, so the observation-history rules
never fire there.  This harness drives ``run_corpus_sweep`` (the pure
cycle-end Class D path) over the committed history cycles
(``tests/fixtures/history_corpus.py``) and reports the fired rule set per
cycle, so the co-fire matrix has a real measurement and a parity
check.

Usage:
    uv run python tests/harness/history_replay.py [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from history_corpus import CYCLES  # noqa: E402


def replay() -> list[dict]:
    """One row per cycle: its fired rule ids, sorted."""
    from trustsight.full_aur.corpus import run_corpus_sweep

    rows: list[dict] = []
    for cycle in CYCLES:
        findings = run_corpus_sweep(
            cycle["new"], cycle.get("old"),
            source_repos=cycle.get("source_repos"),
            prior_history=cycle.get("prior_history"),
            maintainer_history=cycle.get("maintainer_history"),
            edges=cycle.get("edges"),
            detail=cycle.get("detail"),
            maintainer_transitions=cycle.get("maintainer_transitions"),
            prior_rule_history=cycle.get("prior_rule_history"),
            package_cycle_events=cycle.get("package_cycle_events"),
            now=cycle.get("now", 0),
        )
        rows.append({
            "name": cycle["name"],
            "stratum": cycle.get("stratum", "history"),
            "fired": sorted({f["rule_id"] for f in findings}),
            "expected": sorted(cycle["expected"]),
        })
    return rows


def compare(rows: list[dict]) -> list[str]:
    """Cycles whose fired set differs from the committed expectation."""
    return [
        f"{row['name']}: fired {row['fired']}, expected {row['expected']}"
        for row in rows if row["fired"] != row["expected"]
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="History-corpus replay")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    rows = replay()
    if args.json:
        args.json.write_text(json.dumps(rows, indent=1) + "\n")

    failures = compare(rows)
    for failure in failures:
        print(f"HISTORY DRIFT {failure}")
    print(f"history replay: {len(rows)} cycles, {len(failures)} drifted")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
