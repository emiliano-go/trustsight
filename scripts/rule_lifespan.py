#!/usr/bin/env python3
"""Check rule measurement age and propose demotions.

The lab owns the measurements; this gate owns the consequence.  It reads a
rule-health document and fails when a live rule is past its review horizon
without a recorded disposition.  It never edits the anergy ledger.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path


def load(path: Path) -> list[dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = raw.get("rules", raw) if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        raise ValueError("rule health must be a list")
    return rows


def expired(row: dict, today: dt.date) -> bool:
    try:
        measured = dt.date.fromisoformat(str(row["last_measured"]))
        horizon = int(row["review_horizon_days"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"malformed rule health row: {row!r}") from exc
    return (today - measured).days > horizon


def check(rows: list[dict], today: dt.date) -> list[dict]:
    out = []
    for row in rows:
        if str(row.get("status", "live")) != "live":
            continue
        if not expired(row, today):
            continue
        if row.get("disposition"):
            continue
        out.append(row)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--health", type=Path, required=True)
    parser.add_argument("--today", type=dt.date.fromisoformat)
    args = parser.parse_args(argv)
    today = args.today or dt.date.today()
    try:
        rows = load(args.health)
        stale = check(rows, today)
    except (OSError, ValueError) as exc:
        print(f"rule lifespan: {exc}", file=sys.stderr)
        return 2
    if stale:
        print("expired rules without a disposition:")
        for row in stale:
            print(f"  {row.get('rule_id', '?')}")
        return 1
    print(f"rule lifespan: {len(rows)} rule(s) current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
