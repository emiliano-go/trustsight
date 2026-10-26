#!/usr/bin/env python3
"""Attach H104 findings to a watcher database's stored PKGBUILD snapshots.

H104 is absolute-state, but the watcher only analyses a package when it
changes.  A placeholder burst that predates the rule therefore sits in
``pkgbuild_snapshots`` with no ``triggered_rules`` row, and the incremental
watcher will never revisit a package that was removed.  This one-off pass
asks the current detector about every stored recipe and attaches the finding
to the package's most recent analysis, so the corpus has the H104 history
G011 needs.

It is idempotent and queues all writes in one transaction.  Run it with the
watcher stopped (or between cycles): the live watcher is also a writer.

    python scripts/backfill_h104.py --db ~/.local/share/trustsight/trustsight.db
    python scripts/backfill_h104.py --db ... --dry-run
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def backfill(db_path: str | Path, *, dry_run: bool = False,
             update_facts: bool = True) -> dict:
    """Backfill H104 over every stored recipe; return what happened."""
    from trustsight.analysis.placeholder import placeholder_finding

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout = 5000")
    stats = {
        "scanned": 0, "hits": 0, "inserted": 0, "existing": 0,
        "facts_updated": 0, "no_analysis": 0, "unparseable": 0,
    }
    try:
        rows = con.execute(
            "SELECT package_name, pkgbuild_text FROM pkgbuild_snapshots "
            "ORDER BY package_name"
        ).fetchall()
        for row in rows:
            stats["scanned"] += 1
            text = row["pkgbuild_text"] or ""
            if not text.strip():
                continue
            try:
                finding = placeholder_finding(text)
            except Exception:  # noqa: BLE001 - one unreadable recipe is a skip
                stats["unparseable"] += 1
                continue
            if not finding:
                continue
            stats["hits"] += 1
            latest = con.execute(
                "SELECT a.id, a.fact_json FROM analysis_history a "
                "JOIN packages p ON p.id = a.package_id "
                "WHERE p.name = ? ORDER BY a.id DESC LIMIT 1",
                (row["package_name"],),
            ).fetchone()
            if latest is None:
                stats["no_analysis"] += 1
                continue
            history_id = latest["id"]
            already = con.execute(
                "SELECT 1 FROM triggered_rules "
                "WHERE history_id = ? AND rule_id = 'H104'",
                (history_id,),
            ).fetchone()
            if already:
                stats["existing"] += 1
                continue
            stats["inserted"] += 1
            if dry_run:
                continue
            con.execute(
                "INSERT INTO triggered_rules (history_id, rule_id, severity) "
                "VALUES (?, 'H104', 'INFO')",
                (history_id,),
            )
            if update_facts and latest["fact_json"]:
                try:
                    fact = json.loads(latest["fact_json"])
                except (TypeError, ValueError):
                    continue
                breakdown = fact.get("score_breakdown") or []
                if not any(entry.get("rule_id") == "H104" for entry in breakdown):
                    breakdown.append({
                        "rule_id": "H104", "severity": "INFO", "weight": 0,
                        "reason": finding["match"],
                        "params": finding.get("params") or {},
                        "template": finding.get("template", ""),
                        "evidence": finding.get("evidence") or {},
                        "file": "PKGBUILD", "line": None,
                        "licensed_by": [], "techniques": [],
                    })
                    fact["score_breakdown"] = breakdown
                    con.execute(
                        "UPDATE analysis_history SET fact_json = ? WHERE id = ?",
                        (json.dumps(fact, ensure_ascii=False,
                                    separators=(",", ":")), history_id),
                    )
                    stats["facts_updated"] += 1
        if dry_run:
            con.rollback()
        else:
            con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    return stats


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", default=str(Path.home() / ".local/share/trustsight/trustsight.db"),
        help="watcher database (default: the per-user data directory)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-fact-patch", action="store_true")
    args = parser.parse_args(argv)
    if not Path(args.db).exists():
        print(f"database not found: {args.db}", file=sys.stderr)
        return 1
    stats = backfill(
        args.db, dry_run=args.dry_run, update_facts=not args.no_fact_patch,
    )
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
