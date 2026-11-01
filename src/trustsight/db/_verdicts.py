"""Review verdicts and the tender-point projection.

A verdict is a human's disposition, not a rule: ``confirmed``, ``cleared`` or
``uncertain``.  The store exists so "N unresolved verdicts in M months" is a
count over recorded facts rather than a guess.  Nothing here scores.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Optional

from ..safe_text import clean

from ._connection import get_connection
from ._metadata import observation_seq

__all__ = [
    "VERDICTS",
    "record_verdict",
    "review_verdicts_available",
    "tender_point",
    "verdicts_for_package",
]

VERDICTS = frozenset({"confirmed", "cleared", "uncertain"})

MAX_VERDICT_ID_CHARS = 200
MAX_VERDICT_NOTE_CHARS = 2_000
MAX_VERDICT_ROWS = 1_000


def _bounded_int(value, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(high, max(low, number))


def review_verdicts_available() -> bool:
    """True when the verdict table exists (warm state)."""
    try:
        with get_connection() as conn:
            conn.execute("SELECT 1 FROM review_verdicts LIMIT 1").fetchone()
        return True
    except Exception:  # noqa: BLE001 - a missing table is a cold read
        return False


def record_verdict(package_name: str, verdict: str, rule_id: str = "",
                   campaign_id: str = "", note: str = "",
                   observed_at: Optional[str] = None,
                   observed_seq: Optional[int] = None) -> None:
    """Append one verdict.  Unknown dispositions raise ``ValueError``."""
    verdict = str(verdict or "")[:32].strip().lower()
    if verdict not in VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r}; expected one of "
                         + ", ".join(sorted(VERDICTS)))
    package = clean(
        str(package_name)[:MAX_VERDICT_ID_CHARS * 4],
        limit=MAX_VERDICT_ID_CHARS).strip()
    if not package:
        raise ValueError("package name is required")
    rule_id = clean(str(rule_id or "")[:MAX_VERDICT_ID_CHARS * 4],
                    limit=MAX_VERDICT_ID_CHARS).strip()
    campaign_id = clean(
        str(campaign_id or "")[:MAX_VERDICT_ID_CHARS * 4],
        limit=MAX_VERDICT_ID_CHARS).strip()
    note = clean(str(note or "")[:MAX_VERDICT_NOTE_CHARS * 4],
                 limit=MAX_VERDICT_NOTE_CHARS).strip()
    stamp = (clean(str(observed_at)[:256], limit=64)
             if observed_at else datetime.now(timezone.utc).isoformat())
    seq = (observation_seq() if observed_seq is None
           else _bounded_int(observed_seq, 0, 0, 2**63 - 1))
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO review_verdicts (package_name, rule_id, campaign_id,"
                " verdict, observed_at, observed_seq, note)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (package, rule_id, campaign_id, verdict, stamp, seq, note),
            )
            conn.commit()
    except sqlite3.Error as exc:
        raise RuntimeError("could not record the verdict") from exc


def verdicts_for_package(package_name: str, limit: int = 500) -> list[dict]:
    """Recorded verdicts for *package_name*, newest first."""
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM review_verdicts WHERE package_name = ?"
                " ORDER BY observed_at DESC, id DESC LIMIT ?",
                (package_name, _bounded_int(limit, 500, 1, MAX_VERDICT_ROWS)),
            ).fetchall()
    except Exception:  # noqa: BLE001 - a cold store has no rows
        return []
    return [dict(row) for row in rows]


def tender_point(package_name: str, months: int = 6,
                 min_unresolved: int = 3) -> dict:
    """Count unresolved verdicts over a window ending at the latest cycle.

    The cutoff is derived from the stored latest cycle time, never from
    ``datetime.now()``: a replay over the same database returns the same
    count.  A missing table is ``unavailable``, not ``clear``.
    """
    from ._profiles import latest_cycle_time

    months = _bounded_int(months, 6, 1, 120)
    min_unresolved = _bounded_int(min_unresolved, 3, 1, 1_000)
    if not review_verdicts_available():
        return {"state": "unavailable", "unresolved": 0, "months": int(months)}
    try:
        latest = latest_cycle_time()
        anchor = (datetime.fromtimestamp(int(latest), timezone.utc)
                  if latest else None)
    except Exception:  # noqa: BLE001
        anchor = None
    if anchor is None:
        return {"state": "unavailable", "unresolved": 0, "months": int(months)}
    cutoff = (anchor - timedelta(days=30 * max(1, int(months)))).isoformat()
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM review_verdicts"
                " WHERE package_name = ? AND verdict = 'uncertain'"
                " AND observed_at >= ?",
                (package_name, cutoff),
            ).fetchone()
        count = int(row["n"] if row is not None else 0)
    except Exception:  # noqa: BLE001
        return {"state": "unavailable", "unresolved": 0, "months": int(months)}
    return {
        "state": "tender" if count >= max(1, int(min_unresolved)) else "clear",
        "unresolved": count,
        "months": int(months),
    }
