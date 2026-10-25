"""Operator maintenance for a long-lived watcher database."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from ._connection import get_connection, get_db_path
from ._outbox import alert_outbox_stats


def database_stats() -> dict:
    """Size and queue health without changing anything."""
    path = get_db_path()
    db_bytes = path.stat().st_size if path.exists() else 0
    wal = path.with_name(path.name + "-wal")
    wal_bytes = wal.stat().st_size if wal.exists() else 0
    return {
        "path": str(path),
        "bytes": db_bytes,
        "wal_bytes": wal_bytes,
        "outbox": alert_outbox_stats(),
    }


def prune_cycle_events(days: int) -> int:
    """Delete cycle events older than *days*; 0 disables pruning."""
    if days <= 0:
        return 0
    cutoff = int(time.time()) - days * 86400
    with get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM cycle_events WHERE cycle_time < ?", (cutoff,)
        )
        conn.commit()
        return int(cur.rowcount or 0)


def prune_alert_state(days: int) -> int:
    """Delete alert history not seen for *days*; 0 disables pruning."""
    if days <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM alert_state WHERE last_sent < ?", (cutoff,)
        )
        conn.commit()
        return int(cur.rowcount or 0)


def vacuum_database() -> None:
    """Reclaim space after a prune.  Expensive; operator-invoked only."""
    with get_connection() as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.commit()
