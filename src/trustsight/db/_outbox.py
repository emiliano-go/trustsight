"""Durable delivery queue for watcher alert documents.

An unattended watcher must not lose the one document it produced because a
webhook was down.  The queue stores the exact payload and the webhook identity
used to sign it, so a retry is the same document and the feed's idempotency
key still matches.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from ._connection import get_connection

#: Attempts before a document is parked.  A parked document is visible in
#: ``full-aur health`` and the logs; it is never silently discarded.
MAX_ATTEMPTS = 10

#: Documents older than this are parked even if attempts remain.
MAX_AGE = timedelta(hours=24)

#: Retry spacing: 30s, 1m, 2m, ... capped at six hours.
_BACKOFF_BASE_SECONDS = 30
_BACKOFF_MAX_SECONDS = 6 * 60 * 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    return moment.isoformat()


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def enqueue_alert_payload(
    payload: dict,
    webhook_id: str,
    webhook_timestamp: int,
    now: datetime | None = None,
) -> int:
    """Store *payload* and return its row id."""
    stamp = _stamp(now or _now())
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO alert_outbox (created_at, payload_json, webhook_id, "
            "webhook_timestamp) VALUES (?, ?, ?, ?)",
            (stamp, body, webhook_id, int(webhook_timestamp)),
        )
        conn.commit()
        return int(cur.lastrowid)


def pending_alert_payloads(
    now: datetime | None = None, limit: int = 20,
) -> list[dict]:
    """Rows due for delivery, oldest first."""
    moment = now or _now()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, created_at, payload_json, webhook_id, "
            "webhook_timestamp, attempts, next_attempt_at, "
            "ntfy_delivered, feed_delivered "
            "FROM alert_outbox "
            "WHERE parked_at IS NULL "
            "AND (next_attempt_at IS NULL OR next_attempt_at <= ?) "
            "AND (ntfy_delivered = 0 OR feed_delivered = 0) "
            "ORDER BY id LIMIT ?",
            (_stamp(moment), int(limit)),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["payload"] = json.loads(item.pop("payload_json"))
        except (TypeError, ValueError):
            item["payload"] = {}
        out.append(item)
    return out


def mark_alert_sink(row_id: int, sink: str) -> None:
    """Mark one sink as delivered; finish the row when both are done."""
    if sink not in ("ntfy", "feed"):
        raise ValueError(f"unknown alert sink: {sink!r}")
    with get_connection() as conn:
        if sink == "ntfy":
            conn.execute(
                "UPDATE alert_outbox SET ntfy_delivered = 1 WHERE id = ?",
                (row_id,),
            )
        else:
            conn.execute(
                "UPDATE alert_outbox SET feed_delivered = 1 WHERE id = ?",
                (row_id,),
            )
        conn.execute(
            "UPDATE alert_outbox SET next_attempt_at = NULL "
            "WHERE id = ? AND ntfy_delivered = 1 AND feed_delivered = 1",
            (row_id,),
        )
        conn.commit()


def mark_alert_attempt(
    row_id: int,
    error: str,
    now: datetime | None = None,
) -> bool:
    """Record a failed attempt; return True when the row was parked."""
    moment = now or _now()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT created_at, attempts FROM alert_outbox WHERE id = ?",
            (row_id,),
        ).fetchone()
        if row is None:
            return False
        attempts = int(row["attempts"] or 0) + 1
        created = _parse(row["created_at"]) or moment
        expired = moment - created >= MAX_AGE
        park = expired or attempts >= MAX_ATTEMPTS
        if park:
            conn.execute(
                "UPDATE alert_outbox SET attempts = ?, parked_at = ?, "
                "last_error = ? WHERE id = ?",
                (attempts, _stamp(moment), str(error)[:1000], row_id),
            )
        else:
            delay = min(
                _BACKOFF_BASE_SECONDS * (2 ** (attempts - 1)),
                _BACKOFF_MAX_SECONDS,
            )
            conn.execute(
                "UPDATE alert_outbox SET attempts = ?, next_attempt_at = ?, "
                "last_error = ? WHERE id = ?",
                (
                    attempts,
                    _stamp(moment + timedelta(seconds=delay)),
                    str(error)[:1000],
                    row_id,
                ),
            )
        conn.commit()
    return park


def alert_outbox_stats(now: datetime | None = None) -> dict:
    """Counts and age of the delivery queue."""
    moment = now or _now()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT created_at, parked_at, ntfy_delivered, feed_delivered "
            "FROM alert_outbox"
        ).fetchall()
    pending = 0
    parked = 0
    oldest: datetime | None = None
    for row in rows:
        if row["parked_at"]:
            parked += 1
            continue
        if row["ntfy_delivered"] and row["feed_delivered"]:
            continue
        pending += 1
        created = _parse(row["created_at"])
        if created and (oldest is None or created < oldest):
            oldest = created
    return {
        "pending": pending,
        "parked": parked,
        "oldest_pending_seconds": (
            int((moment - oldest).total_seconds()) if oldest else 0
        ),
    }
