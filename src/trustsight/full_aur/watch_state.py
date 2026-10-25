"""Recorded liveness for the always-on watcher.

The log is not a health signal: a watcher whose every cycle fails is quiet in
exactly the same way as a watcher with nothing to report.  These metadata keys
keep the last start, the last success and the consecutive failure count so the
``full-aur health`` command and the failure heartbeat can tell the two apart.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..db import alert_outbox_stats, get_db_path, get_metadata, set_metadata

_LAST_STARTED = "watch_last_started"
_LAST_SUCCESS = "watch_last_success"
_LAST_FAILURE = "watch_last_failure"
_FAILURES = "watch_consecutive_failures"
_LAST_ERROR = "watch_last_error"
_INTERVAL = "watch_interval"

#: Failures before the watcher pushes a low-priority failure heartbeat.
_FAILURE_NOTICE_AFTER = 3


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


def record_start(interval: int, now: datetime | None = None) -> None:
    moment = now or _now()
    set_metadata(_LAST_STARTED, _stamp(moment))
    set_metadata(_INTERVAL, str(int(interval)))


def record_success(now: datetime | None = None) -> None:
    moment = now or _now()
    set_metadata(_LAST_SUCCESS, _stamp(moment))
    set_metadata(_FAILURES, "0")
    set_metadata(_LAST_ERROR, "")


def record_failure(error: str, now: datetime | None = None) -> int:
    moment = now or _now()
    try:
        failures = int(get_metadata(_FAILURES) or 0) + 1
    except (TypeError, ValueError):
        failures = 1
    set_metadata(_LAST_FAILURE, _stamp(moment))
    set_metadata(_FAILURES, str(failures))
    set_metadata(_LAST_ERROR, str(error)[:1000])
    return failures


def should_notify_failure(failures: int) -> bool:
    return failures >= _FAILURE_NOTICE_AFTER


def health(now: datetime | None = None) -> dict:
    """The watcher's recorded state and a healthy/unhealthy verdict."""
    moment = now or _now()
    if not get_db_path().exists():
        return {"watching": False, "healthy": True, "reason": "no database"}
    last_started = _parse(get_metadata(_LAST_STARTED))
    last_success = _parse(get_metadata(_LAST_SUCCESS))
    last_failure = _parse(get_metadata(_LAST_FAILURE))
    if last_started is None and last_success is None:
        return {"watching": False, "healthy": True, "reason": "not a watcher"}
    try:
        interval = int(get_metadata(_INTERVAL) or 3600)
    except (TypeError, ValueError):
        interval = 3600
    try:
        failures = int(get_metadata(_FAILURES) or 0)
    except (TypeError, ValueError):
        failures = 0
    max_age = max(interval * 2 + 300, 900)
    age = int((moment - last_success).total_seconds()) if last_success else None
    try:
        outbox = alert_outbox_stats(moment)
    except Exception:  # noqa: BLE001 - health must report, not raise
        outbox = {"pending": 0, "parked": 0, "oldest_pending_seconds": 0}
    reasons = []
    if last_success is None:
        reasons.append("no successful cycle recorded")
    elif age is not None and age > max_age:
        reasons.append(f"last success {age}s ago, limit {max_age}s")
    if failures >= _FAILURE_NOTICE_AFTER:
        reasons.append(f"{failures} consecutive failed cycles")
    if outbox.get("parked"):
        reasons.append(f"{outbox['parked']} parked alert document(s)")
    path = get_db_path()
    return {
        "watching": True,
        "healthy": not reasons,
        "reason": "; ".join(reasons),
        "last_started": _stamp(last_started) if last_started else "",
        "last_success": _stamp(last_success) if last_success else "",
        "last_failure": _stamp(last_failure) if last_failure else "",
        "last_error": get_metadata(_LAST_ERROR) or "",
        "interval": interval,
        "max_age": max_age,
        "consecutive_failures": failures,
        "outbox": outbox,
        "db_bytes": path.stat().st_size if path.exists() else 0,
    }
