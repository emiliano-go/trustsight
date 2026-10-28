"""A best-effort record of the last baseline and IOC pull.

The pre-command notice (``cli/updates.py``) warns when a newer baseline or IOC
release is waiting on a followed channel.  "Newer" means the channel offers a
tag the operator has not pulled yet, so the pull actually performed has to be
remembered somewhere.  This is that somewhere: a tiny JSON file beside the
update-check cache, written on every successful baseline/IOC import and read by
the notice.

It is best-effort by design.  A missing, corrupt or unwritable file is a miss,
never an error: the worst case is that the notice repeats, which is exactly the
behaviour the version notice already has.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from .bounded_io import read_file_capped

log = logging.getLogger(__name__)

MAX_CHANNEL_STATE_BYTES = 1024 * 1024

#: The kinds of channel this tracks.
BASELINE = "baseline"
IOC = "ioc"
WATCHLIST = "watchlist"


def _path() -> Path:
    from .config import CACHE_DIR

    return CACHE_DIR / "channel-pulls.json"


def _read() -> dict:
    try:
        data = json.loads(read_file_capped(
            _path(), MAX_CHANNEL_STATE_BYTES, "channel pull state"))
    except Exception:  # noqa: BLE001 - a missing or corrupt file is a miss
        return {}
    return data if isinstance(data, dict) else {}


def record_pull(kind: str, tag: str | None, channel: str = "") -> None:
    """Record that *kind* was pulled at *tag* from *channel*.

    Best-effort: never raises.  An empty *tag* is recorded as-is; the notice
    treats an empty recorded tag as "never pulled".
    """
    if kind not in (BASELINE, IOC, WATCHLIST):
        return
    try:
        from .config import ensure_dirs

        ensure_dirs()
        data = _read()
        data[kind] = {
            "tag": str(tag or ""),
            "channel": str(channel or ""),
            "at": time.time(),
        }
        _path().write_text(json.dumps(data), encoding="utf-8")
    except Exception:  # noqa: BLE001 - the record is best-effort
        log.debug("could not record %s pull", kind, exc_info=True)


def pulled(kind: str) -> dict | None:
    """The recorded pull for *kind*, or ``None``."""
    entry = _read().get(kind)
    return entry if isinstance(entry, dict) else None


def pulled_tag(kind: str) -> str | None:
    """The recorded tag for *kind*, or ``None`` when never pulled."""
    entry = pulled(kind)
    if not entry:
        return None
    return str(entry.get("tag") or "") or None
