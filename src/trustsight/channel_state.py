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
from dataclasses import dataclass
from pathlib import Path

from .bounded_io import read_file_capped

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ChannelPull:
    """One recorded pull: which tag, from which channel, for which feed."""

    tag: str = ""
    channel: str = ""
    feed: str = ""
    at: float = 0.0
    obs: int = 0

    @classmethod
    def from_record(cls, record: dict) -> "ChannelPull":
        def _number(value, cast, default):
            try:
                return cast(value)
            except (TypeError, ValueError, OverflowError):
                return default

        return cls(
            tag=str(record.get("tag") or ""),
            channel=str(record.get("channel") or ""),
            feed=str(record.get("feed") or ""),
            at=_number(record.get("at") or 0.0, float, 0.0),
            obs=_number(record.get("obs") or 0, int, 0),
        )

    def matches(self, tag: str | None, channel: str = "") -> bool:
        """True when *tag* on *channel* is this pull.

        An empty recorded channel matches any channel: it is a legacy
        record, and re-announcing everything once on upgrade is worse than
        trusting the tag alone. An empty tag is never a match.
        """
        if not self.tag or str(tag or "") != self.tag:
            return False
        if not self.channel or not channel:
            return True
        return self.channel == str(channel)

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


def _key(kind: str, feed: str = "") -> str:
    """The record key for one pull: a kind, optionally one feed within it.

    The official/baseline/watchlist channels have one slot each. IOC has one
    slot per configured feed, because two feeds can legitimately sit on
    different tags and one must not mask the other's update.
    """
    feed = str(feed or "").strip()
    return kind if not feed else f"{kind}:{feed}"


def record_pull(
    kind: str, tag: str | None, channel: str = "", *, feed: str = "",
) -> None:
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
        try:
            from .db import observation_seq

            obs = int(observation_seq())
        except Exception:  # noqa: BLE001 - a missing DB is a cold pull
            obs = 0
        data[_key(kind, feed)] = {
            "tag": str(tag or ""),
            "channel": str(channel or ""),
            "feed": str(feed or ""),
            "at": time.time(),
            # The report ages a channel on the observation clock, never on
            # wall time: a replay must produce the same self-state.
            "obs": obs,
        }
        _path().write_text(json.dumps(data), encoding="utf-8")
    except Exception:  # noqa: BLE001 - the record is best-effort
        log.debug("could not record %s pull", kind, exc_info=True)


def pulled_state(kind: str, *, feed: str = "") -> ChannelPull | None:
    """The typed recorded pull for *kind* (or one *feed*), or ``None``."""
    entry = _read().get(_key(kind, feed))
    return ChannelPull.from_record(entry) if isinstance(entry, dict) else None


def pulled(kind: str, *, feed: str = "") -> dict | None:
    """The recorded pull for *kind* (or one *feed*), or ``None``."""
    entry = _read().get(_key(kind, feed))
    return entry if isinstance(entry, dict) else None


def pulled_tag(kind: str, *, feed: str = "") -> str | None:
    """The recorded tag for *kind*, or ``None`` when never pulled."""
    entry = pulled(kind, feed=feed)
    if not entry:
        return None
    return str(entry.get("tag") or "") or None


def pulled_channel(kind: str, *, feed: str = "") -> str | None:
    """The recorded channel for *kind*, or ``None`` when never pulled."""
    entry = pulled(kind, feed=feed)
    if not entry:
        return None
    return str(entry.get("channel") or "") or None


def pulled_matches(
    kind: str, tag: str | None, channel: str = "", *, feed: str = "",
) -> bool:
    """True when *tag* on *channel* is the pull already recorded.

    The tag alone was the old comparison, so a release republished on a
    different channel with the same tag read as "already pulled" and the
    operator was never told to pull the new channel's data. A recorded
    channel is therefore part of the identity. An empty recorded channel
    (an older record, or a caller that did not know one) matches any
    channel, so upgrading does not re-announce everything once.
    """
    entry = pulled_state(kind, feed=feed)
    return bool(entry and entry.matches(tag, channel))
