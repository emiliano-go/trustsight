"""Explicit state for the persisted lifecycles.

Each lifecycle used to live as loose columns and arithmetic spread across a
module.  The states here are values: they are built from a database row,
advanced by one pure transition function, and written back by the caller.
Illegal transitions raise instead of silently producing a row no reader
expects, and the rules are testable without SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Any

__all__ = [
    "AlertOutboxState",
    "CampaignState",
    "IllegalTransition",
    "OrphanState",
    "format_stamp",
    "parse_stamp",
]

_MAX_ERROR_CHARS = 1000


class IllegalTransition(ValueError):
    """A transition that the lifecycle's invariants forbid."""


def parse_stamp(value: Any) -> datetime | None:
    """An ISO timestamp as an aware datetime, or ``None``."""
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def format_stamp(moment: datetime) -> str:
    return moment.isoformat()


# ---------------------------------------------------------------------------
# Alert outbox
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertOutboxState:
    """One alert document's delivery state.

    States: ``pending`` (not parked, not fully delivered, due now),
    ``waiting`` (a retry is scheduled), ``parked`` (terminal), and
    ``delivered`` (both sinks accepted it).  ``feed_only`` rows start with
    the ntfy sink already marked, because the all-scan feed never goes to
    ntfy.
    """

    created_at: datetime
    attempts: int = 0
    next_attempt_at: datetime | None = None
    ntfy_delivered: bool = False
    feed_delivered: bool = False
    parked_at: datetime | None = None
    feed_only: bool = False
    last_error: str = ""

    def __post_init__(self) -> None:
        if self.attempts < 0:
            raise IllegalTransition("outbox attempts cannot be negative")

    @property
    def delivered(self) -> bool:
        return self.ntfy_delivered and self.feed_delivered

    @property
    def parked(self) -> bool:
        return self.parked_at is not None

    def due(self, now: datetime) -> bool:
        """Whether the row should be attempted at *now*."""
        if self.parked or self.delivered:
            return False
        return self.next_attempt_at is None or self.next_attempt_at <= now

    def with_sink(self, sink: str) -> "AlertOutboxState":
        """Mark one sink delivered; finish the row when both are done."""
        if sink not in ("ntfy", "feed"):
            raise IllegalTransition(f"unknown alert sink: {sink!r}")
        if self.parked:
            raise IllegalTransition("a parked alert cannot be delivered")
        ntfy = self.ntfy_delivered or sink == "ntfy"
        feed = self.feed_delivered or sink == "feed"
        next_attempt = None if (ntfy and feed) else self.next_attempt_at
        return replace(
            self, ntfy_delivered=ntfy, feed_delivered=feed,
            next_attempt_at=next_attempt,
        )

    def failed(
        self, now: datetime, error: str,
        *, max_attempts: int, max_age: timedelta,
        backoff_base_seconds: int, backoff_max_seconds: int,
    ) -> tuple["AlertOutboxState", bool]:
        """Record a failed attempt; return the next state and whether parked."""
        if self.parked:
            raise IllegalTransition("a parked alert cannot fail again")
        if self.delivered:
            raise IllegalTransition("a delivered alert cannot fail again")
        attempts = self.attempts + 1
        expired = now - self.created_at >= max_age
        park = expired or attempts >= max_attempts
        if park:
            state = replace(
                self, attempts=attempts, parked_at=now,
                next_attempt_at=None,
                last_error=str(error)[:_MAX_ERROR_CHARS],
            )
        else:
            delay = min(
                backoff_base_seconds * (2 ** (attempts - 1)),
                backoff_max_seconds,
            )
            state = replace(
                self, attempts=attempts,
                next_attempt_at=now + timedelta(seconds=delay),
                last_error=str(error)[:_MAX_ERROR_CHARS],
            )
        return state, park


# ---------------------------------------------------------------------------
# Campaign lifetime
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CampaignState:
    """A campaign's activation window, measured in observations."""

    campaign_id: str
    activated_at_obs: int
    ttl_obs: int
    expiry_announced: bool = False
    activation_count: int = 1
    first_activated_at_obs: int = 0
    last_activated_at_obs: int = 0

    def __post_init__(self) -> None:
        if self.ttl_obs < 1:
            raise IllegalTransition("campaign ttl must be at least one observation")
        if self.activated_at_obs < 0:
            raise IllegalTransition("campaign activation cannot be negative")
        if self.activation_count < 1:
            raise IllegalTransition("campaign activation count must be positive")

    @property
    def expires_at_obs(self) -> int:
        return self.activated_at_obs + self.ttl_obs

    def is_active(self, now_obs: int) -> bool:
        return self.expires_at_obs > now_obs

    def is_expired(self, now_obs: int) -> bool:
        return not self.is_active(now_obs)

    def is_expired_unannounced(self, now_obs: int) -> bool:
        return self.is_expired(now_obs) and not self.expiry_announced

    def reactivated(self, now_obs: int, ttl_obs: int) -> "CampaignState":
        """Refresh the window; never shorten a live one."""
        ttl = max(1, int(ttl_obs))
        if self.is_active(now_obs) and ttl < self.ttl_obs:
            # The caller asked to shorten a live window.  Keep the live
            # protection; reporting may notice, enforcement may not.
            ttl = self.ttl_obs
        return replace(
            self,
            activated_at_obs=now_obs,
            ttl_obs=ttl,
            expiry_announced=False,
            activation_count=self.activation_count + 1,
            first_activated_at_obs=(
                self.activated_at_obs
                if self.first_activated_at_obs == 0
                else self.first_activated_at_obs
            ),
            last_activated_at_obs=now_obs,
        )


# ---------------------------------------------------------------------------
# AUR orphan tri-state
# ---------------------------------------------------------------------------


class OrphanState(IntEnum):
    """The last recorded AUR orphan answer.

    ``UNKNOWN`` is load-bearing: "never asked" is not "was maintained" and
    is not "was orphaned".  H086 needs a prior ``ORPHANED`` observation.
    """

    UNKNOWN = -1
    MAINTAINED = 0
    ORPHANED = 1

    @classmethod
    def from_db(cls, value: Any) -> "OrphanState":
        if value is None:
            return cls.UNKNOWN
        try:
            return cls(int(value))
        except (TypeError, ValueError):
            return cls.UNKNOWN

    @classmethod
    def observe(cls, orphaned: bool | None) -> "OrphanState":
        """The state after a metadata read: unavailable is UNKNOWN."""
        if orphaned is None:
            return cls.UNKNOWN
        return cls.ORPHANED if orphaned else cls.MAINTAINED

    @property
    def was_orphaned(self) -> bool:
        return self is OrphanState.ORPHANED
