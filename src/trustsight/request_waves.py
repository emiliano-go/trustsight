"""Campaign-shaped waves in AUR package requests.

An individual adoption, orphan or deletion request is intent, not a change:
somebody asked for something, nothing has happened yet.  Reporting one is the
H058 mistake (a signal that fires so often it is muted).

Time alone is no better.  Arch staff review the request queue by hand and
process it in batches, so twenty approvals in one hour by twenty different
filers is an afternoon of staff work, not a campaign.  The false-positive
engine is therefore the window without the account: a wave is always
``(filer, window)``, never ``N requests in T``.

Three shapes are worth an event:

``filer_burst``
    One account filing at a rate that is extreme for that account.  Every
    account clears a hard floor (4 in an hour, 8 in a day) - a handful of
    requests is a person working - and an account with history must also
    deviate by three standard deviations from its own 90-day rate, so a
    high-volume maintainer doing routine work stays quiet.
``orphan_then_adopt``
    One account files orphan requests and then adoption requests on the same
    pkgbases within a day - the squeeze before the grab.
``first_seen_cohort``
    Three or more accounts with no request history file in the same day on
    pkgbases from one upstream organisation: the shape coordinated
    sock-puppets leave.

Nothing here scores a package or reads a recipe: the event names the filers,
the request numbers and the pkgbases, and the existing G/H rules on the push
side confirm or dismiss it days later.  Every function is pure, so the
fixtures run without a network or a database.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

__all__ = [
    "DEFAULT_THRESHOLDS",
    "Request",
    "Thresholds",
    "WaveEvent",
    "detect_waves",
    "new_events",
]

#: Request kinds the lane understands; anything else is carried as "other".
KINDS = frozenset({"adoption", "orphan", "deletion", "merge", "other"})

def _as_utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Request:
    """One filed AUR request, as the request feed reports it."""

    prq: int
    filer: str
    kind: str
    pkgbase: str
    filed_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "filed_at", _as_utc(self.filed_at))
        object.__setattr__(self, "kind", (self.kind or "other").strip().lower())
        if self.kind not in KINDS:
            object.__setattr__(self, "kind", "other")


@dataclass(frozen=True)
class Thresholds:
    """The bounds a wave has to clear.

    ``burst_hour`` and ``burst_day`` are the first-seen floors.  An account
    with at least ``min_history_days`` of history is judged against its own
    rate instead, at ``sigma`` standard deviations above the Poisson mean for
    the window.
    """

    burst_hour: int = 4
    burst_day: int = 8
    hour: timedelta = timedelta(hours=1)
    day: timedelta = timedelta(hours=24)
    cohort_accounts: int = 3
    sigma: float = 3.0
    baseline_days: int = 90
    min_history_days: int = 30


#: The threshold set the lane runs with.
DEFAULT_THRESHOLDS = Thresholds()


@dataclass(frozen=True)
class WaveEvent:
    """A campaign seed: what an account did, never what a package is."""

    shape: str
    filers: tuple[str, ...]
    prqs: tuple[int, ...]
    pkgbases: tuple[str, ...]
    kind_mix: dict[str, int] = field(default_factory=dict)
    window_seconds: int = 0
    filer_history_days: int = 0
    started_at: datetime | None = None
    ended_at: datetime | None = None

    def fingerprint(self) -> str:
        """Stable identity, so a re-poll never re-announces the same wave."""
        material = "|".join([
            self.shape,
            ",".join(sorted(self.filers)),
            ",".join(str(prq) for prq in sorted(self.prqs)),
        ])
        return hashlib.sha256(material.encode()).hexdigest()


def _kind_mix(rows: list[Request]) -> dict[str, int]:
    mix: dict[str, int] = {}
    for row in rows:
        mix[row.kind] = mix.get(row.kind, 0) + 1
    return dict(sorted(mix.items()))


def _window(rows: list[Request], until: datetime, span: timedelta) -> list[Request]:
    start = until - span
    return [row for row in rows if start < row.filed_at <= until]


def _history_days(rows: list[Request], moment: datetime) -> int:
    first = min((row.filed_at for row in rows), default=moment)
    return max(0, int((moment - first).days))


def _baseline_before(rows: list[Request], moment: datetime, days: int) -> float:
    """Requests per second in the *days* before *moment*, from the filer's own row."""
    start = moment - timedelta(days=days)
    prior = [row for row in rows if start <= row.filed_at < moment]
    return len(prior) / (days * 86400.0)


def _exceeds_rate(observed: int, expected: float, sigma: float) -> bool:
    """True when *observed* is at least *sigma* deviations above *expected*."""
    if expected <= 0:
        return False
    return observed >= expected + sigma * math.sqrt(expected)


def _burst_events(rows: list[Request], thresholds: Thresholds) -> list[WaveEvent]:
    events: list[WaveEvent] = []
    by_filer: dict[str, list[Request]] = {}
    for row in rows:
        by_filer.setdefault(row.filer, []).append(row)

    for filer, filer_rows in by_filer.items():
        filer_rows.sort(key=lambda row: row.filed_at)
        # One event per hot window, not one per request that lands in it: the
        # fifth request of the same burst must not announce the burst again.
        last_end: dict[int, datetime] = {}
        for end in filer_rows:
            history = _history_days(filer_rows, end.filed_at)
            established = history >= thresholds.min_history_days
            for span, floor in ((thresholds.hour, thresholds.burst_hour),
                                (thresholds.day, thresholds.burst_day)):
                window = _window(filer_rows, end.filed_at, span)
                count = len(window)
                if count < floor:
                    # A handful of requests is a person working, not a
                    # campaign: the floor holds for every account, and is the
                    # only test a first-seen account has.
                    continue
                if established:
                    rate = _baseline_before(filer_rows, end.filed_at, thresholds.baseline_days)
                    if not _exceeds_rate(count, rate * span.total_seconds(), thresholds.sigma):
                        continue
                start = end.filed_at - span
                seconds = int(span.total_seconds())
                if seconds in last_end and start < last_end[seconds]:
                    continue
                last_end[seconds] = end.filed_at
                events.append(WaveEvent(
                    shape="filer_burst",
                    filers=(filer,),
                    prqs=tuple(sorted(row.prq for row in window)),
                    pkgbases=tuple(sorted({row.pkgbase for row in window})),
                    kind_mix=_kind_mix(window),
                    window_seconds=int(span.total_seconds()),
                    filer_history_days=history,
                    started_at=start,
                    ended_at=end.filed_at,
                ))
    return events


def _orphan_then_adopt(rows: list[Request], thresholds: Thresholds) -> list[WaveEvent]:
    events: list[WaveEvent] = []
    by_filer: dict[str, list[Request]] = {}
    for row in rows:
        by_filer.setdefault(row.filer, []).append(row)

    for filer, filer_rows in by_filer.items():
        orphans = [row for row in filer_rows if row.kind == "orphan"]
        adoptions = [row for row in filer_rows if row.kind == "adoption"]
        if not orphans or not adoptions:
            continue
        pairs: list[tuple[Request, Request]] = []
        for adopted in adoptions:
            for orphan in orphans:
                delay = adopted.filed_at - orphan.filed_at
                if adopted.pkgbase == orphan.pkgbase and timedelta(0) <= delay <= thresholds.day:
                    pairs.append((orphan, adopted))
        if not pairs:
            continue
        involved = [row for pair in pairs for row in pair]
        events.append(WaveEvent(
            shape="orphan_then_adopt",
            filers=(filer,),
            prqs=tuple(sorted({row.prq for row in involved})),
            pkgbases=tuple(sorted({row.pkgbase for row in involved})),
            kind_mix=_kind_mix(involved),
            window_seconds=int(thresholds.day.total_seconds()),
            filer_history_days=_history_days(filer_rows, max(r.filed_at for r in involved)),
            started_at=min(row.filed_at for row in involved),
            ended_at=max(row.filed_at for row in involved),
        ))
    return events


def _first_seen_cohort(
    rows: list[Request], thresholds: Thresholds, pkgbase_org: dict[str, str],
) -> list[WaveEvent]:
    if not pkgbase_org:
        return []
    events: list[WaveEvent] = []
    first_by_filer: dict[str, datetime] = {}
    for row in rows:
        first_by_filer[row.filer] = min(first_by_filer.get(row.filer, row.filed_at),
                                        row.filed_at)
    recent = [row for row in rows
              if row.pkgbase in pkgbase_org
              and (row.filed_at - first_by_filer[row.filer]) < timedelta(
                  days=thresholds.min_history_days)]
    recent.sort(key=lambda row: row.filed_at)
    consumed: set[tuple[datetime, str]] = set()
    for anchor in recent:
        org = pkgbase_org[anchor.pkgbase]
        window = [row for row in recent
                  if org == pkgbase_org.get(row.pkgbase, "")
                  and anchor.filed_at - thresholds.day < row.filed_at <= anchor.filed_at]
        filers = {row.filer for row in window}
        if len(filers) < thresholds.cohort_accounts:
            continue
        start = anchor.filed_at - thresholds.day
        key = (start, org)
        if key in consumed:
            continue
        consumed.add(key)
        events.append(WaveEvent(
            shape="first_seen_cohort",
            filers=tuple(sorted(filers)),
            prqs=tuple(sorted({row.prq for row in window})),
            pkgbases=tuple(sorted({row.pkgbase for row in window})),
            kind_mix=_kind_mix(window),
            window_seconds=int(thresholds.day.total_seconds()),
            filer_history_days=0,
            started_at=start,
            ended_at=anchor.filed_at,
        ))
    return events


def detect_waves(
    requests,
    *,
    pkgbase_org: dict[str, str] | None = None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> list[WaveEvent]:
    """Every campaign-shaped wave in *requests*, oldest first.

    *requests* should span at least ``thresholds.baseline_days`` so an
    account's own rate can be measured; the function never fetches anything.
    *pkgbase_org* maps a pkgbase to the upstream organisation its ``url=``
    names, which is what the cohort shape joins on; pkgbases without an entry
    simply cannot join a cohort.
    """
    rows = sorted(requests, key=lambda row: row.filed_at)
    if not rows:
        return []
    events = _burst_events(rows, thresholds)
    events.extend(_orphan_then_adopt(rows, thresholds))
    events.extend(_first_seen_cohort(rows, thresholds, pkgbase_org or {}))
    events.sort(key=lambda event: (event.started_at or datetime.min.replace(tzinfo=timezone.utc),
                                   event.shape))
    return events


def new_events(events, seen: set[str]) -> list[WaveEvent]:
    """Drop events whose fingerprint the caller has already announced."""
    fresh: list[WaveEvent] = []
    for event in events:
        fingerprint = event.fingerprint()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        fresh.append(event)
    return fresh
