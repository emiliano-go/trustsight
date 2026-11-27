"""AUR request waves: campaign shapes only, never a single request.

The lane exists because Arch staff process the request queue in batches, so a
window alone is a processing artefact.  These fixtures are the four acceptance
cases that decide whether the lane is worth having - in particular the one
that must stay quiet.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from trustsight.request_waves import (
    DEFAULT_THRESHOLDS,
    Request,
    detect_waves,
    new_events,
)

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)


def req(prq, filer, kind, pkgbase, minutes_ago, day_offset=0):
    return Request(
        prq=prq, filer=filer, kind=kind, pkgbase=pkgbase,
        filed_at=NOW - timedelta(minutes=minutes_ago) - timedelta(days=day_offset),
    )


def shapes(events):
    return [event.shape for event in events]


def test_a_filers_batch_of_adoptions_fires_once():
    """fbf-prog64 filed four adoption requests in one batch, 26/11/2026."""
    rows = [
        req(91001, "fbf-prog64", "adoption", "fbf-one", 55),
        req(91002, "fbf-prog64", "adoption", "fbf-two", 50),
        req(91003, "fbf-prog64", "adoption", "fbf-three", 45),
        req(91004, "fbf-prog64", "adoption", "fbf-four", 40),
    ]
    events = detect_waves(rows)
    assert shapes(events) == ["filer_burst"]
    burst = events[0]
    assert burst.filers == ("fbf-prog64",)
    assert burst.prqs == (91001, 91002, 91003, 91004)
    assert burst.kind_mix == {"adoption": 4}
    assert burst.window_seconds == int(timedelta(hours=1).total_seconds())
    assert len(burst.pkgbases) == 4


def test_staff_processing_twenty_filers_in_an_hour_is_not_a_wave():
    """The acceptance case: twenty adoptions, twenty filers, one hour."""
    rows = [
        req(92000 + index, f"filer-{index}", "adoption", f"pkg-{index}", 60 - index)
        for index in range(20)
    ]
    events = detect_waves(rows, pkgbase_org={f"pkg-{index}": f"org-{index}" for index in range(20)})
    assert events == []


def test_a_high_volume_maintainer_at_their_own_rate_is_not_a_wave():
    rows = [req(93000 + day, "steady", "adoption", f"pkg-{day}", 0, day_offset=day)
            for day in range(1, 91)]
    rows += [req(94001, "steady", "adoption", "pkg-a", 300),
             req(94002, "steady", "adoption", "pkg-b", 120)]
    assert detect_waves(rows) == []


def test_the_same_batch_is_not_announced_twice():
    rows = [
        req(95001, "bursty", "adoption", "pkg-a", 55),
        req(95002, "bursty", "adoption", "pkg-b", 50),
        req(95003, "bursty", "adoption", "pkg-c", 45),
        req(95004, "bursty", "adoption", "pkg-d", 40),
    ]
    seen: set[str] = set()
    first = new_events(detect_waves(rows), seen)
    second = new_events(detect_waves(rows), seen)
    assert len(first) == 1
    assert second == []


def test_orphan_then_adopt_by_one_filer_fires():
    rows = [
        req(96001, "squeeze", "orphan", "target-pkg", 1200),
        req(96002, "squeeze", "adoption", "target-pkg", 600),
    ]
    events = detect_waves(rows)
    assert "orphan_then_adopt" in shapes(events)
    event = next(e for e in events if e.shape == "orphan_then_adopt")
    assert event.prqs == (96001, 96002)
    assert event.pkgbases == ("target-pkg",)


def test_three_first_seen_accounts_on_one_org_fire_the_cohort():
    rows = [
        req(97001, "new-one", "adoption", "pkg-a", 300),
        req(97002, "new-two", "adoption", "pkg-b", 240),
        req(97003, "new-three", "adoption", "pkg-c", 120),
    ]
    events = detect_waves(rows, pkgbase_org={"pkg-a": "acme", "pkg-b": "acme", "pkg-c": "acme"})
    assert "first_seen_cohort" in shapes(events)
    cohort = next(e for e in events if e.shape == "first_seen_cohort")
    assert cohort.filers == ("new-one", "new-three", "new-two")
    assert cohort.window_seconds == int(DEFAULT_THRESHOLDS.day.total_seconds())


def test_an_established_account_at_three_sigma_fires():
    baseline = [req(98000 + day, "heavy", "adoption", f"pkg-{day}", 0, day_offset=day)
                for day in range(1, 91)]
    spike = [req(99000 + index, "heavy", "adoption", f"spike-{index}", 60 - index * 5)
             for index in range(6)]
    events = detect_waves(baseline + spike)
    assert "filer_burst" in shapes(events)
    burst = next(e for e in events if e.shape == "filer_burst")
    assert set(burst.prqs) <= set(range(99000, 99006))
    assert len(burst.prqs) == 4


def test_one_request_is_never_an_event():
    assert detect_waves([req(1, "someone", "adoption", "pkg", 5)]) == []
