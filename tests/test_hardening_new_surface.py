"""Hostile-input bounds for the new surfaces: tags, campaign, verdicts."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from trustsight.schema import ScoreEntry


def test_tag_events_bound_hostile_values_and_unhashables():
    from trustsight.tags import (
        MAX_TAG_EVENTS,
        MAX_TAG_VALUE_CHARS,
        tag_events_from_breakdown,
        tag_panel,
    )

    breakdown = [
        ScoreEntry(rule_id="P001", severity="INFO", weight=0,
                   params={"literal": "A" * 100_000 + "\x1b[31m"}),
        ScoreEntry(rule_id="G007", severity="INFO", weight=0,
                   params={"campaign_id": {"nested": "unhashable"}},
                   techniques=[{"bad": "shape"}, "ok"]),
    ]
    events = tag_events_from_breakdown(
        breakdown, contacts=[{"kind": "host", "value": 12345}, None, "junk"])
    assert len(events) <= MAX_TAG_EVENTS
    assert all(len(event.value) <= MAX_TAG_VALUE_CHARS + 1 for event in events)
    assert all("\x1b" not in event.value for event in events)
    panel = tag_panel(events)
    assert panel == tag_panel(list(reversed(events)))


def test_notify_ignores_unhashable_and_non_string_members():
    from trustsight.full_aur.pipeline import CycleResult
    from trustsight.notify import alert_payload

    cycle = CycleResult(cluster_findings=[{
        "rule_id": "G001",
        "params": {"members": ["b", {"bad": 1}, ["also", "bad"], None, "a"]},
    }])
    payload = alert_payload(cycle)
    cluster = payload["campaign_cluster"][0]
    assert cluster["members"] == ["a", "b"]


def test_missing_self_tolerates_malformed_recipe_arrays():
    from trustsight.analysis.structural._missing_self import (
        scheme_downgrade_findings,
        srcinfo_version_findings,
        vouch_surface_findings,
    )

    calls = []

    def add(*args, **kwargs):
        calls.append((args, kwargs))
    # Arrays are not tuples of strings; a direct caller (or a future parser
    # regression) must stand the rules down, not raise.
    pre = SimpleNamespace(arrays={
        "validpgpkeys": 123,
        "source": None,
        "source_x86_64": "https://example.com/a",
    })
    post = SimpleNamespace(arrays={
        "validpgpkeys": {"not": "a list"},
        "source": 5,
        "source_x86_64": "http://example.com/b",
    })
    vouch_surface_findings("diff", pre, post, add)
    scheme_downgrade_findings(pre, post, add)
    srcinfo_version_findings(None, [("bad", object()), (".SRCINFO", b"\xff")], add)
    # No crash; any finding is a normal one.
    assert isinstance(calls, list)


def test_malformed_tree_manifest_is_skipped_not_fatal():
    from trustsight.analysis import scan_diff

    fact = scan_diff(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n-pkgver=1\n+pkgver=2\n",
        package_name="demo",
        tree_manifest=[("bad", object()), None, ("x", 5),
                       (".SRCINFO", b"pkgbase = demo\n\tpkgver = 1\n")],
        current_text="pkgname=demo\npkgver=2\npkgrel=1\n",
    )
    assert fact.final_score >= 0


def test_verdict_inputs_are_bounded_and_invalid_dispositions_refused():
    import trustsight.db as db

    db.init_db()
    from trustsight.db._verdicts import (
        MAX_VERDICT_NOTE_CHARS,
        record_verdict,
        tender_point,
        verdicts_for_package,
    )

    record_verdict("hardening-demo" + "\x1b[0m", "uncertain", rule_id="H015",
                   note="\x00" + "x" * 100_000)
    rows = verdicts_for_package("hardening-demo", limit=10**12)
    assert len(rows) == 1
    assert len(rows[0]["note"]) <= MAX_VERDICT_NOTE_CHARS
    assert "\x00" not in rows[0]["note"]
    assert tender_point("hardening-demo", months="not-a-number",
                        min_unresolved="also-bad")["months"] == 6
    with pytest.raises(ValueError):
        record_verdict("hardening-demo", "explode")


def test_record_alerts_skips_malformed_pairs_and_bounds_campaign_ids():
    import trustsight.db as db

    db.init_db()
    audit = []
    fresh = db.record_alerts([
        (),
        ("pkg",),
        (None, None),
        ("pkg", "H015"),
        ("pkg2", "H015", {"not": "a string"}),
        ("pkg3", "H015", "c" * 10_000),
    ], audit=audit)
    assert ("pkg", "H015") in fresh
    assert all(isinstance(pair, tuple) and len(pair) == 2 for pair in fresh)
    assert len(audit) <= 10_000


def test_self_state_caps_hostile_channel_values(monkeypatch):
    from trustsight import channel_state
    from trustsight.reporting import _self_state

    monkeypatch.setattr(
        channel_state, "pulled",
        lambda kind: {"tag": "T" * 100_000 + "\x1b[2J",
                      "channel": "c" * 100_000, "obs": "bad"})
    state = _self_state(SimpleNamespace(package_name="demo",
                                        campaign_state="unavailable"))
    for row in state["channels"].values():
        assert len(row["tag"] or "") <= 200
        assert len(row["channel"]) <= 200
        assert "\x1b" not in row["channel"]
