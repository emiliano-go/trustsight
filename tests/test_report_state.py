"""Tag panel, self-state, campaign context, refractory, tender point."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from trustsight.analysis import scan_diff
from trustsight.reporting import evaluate_fact, report_body
from trustsight.schema import ScoreEntry


def _body(fact):
    return report_body(evaluate_fact(fact), include_score=True, verbose=True)


def test_report_body_carries_the_state_keys():
    fact = scan_diff(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
        " pkgname=demo\n-pkgver=1\n+pkgver=2\n",
        package_name="demo",
    )
    body = _body(fact)
    for key in ("tag_panel", "self_state", "campaign_hold", "campaign_id",
                "campaign_state", "tender_point"):
        assert key in body
    assert body["self_state"]["blind"] == sorted(body["self_state"]["blind"])


def test_tag_events_are_grouped_and_convergence_is_bounded():
    from trustsight.tags import (
        TagEvent,
        tag_convergence,
        tag_events_from_breakdown,
        tag_panel,
    )

    breakdown = [
        ScoreEntry(rule_id="P001", severity="INFO", weight=0),
        ScoreEntry(rule_id="W009", severity="INFO", weight=0),
        ScoreEntry(rule_id="G007", severity="INFO", weight=0,
                   evidence={"campaign_id": "camp-x"}),
        ScoreEntry(rule_id="H003", severity="LOW", weight=5),
    ]
    events = tag_events_from_breakdown(breakdown)
    assert events == sorted(events, key=lambda event: event.sort_key)
    assert {event.kind for event in events} == {"annotation", "campaign"}
    panel = tag_panel(events)
    assert [row["kind"] for row in panel] == ["campaign", "annotation"]
    assert tag_convergence([TagEvent("contact", "h")], 2) is None
    assert tag_convergence(
        [TagEvent("contact", "h"), TagEvent("campaign", "c")], 2)["count"] == 2


def test_campaign_context_adds_g007_w013_and_hold(monkeypatch):
    import trustsight.db as db
    from trustsight.analysis.pipeline._analyze_helpers import (
        _campaign_corroboration,
    )

    db.init_db()
    db.activate_campaign("camp-demo", {"package_names": ["demo"]}, "G001")
    breakdown = [ScoreEntry(rule_id="W009", severity="INFO", weight=0)]
    score, enriched, context = _campaign_corroboration(
        0, breakdown, "demo", [], ["parent_baseline"])
    assert score == 0
    assert {entry.rule_id for entry in enriched} == {"W009", "G007", "W013"}
    assert all(entry.weight == 0 for entry in enriched)
    assert context == {
        "campaign_hold": True,
        "campaign_id": "camp-demo",
        "campaign_state": "active",
    }


def test_refractory_debounces_one_alert_per_campaign_window():
    import trustsight.db as db

    db.init_db()
    db.activate_campaign("camp-demo", {"package_names": ["demo"]}, "G001")
    audit: list[dict] = []
    first = db.record_alerts([("demo", "G001", "camp-demo")], audit=audit)
    second = db.record_alerts([("demo", "G001", "camp-demo")], audit=audit)
    assert first == [("demo", "G001")]
    assert second == []
    assert audit[0]["emitted"] is True
    assert audit[1]["emitted"] is False


def test_tender_point_counts_unresolved_verdicts(monkeypatch):
    import trustsight.db as db
    import trustsight.db._profiles as profiles

    db.init_db()
    now = int(datetime.now(timezone.utc).timestamp())
    monkeypatch.setattr(profiles, "latest_cycle_time", lambda: now)
    for _ in range(3):
        db.record_verdict("tender-demo", "uncertain", rule_id="H015",
                          observed_at=datetime.now(timezone.utc).isoformat())
    point = db.tender_point("tender-demo", months=6, min_unresolved=3)
    assert point["state"] == "tender"
    assert point["unresolved"] == 3


def test_cli_records_a_verdict():
    from typer.testing import CliRunner

    from trustsight.cli import app

    result = CliRunner().invoke(app, [
        "verdict", "cli-demo", "--verdict", "cleared", "--rule", "H015",
        "--json",
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["verdict"] == "cleared"
