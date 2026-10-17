"""Malformed input must not crash the new immune-import surfaces.

Every entry point here is reachable with a hand-edited config, a corrupt
database row, or (for the corpus functions) a finding built from
attacker-influenced metadata.  The rule is the same as everywhere else: a
nonsensical value is refused or ignored, never raised out of the analysis.
"""

import pytest

from trustsight.db import (
    activate_campaign,
    active_campaigns,
    init_db,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield


# --- campaign state ---------------------------------------------------------


def test_activate_campaign_tolerates_nonsense_arguments(db):
    # None/overflow TTL, non-iterable scope: refused to a sane value, no crash.
    for ttl in (None, float("inf"), "x"):
        assert activate_campaign("c", ["a"], "s", ttl) is True
    assert activate_campaign("c2", None) is True
    assert activate_campaign("c3", 5) is True
    assert activate_campaign("c4", ["a"], "s", 1, max_active=float("inf")) is True
    assert active_campaigns(now_obs="not-an-int") is not None


# --- W010 -------------------------------------------------------------------


def test_alert_volume_finding_tolerates_a_bad_cap_and_bad_rules():
    from trustsight.analysis.meta import alert_volume_finding

    for cap in (float("inf"), float("nan"), "x", [], None):
        finding = alert_volume_finding(
            [{"rule_id": f"C{i:03d}", "severity": "HIGH"} for i in range(8)],
            {"alerts": {"max_rendered_findings": cap},
             "severity_weights": {"HIGH": 25}},
        )
        assert finding is None or finding["rule_id"] == "W010"
    # Non-dict rules, missing severity, a bool weight override: no crash.
    odd = [None, "x", {"rule_id": None}, {"rule_id": "C1", "weight_override": True}]
    assert alert_volume_finding(odd * 30,
                                {"alerts": {"max_rendered_findings": 5},
                                 "severity_weights": {}}) is not None


# --- corpus campaign aggregation -------------------------------------------


def test_neighborhood_elevation_tolerates_bad_records(db):
    from trustsight.full_aur.pipeline import _neighborhood_elevation

    activate_campaign("g001:new.cdn", {"hosts": ["new.cdn"]}, "G001", ttl_obs=50)
    assert _neighborhood_elevation(None) == []
    assert _neighborhood_elevation("x") == []
    assert _neighborhood_elevation([None, "y", {"package": "a"}]) == []
    # A bare-string host and a non-list members param are handled.
    assert _neighborhood_elevation(
        [{"package": "a", "hosts_gained": "new.cdn"}])[0]["rule_id"] == "G006"


def test_campaign_identity_tolerates_bad_findings():
    from trustsight.full_aur.pipeline import _campaign_identity

    assert _campaign_identity(None) is None
    assert _campaign_identity("x") is None
    assert _campaign_identity({}) is None
    assert _campaign_identity(
        {"rule_id": "G005", "params": "x"}) == (
            "g005:unknown", {"package_names": [], "targets": []})
    assert _campaign_identity(
        {"rule_id": "G005", "params": {"members": [None, 1], "targets": "y"}}
    ) == ("g005:unknown",
          {"package_names": ["1", "None"], "targets": ["y"]})


def test_activate_campaigns_tolerates_bad_findings(db):
    from trustsight.full_aur.pipeline import _activate_campaigns

    _activate_campaigns([None, "x", {"rule_id": "G003", "params": {}}], {})


# --- overrides --------------------------------------------------------------


def test_override_expiry_tolerates_a_bad_clock(monkeypatch):
    import trustsight.override as ov
    from trustsight.override import RuleOverride, filter_triggered_rules

    override = RuleOverride(rule_id="H029", reason="r", package="p",
                            created_at_obs="old", ttl_observations="5")
    monkeypatch.setattr(ov, "load_overrides", lambda: [override])
    # A malformed clock must not raise; the override simply is not expired.
    kept, suppressed = filter_triggered_rules(
        [{"rule_id": "H029", "severity": "HIGH"}], package="p", now_obs="nonsense")
    assert len(kept) + len(suppressed) == 1


def test_indicator_cross_check_ignores_non_dict_rows():
    from trustsight.override import apply_indicator_cross_check

    assert apply_indicator_cross_check(None, True) is None
    rows = ["x", None, {"override_requires_clear_indicators": True}]
    apply_indicator_cross_check(rows, True)
    assert rows[2]["indicator_corroborated"] is True


# --- scoring / escalation ---------------------------------------------------


def test_licensors_fired_tolerates_malformed_rules(monkeypatch):
    from trustsight.scoring import _annotate_licensed, _licensors_fired
    from trustsight.schema import ScoreEntry

    monkeypatch.setattr("trustsight.config.load_rules",
                        lambda: [None, "x", {"id": "R1", "escalates_when": 5},
                                 {"id": "R2", "escalates_when": [{"bad": 1}]}])
    assert _licensors_fired({"R1"}) is False
    _annotate_licensed([None, "y", ScoreEntry(rule_id="R1")])


def test_lint_chains_tolerate_malformed_rules():
    from trustsight.lint import lint_escalation_chains

    assert lint_escalation_chains(None) == []
    assert lint_escalation_chains("x") == []
    assert lint_escalation_chains(
        [None, {"id": "R1", "escalates_when": "R2"}]) == []


# --- notify -----------------------------------------------------------------


def test_alert_payload_tolerates_malformed_cycle():
    from trustsight.full_aur.pipeline import CycleResult
    from trustsight.notify import alert_payload

    # A None score, non-dict cluster findings, duplicate alerts: no crash.
    cycle = CycleResult(
        over_threshold=[("a", None), ("b", "9")],
        cluster_findings=[None, "x", {"rule_id": "G005", "params": None}],
        new_alerts=[("a", "H001"), ("a", "H001")],
    )
    payload = alert_payload(cycle)
    assert isinstance(payload["title"], str)


# --- install capture --------------------------------------------------------


def test_install_diff_text_refuses_non_text():
    from trustsight.full_aur.analyze import _install_diff_text

    assert _install_diff_text(None, "p") == ""
    assert _install_diff_text("", "p") == ""
