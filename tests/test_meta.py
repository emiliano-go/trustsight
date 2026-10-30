"""The M-series meta/confluence predicates."""

from trustsight.analysis.meta import (
    claim_contradictions,
    composition_not_owned,
    m_series_findings,
    weak_layer_span,
)
from trustsight.analysis.pipeline import scan_diff


def _ids(text: str) -> set[str]:
    return {e.rule_id for e in scan_diff(text, package_name="demo").score_breakdown}


def test_m001_fires_when_a_checksum_claim_is_contradicted():
    found = claim_contradictions([{"rule_id": "H091"}])
    assert [f["rule_id"] for f in found] == ["M001"]
    assert found[0]["evidence"]["contradicted_by"] == "H091"


def test_m001_fires_two_contradiction_shapes():
    rules = {"H091", "H024"}
    assert len(claim_contradictions([{"rule_id": r} for r in rules])) == 2


def test_m001_does_not_fire_without_a_contradiction():
    assert claim_contradictions([{"rule_id": "R001"}]) == []


def test_m002_fires_on_three_weak_layers():
    # R001=L3, H015=L5, C001=L1: three layers, none strong.
    triggered = [
        {"rule_id": "R001", "severity": "MEDIUM", "category": "network"},
        {"rule_id": "H015", "severity": "MEDIUM", "category": "context"},
        {"rule_id": "C001", "severity": "INFO", "category": "integrity"},
    ]
    found = weak_layer_span(triggered, None)
    assert len(found) == 1
    assert found[0]["rule_id"] == "M002"
    assert found[0]["weight_override"] == 0


def test_m002_stands_down_when_a_strong_signal_exists():
    triggered = [
        {"rule_id": "R001", "severity": "CRITICAL", "category": "network"},
        {"rule_id": "H015", "severity": "MEDIUM", "category": "context"},
        {"rule_id": "C001", "severity": "INFO", "category": "integrity"},
    ]
    assert weak_layer_span(triggered, None) == []


def test_m003_fires_when_no_cluster_owner_recorded():
    triggered = [
        {"rule_id": "R001", "category": "network"},
        {"rule_id": "H015", "category": "context"},
    ]
    found = composition_not_owned(triggered, None)
    assert len(found) == 1
    assert found[0]["weight_override"] == 0


def test_m003_stands_down_when_an_owner_recorded_it():
    triggered = [
        {"rule_id": "R001", "category": "network"},
        {"rule_id": "H015", "category": "context"},
        {"rule_id": "H027", "category": "meta"},
    ]
    assert composition_not_owned(triggered, None) == []


def test_m_series_is_wired_into_the_scan():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "+source=('https://a.example/x' 'https://b.example/y')\n"
        "+sha256sums=('aaaa')\n"
    )
    ids = _ids(text)
    assert "H091" in ids
    assert "M001" in ids


def test_m_series_findings_are_a_flat_list():
    found = m_series_findings(
        [{"rule_id": "H091", "severity": "HIGH", "category": "integrity"}],
        None,
    )
    assert isinstance(found, list)
    assert any(f["rule_id"] == "M001" for f in found)


def test_m001_requires_the_claim_when_a_ledger_is_supplied():
    triggered = [{"rule_id": "H091"}]
    assert claim_contradictions(triggered, claims=set()) == []
    assert len(claim_contradictions(triggered, claims={"P001"})) == 1


def test_declared_claims_from_evidence_and_pinning():
    from trustsight.scoring import declared_claims

    claims = declared_claims(
        verification_evidence=["checksum_present", "validpgpkeys_declared"],
        pinning_level="commit_pinned",
        source_buckets={"https://github.com/a/b": "trusted_forge"},
    )
    assert claims == {"P001", "P002", "P005", "P007"}


def test_m004_cofire_absence_is_a_health_note_not_a_finding():
    from trustsight.analysis.meta import cofire_absence

    notes = cofire_absence([{"rule_id": "H091"}], [("H091", "H024")])
    assert notes == ["H091 fired without expected co-fire H024"]
    assert cofire_absence(
        [{"rule_id": "H091"}, {"rule_id": "H024"}], [("H091", "H024")]) == []


def test_m002_and_m003_escalate_the_band_one_step():
    from trustsight.schema import ScoreEntry
    from trustsight.scoring import _escalate_for_meta

    for rule_id in ("M002", "M003"):
        breakdown = [ScoreEntry(
            rule_id=rule_id, severity="MEDIUM", weight=0, reason="span")]
        assert _escalate_for_meta("Low", breakdown) == "Medium"
        assert _escalate_for_meta("Medium", breakdown) == "High"
        assert _escalate_for_meta("High", breakdown) == "Critical"
        assert _escalate_for_meta("Critical", breakdown) == "Critical"


def test_no_escalation_without_an_meta_rule():
    from trustsight.scoring import _escalate_for_meta

    assert _escalate_for_meta("Low", []) == "Low"
    assert _escalate_for_meta("Inconclusive", []) == "Inconclusive"


def test_alert_volume_finding_counts_and_groups():
    from trustsight.analysis.meta import alert_volume_finding

    rules = [{"rule_id": f"C{i:03d}", "severity": "HIGH", "category": "x"}
             for i in range(60)]
    config = {"alerts": {"max_rendered_findings": 50},
              "severity_weights": {"HIGH": 25, "INFO": 0}}
    finding = alert_volume_finding(rules, config)
    assert finding["rule_id"] == "W010"
    assert finding["severity"] == "INFO"
    assert finding["params"]["shown"] == 50
    assert finding["params"]["grouped"] == 10
    # Under the cap: no finding at all.
    assert alert_volume_finding(rules[:40], config) is None
    # A cap of 0 disables it.
    assert alert_volume_finding(rules, {"alerts": {"max_rendered_findings": 0}}) is None


def test_escalation_fires_when_a_declared_licensor_also_fired(monkeypatch):
    """A rule declaring `escalates_when` moves the band one notch only."""
    import trustsight.scoring as scoring
    from trustsight.schema import ScoreEntry

    monkeypatch.setattr(
        "trustsight.config.load_rules",
        lambda: [{"id": "R001", "escalates_when": ["R002"]}],
    )
    licensor = ScoreEntry(rule_id="R002", severity="LOW", weight=5, reason="y")
    licensed = ScoreEntry(rule_id="R001", severity="HIGH", weight=25, reason="x")
    assert scoring._escalate_for_meta("Medium", [licensed, licensor]) == "High"
    # Without the licensor: the bump is lost, the finding is not.
    assert scoring._escalate_for_meta("Medium", [licensed]) == "Medium"
    # Never to FATAL: Critical stays Critical.
    assert scoring._escalate_for_meta(
        "Critical", [licensed, licensor]) == "Critical"


def test_m005_reports_a_licensed_shape_without_its_licensor():
    from trustsight.analysis.meta import m_tool_health

    rules = [{"id": "R001", "escalates_when": ["R002"]}]
    fired = [{"rule_id": "R001", "severity": "HIGH"}]
    rows = m_tool_health(fired, rules)
    assert [r["rule_id"] for r in rows] == ["M005"]
    # With the licensor present: no tool-health note.
    assert m_tool_health(fired + [{"rule_id": "R002"}], rules) == []


def test_m004_fires_when_a_configured_cofire_pair_breaks(monkeypatch):
    from trustsight.analysis import meta

    monkeypatch.setattr(meta, "_cofire_pairs", lambda: [("X001", "X002")])
    rows = meta.m_tool_health([{"rule_id": "X001", "severity": "HIGH"}], [])
    assert [r["rule_id"] for r in rows] == ["M004"]
    # With the partner present: quiet.
    assert meta.m_tool_health(
        [{"rule_id": "X001"}, {"rule_id": "X002"}], []) == []


def test_licensed_escalation_is_attributed(monkeypatch):
    from trustsight.scoring import _annotate_licensed
    from trustsight.schema import ScoreEntry

    monkeypatch.setattr(
        "trustsight.config.load_rules",
        lambda: [{"id": "R001", "escalates_when": ["R002"]}],
    )
    breakdown = [
        ScoreEntry(rule_id="R001", severity="HIGH", weight=25, reason="x"),
        ScoreEntry(rule_id="R002", severity="LOW", weight=5, reason="y"),
    ]
    _annotate_licensed(breakdown)
    assert breakdown[0].licensed_by == ("R002",)
    assert breakdown[1].licensed_by == ()


def test_m006_reports_reactivation_pressure_with_its_measurements():
    from trustsight.analysis.meta import campaign_reactivation_notes

    pressure = [{
        "source": "campaign", "campaign_id": "camp-123", "count": 3,
        "span": 2, "min_interval": 5,
    }]
    rows = campaign_reactivation_notes(pressure)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "M006"
    assert rows[0]["name"] == "Campaign Re-armed Too Often"
    assert rows[0]["severity"] == "INFO"
    assert rows[0]["category"] == "meta"
    assert rows[0]["params"] == pressure[0]
    assert "camp-123 re-armed 3 time(s) over 2 observation(s)" in rows[0]["match"]


def test_m006_stands_down_without_reactivation_pressure():
    from trustsight.analysis.meta import campaign_reactivation_notes

    assert campaign_reactivation_notes(None) == []
    assert campaign_reactivation_notes([]) == []
    assert campaign_reactivation_notes([None, "not-a-row"]) == []
