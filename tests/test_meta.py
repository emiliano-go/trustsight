"""Addendum 5 §6.5: the M-series meta/confluence predicates."""

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
