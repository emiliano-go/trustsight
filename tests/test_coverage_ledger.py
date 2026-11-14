"""The coverage ledger must account for every catalog id exactly once."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from calibration._gates import gate_coverage_expectations  # noqa: E402
from calibration._ledger import (  # noqa: E402
    Observation,
    build_ledger,
    expected_from_strata,
    ledger_audit,
    unmet_expectations,
)
from trustsight.contract import pseudo_rule_ids, rule_ids  # noqa: E402


def test_every_catalog_id_has_one_state_and_a_reason():
    ledger = build_ledger([Observation(source="cold")])
    assert set(ledger["rules"]) == set(rule_ids()) | set(pseudo_rule_ids())
    assert all(row["state"] in {"measured", "zero_fire", "cold_only", "adversarial_only"}
               for row in ledger["rules"].values())
    assert all(row["reason"] for row in ledger["rules"].values()
               if row["state"] != "measured")


def test_committed_ledger_matches_the_strata_expectations():
    """Adding a stratum must update the committed ledger's expectations.

    The ledger is rebuilt in CI; a stratum edit that only changes
    ``strata.toml`` leaves the checked-in expectations stale, and
    ``coverage_ledger.py --check`` reports functional drift even though the
    coverage gate itself still passes.
    """
    import tomllib

    fixture = Path(__file__).resolve().parent / "fixtures" / "coverage-ledger.json"
    strata = Path(__file__).resolve().parent.parent / "scripts" / "strata.toml"
    expected = expected_from_strata(tomllib.loads(strata.read_text()))
    ledger = json.loads(fixture.read_text())
    for rid, row in ledger["rules"].items():
        assert row.get("expected_strata", []) == expected.get(rid, []), rid


def test_a_benign_fire_makes_a_rule_measured_with_its_stratum():
    fired = set(rule_ids())
    obs = Observation(source="cold", fires={rid: 1 for rid in fired})
    for rid in fired:
        obs.strata[rid].add("source_patched")
    ledger = build_ledger([obs])
    row = ledger["rules"]["H015"]
    assert row["state"] == "measured"
    assert row["sources"]["cold"]["strata"] == ["source_patched"]


def test_cold_only_and_adversarial_states_are_distinct():
    ledger = build_ledger([Observation(source="cold")])
    assert ledger["rules"]["G001"]["state"] == "cold_only"
    assert ledger["rules"]["A001"]["state"] == "cold_only"
    assert ledger["rules"]["X001"]["state"] == "adversarial_only"
    assert ledger["rules"]["S001"]["state"] == "adversarial_only"
    assert ledger["rules"]["R001"]["state"] == "adversarial_only"
    assert ledger["rules"]["H096"]["state"] == "zero_fire"


def test_ledger_audit_names_unexpected_and_unmoved_expectations():
    before = build_ledger([Observation(source="cold")])
    fired = Observation(source="cold", fires={"H015": 1, "H016": 1})
    after = build_ledger([fired])
    audit = ledger_audit(before, after, expected={"H015": ["source_patched"]})
    assert "H015" in audit["moved"]
    assert "H016" in audit["unexpected"]
    assert audit["unmoved_expectations"] == []


def test_t_series_source_exercises_the_stateful_t_rules():
    import coverage_ledger

    fired = {
        rule_id
        for row in coverage_ledger._scan_t_series()
        for rule_id in row["fired"]
    }
    assert fired == {"T001", "T002", "T003"}


def _write_ledger(path: Path, **kwargs) -> dict:
    ledger = build_ledger([Observation(source="cold")], **kwargs)
    path.write_text(json.dumps(ledger))
    return ledger


def test_benign_state_separates_malicious_only_from_cold_only():
    obs = Observation(source="malicious", fires={"H015": 1})
    obs.strata["H015"].add("attack")
    ledger = build_ledger([obs])
    assert ledger["rules"]["H015"]["benign_state"] == "malicious_only"
    assert ledger["rules"]["H015"]["expected_met"] is False
    assert ledger["rules"]["G001"]["benign_state"] == "cold_only"
    assert ledger["rules"]["X001"]["benign_state"] == "adversarial_only"


def test_unmet_expectations_reports_missing_source_and_wrong_stratum():
    obs = Observation(source="cold", fires={"H015": 1})
    obs.strata["H015"].add("bin_repack")
    ledger = build_ledger([obs])
    unmet = unmet_expectations(ledger, {"H015": ["source_patched"]},
                               require_stratum=True)
    assert unmet["H015"]["reason"] == "wrong_stratum"
    assert unmet["H015"]["missing_strata"] == ["source_patched"]
    assert unmet_expectations(ledger, {"H016": ["source_patched"]})["H016"]["reason"] == "no_benign_source"


def test_coverage_gate_requires_a_disposition(tmp_path):
    path = tmp_path / "ledger.json"
    _write_ledger(path, expected={"H015": ["source_patched"]})
    gate = gate_coverage_expectations(path)
    assert not gate.passed
    assert "unmet without disposition" in gate.detail


def test_coverage_gate_requires_a_disposition_for_every_unmeasured_rule(tmp_path):
    """A rule with no benign source and no expectation is still a gap: the
    ledger may not leave it unclassified just because no stratum names it."""
    path = tmp_path / "ledger.json"
    _write_ledger(path)
    gate = gate_coverage_expectations(path)
    assert not gate.passed
    assert "unmeasured without disposition" in gate.detail

    dispositions = {
        rid: {"status": "deferred", "plan": "add_benign_shape"}
        for rid, row in json.loads(path.read_text())["rules"].items()
        if not row.get("benign_sources")
    }
    _write_ledger(path, dispositions=dispositions)
    assert gate_coverage_expectations(path).passed


def test_coverage_gate_accepts_deferred_and_rejects_stale_add(tmp_path):
    disposition = {"status": "deferred", "plan": "add_benign_shape"}
    path = tmp_path / "ledger.json"
    base = build_ledger([Observation(source="cold")],
                        expected={"H015": ["source_patched"]})
    all_dispositions = {
        rid: disposition for rid, row in base["rules"].items()
        if not row.get("benign_sources")
    }
    all_dispositions["H015"] = disposition
    ledger = build_ledger([Observation(source="cold")],
                          expected={"H015": ["source_patched"]},
                          dispositions=all_dispositions)
    path.write_text(json.dumps(ledger))
    assert gate_coverage_expectations(path).passed

    obs = Observation(source="cold", fires={"H015": 1})
    obs.strata["H015"].add("source_patched")
    ledger = build_ledger([obs], expected={"H015": ["source_patched"]},
                          dispositions=all_dispositions)
    path.write_text(json.dumps(ledger))
    gate = gate_coverage_expectations(path)
    assert not gate.passed
    assert "stale add_* disposition" in gate.detail


def test_coverage_gate_rejects_resolved_non_benign_expectation(tmp_path):
    path = tmp_path / "ledger.json"
    _write_ledger(
        path, expected={"H015": ["source_patched"]},
        dispositions={"H015": {"status": "resolved", "plan": "attack_only"}},
    )
    gate = gate_coverage_expectations(path)
    assert not gate.passed
    assert "resolved non-benign plan still expected" in gate.detail


def test_ledger_check_detects_functional_drift(tmp_path):
    import coverage_ledger

    committed = build_ledger([Observation(source="cold")],
                             expected={"H015": ["source_patched"]})
    current = json.loads(json.dumps(committed))
    path = tmp_path / "committed.json"
    path.write_text(json.dumps(committed))
    assert coverage_ledger._ledger_drift(path, current) == []
    current["rules"]["H015"]["expected_met"] = True
    assert coverage_ledger._ledger_drift(path, current)
