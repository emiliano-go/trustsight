"""The coverage ledger must account for every catalog id exactly once."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from calibration._ledger import (  # noqa: E402
    Observation,
    build_ledger,
    ledger_audit,
)
from trustsight.contract import pseudo_rule_ids, rule_ids  # noqa: E402


def test_every_catalog_id_has_one_state_and_a_reason():
    ledger = build_ledger([Observation(source="cold")])
    assert set(ledger["rules"]) == set(rule_ids()) | set(pseudo_rule_ids())
    assert all(row["state"] in {"measured", "zero_fire", "cold_only", "adversarial_only"}
               for row in ledger["rules"].values())
    assert all(row["reason"] for row in ledger["rules"].values()
               if row["state"] != "measured")


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
