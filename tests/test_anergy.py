"""The anergy ledger: state, scoring enforcement, and release gates."""

from __future__ import annotations

import json

from trustsight import anergy
from trustsight.anergy import ANERGIC, AnergyEntry
from trustsight.schema import NoveltyContext
from trustsight.scoring import calculate_score


def _entry(rule_id: str, status: str = ANERGIC) -> AnergyEntry:
    return AnergyEntry(
        rule_id=rule_id,
        status=status,
        signal="locked corpus rate < 0.30",
        since="0.27.0",
        promotion="corpus rate < 0.30 and changelog",
    )


def test_shipped_ledger_records_the_promoted_detectors():
    promoted = {row.rule_id for row in anergy.promoted_entries()}
    assert {"T004", "T005", "C033"} <= promoted
    assert "C034" not in promoted  # INFO by design, never scored


def test_scoring_forces_anergic_rules_to_zero(monkeypatch):
    monkeypatch.setattr(
        anergy, "_ENTRIES", {"X999": _entry("X999")}, raising=False)
    finding = {
        "rule_id": "X999", "name": "probe", "severity": "CRITICAL",
        "category": "x", "match": "probe", "weight_override": 40,
    }
    score, breakdown, _ = calculate_score([finding], {}, NoveltyContext())
    row = next(entry for entry in breakdown if entry.rule_id == "X999")
    assert row.weight == 0
    assert row.evidence["anergic"] is True


def test_a_promoted_rule_scores_normally(monkeypatch):
    monkeypatch.setattr(
        anergy, "_ENTRIES", {"X999": _entry("X999", "promoted")}, raising=False)
    finding = {
        "rule_id": "X999", "name": "probe", "severity": "MEDIUM",
        "category": "x", "match": "probe",
    }
    score, breakdown, _ = calculate_score([finding], {}, NoveltyContext())
    row = next(entry for entry in breakdown if entry.rule_id == "X999")
    assert row.weight == 15


def test_anergy_gates_pass_on_the_shipped_ledger():
    from scripts.gates._process import (
        gate_anergic_promotions_are_changelogged,
        gate_anergic_rules_never_score,
    )

    assert gate_anergic_rules_never_score().passed
    assert gate_anergic_promotions_are_changelogged().passed


def test_admin_anergic_json_lists_the_ledger():
    from typer.testing import CliRunner

    from trustsight.cli import app

    result = CliRunner().invoke(app, ["admin", "anergic", "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert {row["rule_id"] for row in rows} == set(anergy.anergic_ids())
    assert all(row["status"] == "anergic" for row in rows)


def test_a_decided_zero_weight_keeps_a_promoted_rule_report_only(monkeypatch):
    decided = AnergyEntry(
        rule_id="X999", status="promoted", signal="s", since="0.28.0",
        promotion="p", promoted_in="0.28.0", changelog="c",
        weight=0, decided_in="0.28.0",
    )
    monkeypatch.setattr(anergy, "_ENTRIES", {"X999": decided}, raising=False)
    finding = {
        "rule_id": "X999", "name": "probe", "severity": "HIGH",
        "category": "x", "match": "probe",
    }
    _, breakdown, _ = calculate_score([finding], {}, NoveltyContext())
    row = next(entry for entry in breakdown if entry.rule_id == "X999")
    assert row.weight == 0


def test_a_decided_weight_overrides_severity(monkeypatch):
    decided = AnergyEntry(
        rule_id="X999", status="promoted", signal="s", since="0.28.0",
        promotion="p", promoted_in="0.28.0", changelog="c",
        weight=40, decided_in="0.28.0",
    )
    monkeypatch.setattr(anergy, "_ENTRIES", {"X999": decided}, raising=False)
    finding = {
        "rule_id": "X999", "name": "probe", "severity": "MEDIUM",
        "category": "x", "match": "probe",
    }
    _, breakdown, _ = calculate_score([finding], {}, NoveltyContext())
    row = next(entry for entry in breakdown if entry.rule_id == "X999")
    assert row.weight == 40


def test_anergic_temporal_rules_stay_weight_zero():
    finding = {
        "rule_id": "T008", "name": "Delayed Payload Adoption",
        "severity": "INFO", "category": "temporal", "match": "probe",
    }
    _, breakdown, _ = calculate_score([finding], {}, NoveltyContext())
    row = next(entry for entry in breakdown if entry.rule_id == "T008")
    assert row.weight == 0
    assert row.evidence.get("anergic") is True


def test_the_shipped_ledger_marks_c001_conditional():
    row = anergy.entry("C001")
    assert row is not None
    assert row.status == anergy.CONDITIONAL
    assert "upstream_hash" in row.signal
    assert not anergy.is_anergic("C001")


def test_a_conditional_entry_scores_normally(monkeypatch):
    monkeypatch.setattr(
        anergy, "_ENTRIES", {"C001": _entry("C001", anergy.CONDITIONAL)},
        raising=False)
    finding = {
        "rule_id": "C001", "name": "probe", "severity": "HIGH",
        "category": "integrity", "match": "probe",
    }
    _, breakdown, _ = calculate_score(
        [finding], {}, NoveltyContext())
    rows = [row for row in breakdown if row.rule_id == "C001"]
    assert rows and rows[0].weight > 0


def test_conditional_and_anergic_entries_share_the_weekly_review(monkeypatch):
    entries = {
        "C001": _entry("C001", anergy.CONDITIONAL),
        "H009": _entry("H009"),
    }
    monkeypatch.setattr(anergy, "_ENTRIES", entries, raising=False)
    assert anergy.review_ids() == ["C001", "H009"]
    assert anergy.anergic_ids() == ["H009"]
