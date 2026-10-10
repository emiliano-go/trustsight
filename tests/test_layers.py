"""The assurance-layer registry (Addendum 5 §2/§3)."""

from trustsight.categories import RULE_CATEGORIES
from trustsight.layers import (
    LAYER_ORDER,
    Layer,
    layer_of,
    layer_profile,
    rules_in_layer,
)


def test_every_rule_has_exactly_one_layer():
    # The M series has no static layer by design: it fires at the layer of
    # its inputs (Addendum 5 §2), so layer_of returns None for it.
    unassigned = [
        rid for rid in RULE_CATEGORIES
        if not rid.startswith("M") and layer_of(rid) is None
    ]
    assert not unassigned, f"rules without a layer: {sorted(unassigned)}"
    assert all(layer_of(rid) is None
               for rid in RULE_CATEGORIES if rid.startswith("M"))


def test_non_rule_ids_have_no_layer():
    for rid in ("P001", "Z999", "", "R015"):
        assert layer_of(rid) is None


def test_refusal_rules_are_readability():
    assert layer_of("X026") is Layer.L2
    assert layer_of("X027") is Layer.L2


def test_series_defaults():
    assert layer_of("R001") is Layer.L3
    assert layer_of("C001") is Layer.L1
    assert layer_of("D001") is Layer.L6
    assert layer_of("S001") is Layer.L3
    assert layer_of("X001") is Layer.L4
    assert layer_of("H015") is Layer.L5


def test_observational_and_indicator_overrides():
    assert layer_of("H020") is Layer.L6
    assert layer_of("H088") is Layer.L6
    assert layer_of("H056") is Layer.L7


def test_layers_l1_through_l7_are_non_empty():
    for layer in LAYER_ORDER[:7]:
        assert rules_in_layer(layer), f"{layer} has no rules"
    # L8 is reserved for the G-series; empty until it ships, and never
    # populated by a non-G rule.
    assert all(rid.startswith("G") for rid in rules_in_layer(Layer.L8))


class _Fact:
    def __init__(self, *, gaps=(), diff_truncated=False, scan_truncated=False):
        self.coverage_gaps = gaps
        self.diff_truncated = diff_truncated
        self.scan_truncated = scan_truncated


def test_profile_marks_fired_passed_unreadable():
    findings = [{"rule_id": "R001"}]
    profile = layer_profile(_Fact(), findings)
    assert set(profile) == {layer.value for layer in LAYER_ORDER}
    assert profile["L3"]["status"] == "fired"
    assert profile["L3"]["findings"] == ["R001"]
    assert profile["L1"]["status"] == "passed"

    unread = layer_profile(_Fact(diff_truncated=True), findings)
    assert unread["L1"]["status"] == "unreadable"
    assert unread["L3"]["status"] == "fired"


def test_profile_ignores_non_rule_findings():
    profile = layer_profile(_Fact(), [{"rule_id": "P001"}])
    assert all(entry["status"] == "passed" for entry in profile.values())


def test_unreadable_is_gap_precise():
    """A history gap blinds ecosystem memory, not the whole profile."""
    profile = layer_profile(_Fact(gaps=["parent_baseline"]), [])
    assert profile["L6"]["status"] == "unreadable"
    assert profile["L1"]["status"] == "passed"
    assert profile["L3"]["status"] == "passed"


def test_content_truncation_blinds_every_layer():
    profile = layer_profile(_Fact(gaps=["diff_truncated"]), [])
    assert all(entry["status"] == "unreadable" for entry in profile.values())


def test_an_unknown_gap_fails_safe():
    profile = layer_profile(_Fact(gaps=["some_new_bound"]), [])
    assert all(entry["status"] == "unreadable" for entry in profile.values())


def test_verdict_names_the_deepest_layer():
    from trustsight.schema import PackageFact, ScoreEntry
    from trustsight.verdict import fallback_verdict, layer_sentence

    fact = PackageFact(
        package_name="demo",
        score_breakdown=[
            ScoreEntry(rule_id="R001", severity="CRITICAL", weight=100, reason="r"),
            ScoreEntry(rule_id="X001", severity="CRITICAL", weight=100, reason="x"),
        ],
    )
    sentence = layer_sentence(fact)
    assert "L4" in sentence and "evasion" in sentence.lower()
    assert "L4" in fallback_verdict(fact)


def test_a_clean_package_has_no_layer_sentence():
    from trustsight.schema import PackageFact
    from trustsight.verdict import layer_sentence

    assert layer_sentence(PackageFact(package_name="demo")) == ""
