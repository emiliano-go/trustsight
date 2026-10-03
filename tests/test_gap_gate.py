"""The known-gap gate must notice a gap closed by a different rule.

The evasion fixtures name the rule that was *meant* to catch a shape.  When
a later rule catches it instead, the label's own check still fails and the
fixture sits filed as an open gap forever; the array-subscript, nameref and
command-substitution gaps survived that way after the crossfire family
closed them.  These tests pin the helper that reports the stale record.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import calibration_gates as gates  # noqa: E402


def _result(**over):
    base = {
        "name": "evasion.diff",
        "score": 60,
        "fired": {"R001"},
        "scored": {"R001", "SOURCE_BUCKET"},
        "expected": {"known_gap": True, "must_fire": ["R133"], "min_score": 40},
    }
    base.update(over)
    return base


def test_a_gap_detected_by_another_rule_is_reported():
    assert gates._gap_detected_by_another_rule(_result()) == ["R001"]


def test_a_gap_with_no_detection_stays_open():
    result = _result(score=20, fired=set(), scored={"SOURCE_BUCKET"})
    assert gates._gap_detected_by_another_rule(result) == []


def test_the_named_rule_firing_is_left_to_the_label_check():
    result = _result(fired={"R133"}, scored={"R133"})
    assert gates._gap_detected_by_another_rule(result) == []


def test_a_covered_fixture_is_not_a_gap_report():
    result = _result(expected={"must_fire": ["R001"]})
    assert gates._gap_detected_by_another_rule(result) == []


def test_coverage_priors_are_not_a_detection():
    result = _result(score=20, fired=set(), scored={"COVERAGE", "NOVELTY"})
    assert gates._gap_detected_by_another_rule(result) == []


def test_a_score_below_the_bar_is_still_open():
    result = _result(score=25, fired=set(), scored={"R001"})
    assert gates._gap_detected_by_another_rule(result) == []


def test_the_warm_d_series_gate_passes():
    """The gate scans warm fixtures with the corpus and cold without it."""
    gate = gates.gate_d_series_warm()
    assert gate.passed, f"measured={gate.measured} {gate.detail}"
