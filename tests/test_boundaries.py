"""Addendum 2 W1: the unified analysis-boundary model.

A coverage gap and a W-series finding describe the same fact: a limit on
what the analysis could conclude.  These tests pin that the two faces are
derived from one object, that the verdict view equals the legacy gap view
(the migration contract), and that the report carries it additively.
"""

from trustsight.boundaries import (
    AnalysisBoundary,
    BoundaryKind,
    boundary_kind_for_gap,
    boundary_kind_for_w_rule,
    boundaries_from_fact,
    forbids_clean,
)
from trustsight.reporting import evaluate_fact, report_body
from trustsight.schema import PackageFact, ScoreEntry


def _fact(gaps=(), rules=()):
    breakdown = [
        ScoreEntry(rule_id=rid, severity="INFO", weight=0, reason=f"{rid} reason")
        for rid in rules
    ]
    return PackageFact(
        package_name="demo", coverage_gaps=list(gaps), score_breakdown=breakdown)


def test_gap_and_w_rule_share_one_kind():
    assert boundary_kind_for_gap("unpinned_build_deps") == BoundaryKind.UNPINNED_DEPS
    assert boundary_kind_for_w_rule("W002") == BoundaryKind.REGISTRY_RESOLUTION
    assert boundary_kind_for_gap("binary_metadata") == BoundaryKind.UNREADABLE_FILE


def test_boundaries_include_gaps_and_w_findings():
    fact = _fact(gaps=["partial_hunk"], rules=["W001", "W006"])
    kinds = {b.kind for b in boundaries_from_fact(fact)}
    assert BoundaryKind.TRUNCATED in kinds
    assert BoundaryKind.UNREADABLE_FILE in kinds
    assert BoundaryKind.BUILD_ONLY_PATH in kinds


def test_forbids_clean_matches_the_legacy_gap_view():
    """The migration contract: the verdict view equals bool(coverage_gaps)."""
    for gaps in ([], ["diff_truncated"], ["parent_baseline", "ruleset_drifted"]):
        fact = _fact(gaps=gaps, rules=["W001"])
        assert forbids_clean(boundaries_from_fact(fact)) == bool(gaps)


def test_a_w_only_boundary_does_not_forbid_clean():
    boundaries = boundaries_from_fact(_fact(rules=["W001"]))
    assert len(boundaries) == 1
    assert boundaries[0].forbids_clean is False
    assert forbids_clean(boundaries) is False


def test_report_body_carries_boundaries_additively():
    fact = _fact(gaps=["diff_truncated"], rules=["W001"])
    body = report_body(evaluate_fact(fact))
    assert "boundaries" in body
    assert body["coverage_gaps"] == ["diff_truncated"]
    forbidding = [b for b in body["boundaries"] if b["forbids_clean"]]
    assert forbidding and forbidding[0]["gap"] == "diff_truncated"


def test_unknown_gap_is_ignored_not_misreported():
    boundaries = boundaries_from_fact(_fact(gaps=["totally_new_gap"]))
    assert boundaries == []
    assert AnalysisBoundary(kind=BoundaryKind.TRUNCATED).to_dict()["gap"] == ""
