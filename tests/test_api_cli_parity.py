"""Parity checks for shared CLI and API evaluation semantics."""

from trustsight.api import _report_from_fact, _report_from_result
from trustsight.reporting import evaluate_fact
from trustsight.schema import DiffSummary, PackageFact, ScoreEntry


def _fact() -> PackageFact:
    return PackageFact(
        package_name="parity",
        old_version="1.0",
        new_version="1.1",
        diff_summary=DiffSummary(
            files_changed=["PKGBUILD"],
            file_changes=[{"path": "PKGBUILD", "status": "modified"}],
        ),
        score_breakdown=[
            ScoreEntry(
                rule_id="R001",
                severity="CRITICAL",
                weight=40,
                reason="curl piped to bash",
                file="PKGBUILD",
                line=4,
            ),
        ],
        final_score=40,
        risk="Critical",
        coverage_gaps=["line_truncated"],
        changes=["PKGBUILD modified"],
    )


def test_api_and_shared_review_values_match_for_the_same_fact():
    fact = _fact()
    evaluated = evaluate_fact(fact)
    report = _report_from_fact(fact)

    assert report.score == evaluated["score"]
    assert report.risk == evaluated["risk"]
    assert report.risk_label == evaluated["risk_label"]
    assert report.verdict == evaluated["verdict"]
    assert report.coverage_gaps == tuple(evaluated["coverage_gaps"])
    assert [finding.rule_id for finding in report.findings] == ["R001"]
    assert report.config_fingerprint == evaluated["config_fingerprint"]


def test_api_review_row_adapter_preserves_shared_semantic_fields():
    fact = _fact()
    evaluated = evaluate_fact(fact)
    row = dict(evaluated)
    row.pop("raw")
    row.pop("fact")
    row["package"] = row.pop("package")
    report = _report_from_result(row)

    assert report.score == evaluated["score"]
    assert report.risk == evaluated["risk"]
    assert report.risk_label == evaluated["risk_label"]
    assert report.coverage_gaps == tuple(evaluated["coverage_gaps"])
    assert report.findings[0].rule_id == "R001"
