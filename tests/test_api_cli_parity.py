"""Parity checks for shared CLI and API evaluation semantics."""

from trustsight.api import ReviewResult, _report_from_fact, _report_from_result
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


def test_every_json_surface_emits_the_same_body():
    """B11: the surfaces differ in form, never in information."""
    from trustsight.reporting import REPORT_KEYS, report_body

    fact = _fact()
    evaluated = evaluate_fact(fact)

    cli = report_body(evaluated)
    api = _report_from_fact(fact).to_dict()

    assert set(cli) == set(api)
    assert cli == api
    assert set(REPORT_KEYS) == set(api)


def test_review_result_uses_the_cli_json_list_shape():
    report = _report_from_fact(_fact())
    assert ReviewResult(reports=(report,)).to_dict() == [report.to_dict()]
    assert ReviewResult(reports=(report,)).to_dict(
        include_score=True, verbose=True,
    ) == [report.to_dict(include_score=True, verbose=True)]


def test_the_score_is_withheld_until_it_is_asked_for():
    """The default body is evidence; the number is available on request."""
    from trustsight.reporting import SCORE_KEYS, report_body

    fact = _fact()
    evaluated = evaluate_fact(fact)
    report = _report_from_fact(fact)

    for body in (report_body(evaluated), report.to_dict()):
        for key in SCORE_KEYS:
            assert key not in body
        # Withholding the number withholds nothing else.
        assert body["findings"]
        assert body["coverage_gaps"] == ["line_truncated"]
        assert body["verdict"]

    for body in (report_body(evaluated, include_score=True),
                 report.to_dict(include_score=True)):
        assert body["score"] == 40
        assert body["risk"] == "Critical"
        assert body["risk_label"]


def test_a_default_finding_carries_no_weight():
    """A weight is score arithmetic and travels with the breakdown."""
    body = _report_from_fact(_fact()).to_dict()
    assert body["findings"][0]["rule_id"] == "R001"
    assert "weight" not in body["findings"][0]
    assert "severity" in body["findings"][0]

    verbose = _report_from_fact(_fact()).to_dict(verbose=True)
    assert verbose["score_breakdown"][0]["weight"] == 40


def test_the_evidence_a_run_produced_reaches_the_body():
    """Never skipping info: findings and suppressions both travel."""
    body = _report_from_fact(_fact()).to_dict()
    assert [f["rule_id"] for f in body["findings"]] == ["R001"]
    assert body["changes"] == ["PKGBUILD modified"]
    assert body["file_changes"] == [{"path": "PKGBUILD", "status": "modified"}]


def test_the_raw_fact_is_still_reachable_under_its_own_name():
    """`to_dict` is the report; `raw` is the stored record."""
    report = _report_from_fact(_fact())
    assert report.raw["package_name"] == "parity"
    assert report.raw["final_score"] == 40
    assert "package_name" not in report.to_dict()
