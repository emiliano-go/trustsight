"""Addendum 5 §6.4: the indicator tier is promoted from ioc_matches."""

from trustsight.reporting import REPORT_KEYS, evaluate_fact, report_body
from trustsight.schema import PackageFact


def test_indicators_is_in_the_report_surface():
    assert "indicators" in REPORT_KEYS


def test_indicators_mirrors_ioc_matches_in_the_body():
    fact = PackageFact(package_name="demo")
    body = report_body(evaluate_fact(fact))
    assert "indicators" in body
    assert body["indicators"] == body["ioc_matches"]


def test_indicators_carry_the_campaign_tag():
    """Addendum 5 §6.4: campaign-tagged signed indicators surface as-is."""
    from trustsight.ioc_baseline import IocMatch
    from trustsight.reporting import evaluate_fact, report_body
    from trustsight.schema import PackageFact

    fact = PackageFact(
        package_name="demo",
        ioc_matches=[IocMatch(
            type="domain", value="evil.example", source="curator",
            confidence="confirmed", campaign="atomic-arch-2026-06",
            surface="source", line=3)],
    )
    body = report_body(evaluate_fact(fact))
    assert body["indicators"][0]["campaign"] == "atomic-arch-2026-06"
