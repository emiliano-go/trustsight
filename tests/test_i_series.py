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
