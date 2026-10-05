"""Spec §10: explain mode.

The explanation re-reads the document and re-runs the rule's pattern, so
the lines it shows are the lines the original run attributed (the same
line map both times).  A rule with an external read names that input.
"""

from typer.testing import CliRunner

from trustsight.api import Report
from trustsight.cli.app import app
from trustsight.cli.explain import build_explanation
from trustsight.schema import NoveltyContext, PackageFact

_DIFF = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,4 +1,5 @@
 pkgname=demo
 pkgver=1.0
+source=('https://evil.invalid/x.tar.gz')
 sha256sums=('aaaa')
"""

_FINDING = {
    "rule_id": "C003",
    "severity": "HIGH",
    "file": "PKGBUILD",
    "line": 3,
    "description": "source URL changed",
    "template": "source {url}",
    "evidence": {"url": "https://evil.invalid/x.tar.gz"},
}

_DEFINITION = {
    "id": "C003",
    "severity": "HIGH",
    "pattern": r"https://evil\.invalid",
    "match_target": "resolved",
    "scope": "PKGBUILD",
    "description": "Source URL changed",
}


def test_the_explanation_shows_the_cited_line_and_the_document_facts():
    fact = PackageFact(
        package_name="demo",
        change={"sources": {"gained": ["https://evil.invalid/x.tar.gz"]}},
    )
    explanation = build_explanation(fact, _FINDING, _DEFINITION, _DIFF)
    assert explanation["rule_id"] == "C003"
    assert explanation["rule"]["pattern"] == _DEFINITION["pattern"]
    raws = [line["raw"] for line in explanation["lines"]]
    assert any("evil.invalid" in raw for raw in raws)
    assert explanation["pattern_matches"], "the rule was not re-run"
    assert explanation["facts"]["change"]["sources"]["gained"] == [
        "https://evil.invalid/x.tar.gz"
    ]
    assert explanation["external_input"] is None


def test_an_external_read_is_named_with_its_cached_value():
    fact = PackageFact(
        package_name="demo",
        novelty_context=NoveltyContext(observation_count=7),
    )
    finding = dict(_FINDING, rule_id="D001")
    explanation = build_explanation(fact, finding, None, _DIFF)
    assert explanation["external_input"]
    assert explanation["external_value"]["observation_count"] == 7


def test_explain_cli_errors_when_the_rule_did_not_fire(monkeypatch):
    fact = PackageFact(package_name="demo")
    monkeypatch.setattr(
        "trustsight.cli.explain.analyze_package", lambda *a, **k: fact)
    result = CliRunner().invoke(app, ["explain", "demo", "C003"])
    assert result.exit_code == 2
    assert "did not fire" in result.output


def test_explain_cli_renders_from_the_finding_even_without_a_diff(monkeypatch):
    fact = PackageFact(
        package_name="demo",
        change={},
        score_breakdown=[],
    )
    monkeypatch.setattr(
        "trustsight.cli.explain.analyze_package", lambda *a, **k: fact)
    monkeypatch.setattr(
        "trustsight.cli.explain.load_rules", lambda: [_DEFINITION])

    from trustsight.schema import ScoreEntry
    fact.score_breakdown = [ScoreEntry(
        rule_id="C003", severity="HIGH", weight=25,
        reason="source URL changed", template="source {url}",
        evidence={"url": "https://evil.invalid/x.tar.gz"},
        file="PKGBUILD", line=3,
    )]
    monkeypatch.setattr(
        "trustsight.fetcher.clone_or_fetch",
        lambda package: (_ for _ in ()).throw(RuntimeError("no network")),
    )
    result = CliRunner().invoke(app, ["explain", "demo", "C003"])
    assert result.exit_code == 0, result.output
    assert "C003" in result.output
    assert "cited: PKGBUILD line 3" in result.output


def test_report_to_sarif_is_reachable_on_the_api():
    report = Report(
        package="demo",
        findings=(),
        change={"hosts_gained": ["example.com"]},
    )
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "TrustSight"
