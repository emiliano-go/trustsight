"""Addendum 2 D2: a D-rule's statistical abstention is a first-class,
weight-0 boundary, not silence."""

from trustsight.analysis.pipeline import scan_diff

_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
    " pkgname=demo\n pkgver=1.0\n"
    "+depends=('glibc')\n"
)


def test_an_unseeded_corpus_reports_the_decline(monkeypatch):
    import trustsight.analysis.dependencies as deps

    monkeypatch.setattr(deps, "dependency_table_populated", lambda: False)
    fact = scan_diff(_DIFF, package_name="demo")
    findings = {e.rule_id: e for e in fact.score_breakdown}
    assert "W007" in findings
    entry = findings["W007"]
    assert entry.weight == 0
    assert entry.severity == "INFO"


def test_a_seeded_corpus_is_silent(monkeypatch):
    import trustsight.analysis.dependencies as deps

    monkeypatch.setattr(deps, "dependency_table_populated", lambda: True)
    fact = scan_diff(_DIFF, package_name="demo")
    assert "W007" not in {e.rule_id for e in fact.score_breakdown}


def test_no_added_dependency_means_no_decline(monkeypatch):
    import trustsight.analysis.dependencies as deps

    monkeypatch.setattr(deps, "dependency_table_populated", lambda: False)
    fact = scan_diff(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
        " pkgname=demo\n-pkgver=1.0\n+pkgver=1.1\n",
        package_name="demo",
    )
    assert "W007" not in {e.rule_id for e in fact.score_breakdown}
