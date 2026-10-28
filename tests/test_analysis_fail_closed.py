"""Parse failures in analysis must leave a coverage gap, not a silent clean run."""

from trustsight.analysis import dependencies
from trustsight.analysis.refusals import refusal_findings
from trustsight.analysis.structural import _hooks
from trustsight.coverage import begin_stage_tracking, stage_failures


def _boom(*args, **kwargs):
    raise RuntimeError("forced parse failure")


def test_partial_install_files_marks_a_degraded_stage(monkeypatch):
    begin_stage_tracking()
    monkeypatch.setattr(_hooks, "parse_diff_lines", _boom)
    assert _hooks.partial_install_files("--- a/PKGBUILD\n+++ b/PKGBUILD\n") == []
    assert "install-partial-check" in stage_failures()


def test_refusal_parse_failure_marks_a_degraded_stage(monkeypatch):
    begin_stage_tracking()
    monkeypatch.setattr("trustsight.diffdoc.parse_diff", _boom)
    refusal_findings("--- a/PKGBUILD\n+++ b/PKGBUILD\n", {}, lambda *a, **k: None)
    assert "refusal-parse" in stage_failures()


def test_name_shadow_parse_failure_marks_a_degraded_stage(monkeypatch):
    begin_stage_tracking()
    monkeypatch.setattr("trustsight.recipedoc.parse_recipe", _boom)
    assert dependencies.name_shadow_findings("pkgver=1\n", "demo") == []
    assert "name-shadow-parse" in stage_failures()


def test_scriptlet_parse_failure_marks_a_degraded_stage(monkeypatch):
    from trustsight.analysis import edges as edges_module

    begin_stage_tracking()
    monkeypatch.setattr("trustsight.recipedoc.parse_recipe", _boom)
    name = "demo.install"
    assert edges_module.edge_scriptlet_top_level_execution(name, b"post_install() { :; }\n") is None
    assert "scriptlet-parse" in stage_failures()
