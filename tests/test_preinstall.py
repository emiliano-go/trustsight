"""trustsight preinstall: a read-only remote scanner (never installs)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from trustsight.cli import app
from trustsight.cli import preinstall as pre
from trustsight.schema import DiffSummary, PackageFact

runner = CliRunner()


def _fact(package="demo") -> PackageFact:
    return PackageFact(
        package_name=package,
        old_version="",
        new_version="1.0-1",
        diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        score_breakdown=[],
        final_score=0,
        risk="Low",
        coverage_gaps=[],
        changes=[],
    )


@pytest.fixture
def isolated(monkeypatch):
    monkeypatch.setattr(pre, "ensure_default_configs", lambda: None)
    monkeypatch.setattr(pre, "init_db", lambda: None)
    monkeypatch.setattr(pre, "load_config", lambda: {})
    monkeypatch.setattr(pre, "maybe_auto_import_seed", lambda **k: None)
    import trustsight.discovery as discovery
    monkeypatch.setattr(discovery, "get_all_installed", lambda: {})
    monkeypatch.setattr(discovery, "get_aur_package_info",
                        lambda names: {n: {"Name": n} for n in names})
    return monkeypatch


def test_uninstalled_is_accepted_and_uses_whole_recipe(isolated):
    calls = []

    def fake_analyze(package, **kwargs):
        calls.append((package, kwargs))
        return _fact(package)

    isolated.setattr(pre, "analyze_package", fake_analyze)
    result = runner.invoke(app, ["preinstall", "brand-new", "--json"])
    assert result.exit_code == 0, result.output
    assert calls and calls[0][0] == "brand-new"
    assert calls[0][1]["full_recipe"] is True
    assert calls[0][1]["record"] is False
    body = json.loads(result.output)
    assert body["package"] == "brand-new"


def test_installed_package_uses_the_diff_by_default(isolated):
    calls = []

    def fake_analyze(package, **kwargs):
        calls.append(kwargs)
        return _fact(package)

    import trustsight.discovery as discovery
    isolated.setattr(discovery, "get_all_installed",
                     lambda: {"demo": {"Name": "demo"}})
    isolated.setattr(pre, "analyze_package", fake_analyze)
    result = runner.invoke(app, ["preinstall", "demo", "--json"])
    assert result.exit_code == 0, result.output
    assert calls[0]["full_recipe"] is False


def test_missing_from_aur_and_not_installed_exits_2(isolated):
    import trustsight.discovery as discovery
    isolated.setattr(discovery, "get_aur_package_info", lambda names: {})
    result = runner.invoke(app, ["preinstall", "nope"])
    assert result.exit_code == 2


def test_analysis_failure_exits_2(isolated):
    def boom(package, **kwargs):
        raise RuntimeError("clone failed")

    isolated.setattr(pre, "analyze_package", boom)
    result = runner.invoke(app, ["preinstall", "demo"])
    assert result.exit_code == 2


def test_preinstall_is_registered():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "preinstall" in result.output


def test_a_package_name_cannot_inject_terminal_escapes(isolated, monkeypatch):
    """The name is echoed back on the not-found path; it must be inert."""
    import trustsight.discovery as discovery

    monkeypatch.setattr(discovery, "get_aur_package_info", lambda names: {})
    result = runner.invoke(app, ["preinstall", "evil\x1b[31mPWN"])
    assert result.exit_code == 2
    assert "\x1b" not in result.output
