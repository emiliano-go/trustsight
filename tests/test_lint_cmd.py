"""Spec §8 v2: ``trustsight lint`` - pre-submission hygiene, no verdict."""

import json

from typer.testing import CliRunner

from trustsight.cli.app import app
from trustsight.cli.lint import lint_report

_PKGBUILD = """\
pkgname=demo
pkgver=1.0
depends=('glibc' 'glibc')
source=($(curl -fsSL https://example.invalid/x))
build() {
  make
}
package() {
  curl -o "$pkgdir/x" https://example.invalid/x
  install -Dm644 y "$pkgdir/y"
}
"""

_INSTALL = """\
post_install() {
  bash -c 'echo pwned'
}
"""


def test_lint_reports_arrays_functions_unresolved_and_rules():
    report = lint_report(_PKGBUILD, "PKGBUILD")
    assert report["score"] is None
    assert report["arrays"]["depends"]["duplicates"] == ["glibc"]
    assert "package" in report["functions"]
    assert any(row["name"] == "source"
               for row in report["unresolved_assignments"])
    rule_ids = {f["rule_id"] for f in report["rules"]}
    assert "C015" in rule_ids


def test_lint_an_install_file_runs_the_hook_rules():
    report = lint_report(_INSTALL, "demo.install")
    assert "C016" in {f["rule_id"] for f in report["rules"]}


def test_lint_cli_is_pipe_safe_and_scores_nothing(tmp_path):
    target = tmp_path / "PKGBUILD"
    target.write_text(_PKGBUILD, encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(app, ["lint", str(target), "--json"])
    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["score"] is None
    assert body["file"] == "PKGBUILD"

    plain = runner.invoke(app, ["lint", str(target)])
    assert plain.exit_code == 0
    assert "score: none" in plain.stdout


def test_lint_cli_refuses_a_missing_file(tmp_path):
    result = CliRunner().invoke(app, ["lint", str(tmp_path / "nope")])
    assert result.exit_code == 2
    result_json = CliRunner().invoke(
        app, ["lint", str(tmp_path / "nope"), "--json"])
    assert result_json.exit_code == 2
    assert "error" in json.loads(result_json.stdout)
