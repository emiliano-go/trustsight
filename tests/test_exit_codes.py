"""The OS exit-code contract, per docs/reference/exit-codes.md.

0 means the command ran and produced a result; 2 means it could not
run or could not complete. A verdict (FLAGGED/INCONCLUSIVE) never
changes the exit code. These tests pin the entry boundary: uncaught
failures become 2, deliberate exits pass through unchanged.
"""

from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from trustsight.cli import app
from trustsight.cli.app import main

runner = CliRunner()


def test_an_uncaught_failure_exits_2_with_a_message(capsys):
    def _explode() -> None:
        raise RuntimeError("boom")

    with patch("trustsight.cli.app.app", _explode):
        with pytest.raises(typer.Exit) as excinfo:
            main()
    assert excinfo.value.exit_code == 2
    assert "boom" in capsys.readouterr().err


def test_a_deliberate_exit_code_passes_through_unchanged():
    def _exit_3():
        raise typer.Exit(code=3)

    with patch("trustsight.cli.app.app", _exit_3):
        with pytest.raises(typer.Exit) as excinfo:
            main()
    assert excinfo.value.exit_code == 3


def test_an_interrupt_exits_130_with_a_short_message(capsys):
    def _interrupt() -> None:
        raise KeyboardInterrupt

    with patch("trustsight.cli.app.app", _interrupt):
        with pytest.raises(typer.Exit) as excinfo:
            main()
    assert excinfo.value.exit_code == 130
    assert capsys.readouterr().err == "Interrupted.\n"


def test_db_check_json_exits_nonzero_for_a_corrupt_database(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    (tmp_path / "trustsight.db").write_text("not a sqlite database")

    result = runner.invoke(app, ["db", "check", "--json"])

    assert result.exit_code == 2
    assert '"status": "corrupt"' in result.output


def test_inspect_not_found_is_an_error_for_scripting(tmp_path, monkeypatch):
    """`inspect` on a package that exists nowhere exits 2, not 1: nothing
    useful was produced, and the documented contract has no exit 1."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    monkeypatch.setattr(
        "trustsight.discovery.get_aur_package_info",
        lambda *a, **k: {},
    )
    monkeypatch.setattr("trustsight.db.get_package", lambda pkg: None)
    monkeypatch.setattr(
        "trustsight.cli.inspect.maybe_auto_import_seed", lambda **kw: None
    )

    result = runner.invoke(app, ["inspect", "pkg-that-nowhere-exists"])
    assert result.exit_code == 2


def test_review_json_first_metadata_bootstrap_is_an_empty_success(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    monkeypatch.setattr(
        "trustsight.cli.review._discover_packages", lambda **kwargs: (None, 0)
    )

    result = runner.invoke(app, ["review", "--json"])

    assert result.exit_code == 0
    assert result.stdout == "[]\n"
