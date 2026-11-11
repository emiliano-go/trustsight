"""trustsight hook: install/remove the yay and paru approval hooks."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from trustsight.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """Keep every write inside a fake home so the outside-home guard is not
    accidentally satisfied by the developer's own layout."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    return tmp_path


MARKER_INI = "# trustsight-hook:v1"
MARKER_LUA = "-- trustsight-hook:v1"
PARU_LINE = 'PreBuildCommand = trustsight-gate --base "$PKGBASE" --dir "$PWD"'


def _run(*args):
    return runner.invoke(app, ["hook", *args])


def _paru(tmp_path: Path) -> Path:
    return tmp_path / "paru.conf"


def _yay(tmp_path: Path) -> Path:
    return tmp_path / "init.lua"


def test_paru_creates_the_hook(tmp_path):
    path = _paru(tmp_path)
    result = _run("paru", "--config", str(path))
    assert result.exit_code == 0, result.output
    text = path.read_text()
    assert MARKER_INI in text
    assert PARU_LINE in text
    assert "[bin]" in text


def test_paru_is_idempotent(tmp_path):
    path = _paru(tmp_path)
    _run("paru", "--config", str(path))
    before = path.read_text()
    result = _run("paru", "--config", str(path))
    assert result.exit_code == 0
    assert "already configured" in result.output
    assert path.read_text() == before


def test_paru_preserves_comments_and_other_keys(tmp_path):
    path = _paru(tmp_path)
    path.write_text(
        "# my paru config\n[options]\nSudoLoop = true\n\n[bin]\n"
        "BatchInstall = true\n")
    result = _run("paru", "--config", str(path))
    assert result.exit_code == 0, result.output
    text = path.read_text()
    assert "# my paru config" in text
    assert "SudoLoop = true" in text
    assert "BatchInstall = true" in text
    assert MARKER_INI in text and PARU_LINE in text


def test_paru_refuses_a_conflicting_prebuild_command(tmp_path):
    path = _paru(tmp_path)
    path.write_text("[bin]\nPreBuildCommand = something-else\n")
    result = _run("paru", "--config", str(path))
    assert result.exit_code == 2
    assert "--force" in result.output
    assert path.read_text() == "[bin]\nPreBuildCommand = something-else\n"


def test_paru_force_replaces_and_backs_up(tmp_path):
    path = _paru(tmp_path)
    path.write_text("[bin]\nPreBuildCommand = something-else\n")
    result = _run("paru", "--config", str(path), "--force")
    assert result.exit_code == 0, result.output
    assert PARU_LINE in path.read_text()
    backups = list(tmp_path.glob("paru.conf.bak.*"))
    assert len(backups) == 1
    assert "something-else" in backups[0].read_text()


def test_paru_remove_leaves_the_rest(tmp_path):
    path = _paru(tmp_path)
    path.write_text("[bin]\nBatchInstall = true\n")
    _run("paru", "--config", str(path))
    result = _run("paru", "--config", str(path), "--remove")
    assert result.exit_code == 0
    text = path.read_text()
    assert "BatchInstall = true" in text
    assert PARU_LINE not in text
    assert MARKER_INI not in text


def test_paru_remove_without_a_hook_is_a_no_op(tmp_path):
    path = _paru(tmp_path)
    path.write_text("[bin]\nBatchInstall = true\n")
    result = _run("paru", "--config", str(path), "--remove")
    assert result.exit_code == 0
    assert "no TrustSight hook" in result.output
    assert path.read_text() == "[bin]\nBatchInstall = true\n"


def test_paru_print_and_dry_run_write_nothing(tmp_path):
    path = _paru(tmp_path)
    result = _run("paru", "--config", str(path), "--print")
    assert result.exit_code == 0
    assert PARU_LINE in result.output
    assert not path.exists()
    result = _run("paru", "--config", str(path), "--dry-run")
    assert result.exit_code == 0
    assert "create" in result.output
    assert not path.exists()


def test_paru_refuses_a_symlink(tmp_path):
    real = tmp_path / "real.conf"
    real.write_text("[bin]\n")
    link = tmp_path / "link.conf"
    link.symlink_to(real)
    result = _run("paru", "--config", str(link))
    assert result.exit_code == 2
    assert "symlink" in result.output
    assert real.read_text() == "[bin]\n"


def test_yay_creates_the_hook(tmp_path):
    path = _yay(tmp_path)
    result = _run("yay", "--config", str(path))
    assert result.exit_code == 0, result.output
    text = path.read_text()
    assert MARKER_LUA in text
    assert "AURPreInstall" in text
    assert "trustsight-gate" in text


def test_yay_is_idempotent(tmp_path):
    path = _yay(tmp_path)
    _run("yay", "--config", str(path))
    before = path.read_text()
    result = _run("yay", "--config", str(path))
    assert result.exit_code == 0
    assert "already configured" in result.output
    assert path.read_text() == before


def test_yay_refuses_a_foreign_init_lua(tmp_path):
    path = _yay(tmp_path)
    path.write_text("-- the user's own yay config\n")
    result = _run("yay", "--config", str(path))
    assert result.exit_code == 2
    assert "--force" in result.output
    assert path.read_text() == "-- the user's own yay config\n"


def test_yay_force_overwrites_with_a_backup(tmp_path):
    path = _yay(tmp_path)
    path.write_text("-- the user's own yay config\n")
    result = _run("yay", "--config", str(path), "--force")
    assert result.exit_code == 0, result.output
    assert MARKER_LUA in path.read_text()
    backups = list(tmp_path.glob("init.lua.bak.*"))
    assert len(backups) == 1
    assert "the user's own yay config" in backups[0].read_text()


def test_yay_remove_keeps_a_backup(tmp_path):
    path = _yay(tmp_path)
    _run("yay", "--config", str(path))
    result = _run("yay", "--config", str(path), "--remove")
    assert result.exit_code == 0
    assert not path.exists()
    backups = list(tmp_path.glob("init.lua.bak.*"))
    assert len(backups) == 1
    assert MARKER_LUA in backups[0].read_text()


def test_yay_remove_refuses_a_foreign_file(tmp_path):
    path = _yay(tmp_path)
    path.write_text("-- the user's own config\n")
    result = _run("yay", "--config", str(path), "--remove")
    assert result.exit_code == 2
    assert path.read_text() == "-- the user's own config\n"


def test_yay_print_writes_nothing(tmp_path):
    path = _yay(tmp_path)
    result = _run("yay", "--config", str(path), "--print")
    assert result.exit_code == 0
    assert MARKER_LUA in result.output
    assert not path.exists()


def test_a_target_outside_home_needs_force(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    (tmp_path / "home").mkdir()
    outside = tmp_path / "outside" / "paru.conf"
    result = _run("paru", "--config", str(outside))
    assert result.exit_code == 2
    assert "--force" in result.output
    assert not outside.exists()
    result = _run("paru", "--config", str(outside), "--force")
    assert result.exit_code == 0, result.output
    assert outside.exists()


def test_default_paths_follow_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    result = _run("paru")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "xdg" / "paru" / "paru.conf").is_file()
    result = _run("yay")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "xdg" / "yay" / "init.lua").is_file()


def test_print_cannot_be_combined_with_a_write_flag(tmp_path):
    result = _run("paru", "--config", str(_paru(tmp_path)), "--print", "--force")
    assert result.exit_code == 2
    assert "--print" in result.output
