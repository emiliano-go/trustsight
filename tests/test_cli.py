import shutil
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from trustsight.cli import app

pytestmark = pytest.mark.skipif(
    not shutil.which("pacman"),
    reason="pacman not available (non-Arch system)",
)


def test_cli_help():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0


def test_cli_no_args_runs_help():
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 2  # typer shows help and exits with code 2


def test_cli_review_help():
    result = CliRunner().invoke(app, ["review", "--help"])
    assert result.exit_code == 0


def test_cli_inspect_help():
    result = CliRunner().invoke(app, ["inspect", "--help"])
    assert result.exit_code == 0


def test_cli_history_help():
    result = CliRunner().invoke(app, ["history", "--help"])
    assert result.exit_code == 0


def test_cli_inspect_no_args():
    result = CliRunner().invoke(app, ["inspect"])
    assert result.exit_code != 0


def test_cli_history_no_args():
    result = CliRunner().invoke(app, ["history"])
    assert result.exit_code != 0


def test_cli_review_runs(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.discovery.discover_packages", return_value=[]):
        result = CliRunner().invoke(app, ["review", "--limit", "5"])
        assert result.exit_code == 0


# --- Discovery flags ---

def test_cli_review_help_shows_flags():
    result = CliRunner().invoke(app, ["review", "--help"])
    assert "--repo" in result.stdout
    assert "--foreign" in result.stdout
    assert "--all-repos" in result.stdout


def test_cli_review_flag_repo(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--repo", "aur"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        kwargs = mock_disc.call_args[1]
        assert kwargs == {
            "repos": ["aur"],
            "include_foreign": False,
            "all_repos": False,
            "_warn_func": mock_disc.call_args[1]["_warn_func"],
        }


def test_cli_review_flag_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--foreign"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        kwargs = mock_disc.call_args[1]
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos"] is False


def test_cli_review_flag_all_repos(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--all-repos"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        kwargs = mock_disc.call_args[1]
        assert kwargs["all_repos"] is True
        assert kwargs["repos"] == []
        assert kwargs["include_foreign"] is False


def test_cli_review_flag_repo_twice(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--repo", "aur", "--repo", "testing"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["aur", "testing"]


def test_cli_review_flag_repo_plus_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--repo", "aur", "--foreign"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_flag_all_repos_plus_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--all-repos", "--foreign"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["all_repos"] is True
        assert kwargs["include_foreign"] is True


# --- Config-driven discovery (no CLI flags) ---

def _make_config_with_discovery(tmp_path, monkeypatch, **discovery_overrides):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    cfg_dir = tmp_path / ".config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = cfg_dir / "config.toml"

    from trustsight.config import DEFAULT_CONFIG
    if cfg_path.exists():
        cfg_path.unlink()
    text = DEFAULT_CONFIG
    import re
    text = re.sub(r"\n\[discovery\].*?(?=\n\[|\Z)", "", text, flags=re.DOTALL)
    text = text.rstrip() + "\n"
    discovery_lines = [
        "[discovery]",
        f'default_repos = {discovery_overrides.get("default_repos", "[]")}',
        f'include_foreign = {str(discovery_overrides.get("include_foreign", False)).lower()}',
        f'all_repos = {str(discovery_overrides.get("all_repos", False)).lower()}',
    ]
    text += "\n".join(discovery_lines) + "\n"
    cfg_path.write_text(text)


def test_cli_review_config_default_repos(tmp_path, monkeypatch):
    _make_config_with_discovery(
        tmp_path, monkeypatch,
        default_repos='["aur"]',
        include_foreign=True,
    )

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_config_cli_overrides(tmp_path, monkeypatch):
    _make_config_with_discovery(
        tmp_path, monkeypatch,
        default_repos='["aur"]',
        include_foreign=True,
    )

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review", "--repo", "cli-repo"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["cli-repo"]
        assert kwargs["include_foreign"] is False


def test_cli_review_config_no_flags_fallback_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        result = CliRunner().invoke(app, ["review"])
        assert result.exit_code == 0, result.stdout
        kwargs = mock_disc.call_args[1]
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos"] is False


def test_cli_history_no_history(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    result = CliRunner().invoke(app, ["history", "nonexistentpkg"])
    assert "not found" in result.stdout


def test_cli_inspect_calls_analyze(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.analyze_package") as mock_analyze:
        from trustsight.schema import PackageFact, DiffSummary
        mock_analyze.return_value = PackageFact(
            package_name="testpkg",
            new_version="1.1",
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        )
        result = CliRunner().invoke(app, ["inspect", "testpkg"])
        assert result.exit_code == 0, result.stdout
        mock_analyze.assert_called_once_with("testpkg")
