import shutil
import sys
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    not shutil.which("pacman"),
    reason="pacman not available (non-Arch system)",
)


def test_cli_help():
    with patch.object(sys, "argv", ["trustsight", "--help"]):
        with pytest.raises(SystemExit):
            from trustsight.cli import main
            main()


def test_cli_no_args_runs_help():
    with patch.object(sys, "argv", ["trustsight"]):
        try:
            from trustsight.cli import main
            main()
        except SystemExit:
            pytest.fail("Should not raise SystemExit for no args")


def test_cli_review_help():
    with patch.object(sys, "argv", ["trustsight", "review", "--help"]):
        with pytest.raises(SystemExit):
            from trustsight.cli import main
            main()


def test_cli_inspect_help():
    with patch.object(sys, "argv", ["trustsight", "inspect", "--help"]):
        with pytest.raises(SystemExit):
            from trustsight.cli import main
            main()


def test_cli_history_help():
    with patch.object(sys, "argv", ["trustsight", "history", "--help"]):
        with pytest.raises(SystemExit):
            from trustsight.cli import main
            main()


def test_cli_inspect_no_args():
    with patch.object(sys, "argv", ["trustsight", "inspect"]):
        with pytest.raises(SystemExit):
            from trustsight.cli import main
            main()


def test_cli_history_no_args():
    with patch.object(sys, "argv", ["trustsight", "history"]):
        with pytest.raises(SystemExit):
            from trustsight.cli import main
            main()


def test_cli_review_runs(tmp_path, monkeypatch):
    """Verify review command runs without error (will try to fetch AUR)."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.discovery.discover_packages", return_value=[]):
        with patch.object(sys, "argv", ["trustsight", "review", "--limit", "5"]):
            try:
                from trustsight.cli import main
                main()
            except SystemExit:
                pytest.fail("review should not exit")


# --- Discovery flags ---

def test_cli_review_help_shows_flags(capsys):
    with patch.object(sys, "argv", ["trustsight", "review", "--help"]):
        with pytest.raises(SystemExit):
            from trustsight.cli import main
            main()
    captured = capsys.readouterr()
    assert "--repo" in captured.out
    assert "--foreign" in captured.out
    assert "--all-repos" in captured.out


def test_cli_review_flag_repo(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        with patch.object(sys, "argv",
                          ["trustsight", "review", "--repo", "aur"]):
            from trustsight.cli import main
            main()
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
        with patch.object(sys, "argv",
                          ["trustsight", "review", "--foreign"]):
            from trustsight.cli import main
            main()
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
        with patch.object(sys, "argv",
                          ["trustsight", "review", "--all-repos"]):
            from trustsight.cli import main
            main()
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
        with patch.object(
            sys, "argv",
            ["trustsight", "review", "--repo", "aur", "--repo", "testing"],
        ):
            from trustsight.cli import main
            main()
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
        with patch.object(
            sys, "argv",
            ["trustsight", "review", "--repo", "aur", "--foreign"],
        ):
            from trustsight.cli import main
            main()
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
        with patch.object(
            sys, "argv",
            ["trustsight", "review", "--all-repos", "--foreign"],
        ):
            from trustsight.cli import main
            main()
        kwargs = mock_disc.call_args[1]
        assert kwargs["all_repos"] is True
        assert kwargs["include_foreign"] is True


# --- Config-driven discovery (no CLI flags) ---

def _make_config_with_discovery(tmp_path, monkeypatch, **discovery_overrides):
    """Write a config.toml with [discovery] section and patch paths."""
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
        with patch.object(sys, "argv", ["trustsight", "review"]):
            from trustsight.cli import main
            main()
        kwargs = mock_disc.call_args[1]
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_config_cli_overrides(tmp_path, monkeypatch):
    """CLI flags take precedence over config defaults."""
    _make_config_with_discovery(
        tmp_path, monkeypatch,
        default_repos='["aur"]',
        include_foreign=True,
    )

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        with patch.object(sys, "argv",
                          ["trustsight", "review", "--repo", "cli-repo"]):
            from trustsight.cli import main
            main()
        kwargs = mock_disc.call_args[1]
        # CLI --repo overrides config default_repos
        assert kwargs["repos"] == ["cli-repo"]
        # --foreign not passed, so include_foreign is False (not config's True)
        assert kwargs["include_foreign"] is False


def test_cli_review_config_no_flags_fallback_foreign(tmp_path, monkeypatch):
    """When config has no discovery settings, default to foreign-only."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.discover_packages") as mock_disc:
        mock_disc.return_value = []
        with patch.object(sys, "argv", ["trustsight", "review"]):
            from trustsight.cli import main
            main()
        kwargs = mock_disc.call_args[1]
        # No [discovery] in default config, so fallback to include_foreign=True
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos"] is False


def test_cli_history_no_history(tmp_path, monkeypatch, capsys):
    """History for nonexistent package prints message, no error."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch.object(sys, "argv", ["trustsight", "history", "nonexistentpkg"]):
        from trustsight.cli import main
        main()
    captured = capsys.readouterr()
    assert "not found" in captured.out


def test_cli_inspect_calls_analyze(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    import importlib
    import trustsight.cli
    importlib.reload(trustsight.cli)

    with patch("trustsight.cli.analyze_package") as mock_analyze:
        from trustsight.schema import PackageFact, DiffSummary
        mock_analyze.return_value = PackageFact(
            package_name="testpkg",
            new_version="1.1",
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        )
        with patch.object(sys, "argv", ["trustsight", "inspect", "testpkg"]):
            try:
                trustsight.cli.main()
            except SystemExit:
                pass
        mock_analyze.assert_called_once_with("testpkg")
