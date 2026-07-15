import sys
from unittest.mock import patch

import pytest




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

    with patch("trustsight.analysis.discover_updates", return_value=[]):
        with patch.object(sys, "argv", ["trustsight", "review", "--limit", "5"]):
            try:
                from trustsight.cli import main
                main()
            except SystemExit:
                pytest.fail("review should not exit")


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
