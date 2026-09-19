"""Output stream and terminal selection.

Rich is for terminals: a pipe or redirect gets the plain renderer, progress
bars never reach stdout, and diagnostics that ask for stderr land there even
when Rich is installed.
"""

from trustsight.cli import display, review as review_cli


def test_use_rich_follows_the_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_FORCE_RICH", raising=False)
    monkeypatch.setattr(display, "HAS_RICH", True)

    monkeypatch.setattr(display, "_isatty", lambda stream: False)
    assert display.use_rich() is False
    assert display.use_rich_progress() is False

    monkeypatch.setattr(display, "_isatty", lambda stream: True)
    assert display.use_rich() is True
    assert display.use_rich_progress() is True


def test_no_color_disables_and_force_color_wins(monkeypatch):
    monkeypatch.setattr(display, "HAS_RICH", True)
    monkeypatch.setattr(display, "_isatty", lambda stream: True)

    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_FORCE_RICH", raising=False)
    assert display.use_rich() is False

    monkeypatch.setenv("FORCE_COLOR", "1")
    assert display.use_rich() is True


def test_json_discovery_withholds_progress_and_notices(monkeypatch):
    seen = {}

    def fake(*, on_warn, on_download, on_notice, **kwargs):
        seen["on_download"] = on_download
        seen["on_notice"] = on_notice
        return [], 0

    monkeypatch.setattr(review_cli, "_discover_engine", fake)
    review_cli._discover_packages(
        repos=[], include_foreign=False, all_repos_flag=False,
        all_packages=False, _warn=lambda msg: None, json_output=True,
    )
    assert seen["on_download"] is None
    assert seen["on_notice"] is None


def test_colored_stderr_goes_to_stderr(monkeypatch, capsys):
    monkeypatch.setattr(display, "_err_console", None)
    display._print_colored("boom", "red", stderr=True)
    captured = capsys.readouterr()
    assert "boom" in captured.err
    assert captured.out == ""
