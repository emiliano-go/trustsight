"""Shell completion of package-name arguments."""

import pytest
import typer

from trustsight.cli import app, completion


@pytest.fixture
def sources(monkeypatch):
    monkeypatch.setattr(
        "trustsight.discovery.get_installed_foreign",
        lambda: [("example-git", "1-1"), ("other-bin", "1-1")],
    )
    monkeypatch.setattr(
        "trustsight.db.get_all_packages",
        lambda: [{"name": "example-git"}, {"name": "example-drivers"}],
    )


def test_installed_packages_merge_pacman_and_database(sources):
    assert completion.installed_packages("example") == ["example-drivers", "example-git"]
    assert completion.installed_packages("zzz") == []


def test_tracked_packages_come_from_the_database_only(sources):
    assert completion.tracked_packages("oth") == []
    assert completion.tracked_packages("example-d") == ["example-drivers"]


def test_failing_sources_yield_no_candidates(monkeypatch):
    def fail():
        raise RuntimeError("unavailable")

    monkeypatch.setattr("trustsight.discovery.get_installed_foreign", fail)
    monkeypatch.setattr("trustsight.db.get_all_packages", fail)
    assert completion.installed_packages("k") == []


def _complete(path, param_name, incomplete):
    ctx = typer.main.get_command(app).make_context("trustsight", [], resilient_parsing=True)
    command = ctx.command
    for name in path:
        command = command.get_command(ctx, name)
        ctx = command.make_context(name, [], parent=ctx, resilient_parsing=True)
    param = next(p for p in command.params if p.name == param_name)
    return [item.value for item in param.shell_complete(ctx, incomplete)]


@pytest.mark.parametrize(
    ("path", "param_name", "incomplete", "expected"),
    [
        (["inspect"], "package", "example-g", ["example-git"]),
        (["history"], "package", "example-d", ["example-drivers"]),
        (["forget"], "packages", "example-d", ["example-drivers"]),
        (["override", "wizard"], "package", "oth", ["other-bin"]),
        (["override", "add"], "package", "oth", ["other-bin"]),
        (["override", "rm"], "package", "oth", ["other-bin"]),
    ],
)
def test_commands_complete_package_names(sources, path, param_name, incomplete, expected):
    assert _complete(path, param_name, incomplete) == expected
