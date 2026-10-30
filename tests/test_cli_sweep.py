"""CLI surface regression: every registered leaf must render help.

The 2026-10-30 CLI sweep walked all 45 leaves with every option and every
pair.  The parts that belong in the regular suite are cheap and
deterministic: the tree still exposes every leaf, every leaf answers
``--help`` without a traceback, and the console entry point is the wrapper
that turns ``typer.Exit`` into a process status.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from typer.main import get_command
from typer.testing import CliRunner

from trustsight.cli.app import app

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def _leaves() -> list[list[str]]:
    root = get_command(app)
    out: list[list[str]] = []

    def walk(command, path: list[str]) -> None:
        subs = getattr(command, "commands", None) or {}
        if not subs:
            out.append(path)
            return
        for name, sub in sorted(subs.items()):
            walk(sub, path + [name])

    walk(root, [])
    return out


def test_the_cli_tree_has_every_leaf():
    leaves = _leaves()
    assert len(leaves) >= 45
    # A representative leaf from each group, so a dropped registration is
    # visible even when the total count happens to stay the same.
    flat = {" ".join(path) for path in leaves}
    for expected in (
        "review", "inspect", "report", "lint", "config set", "override add",
        "db check", "baseline build", "full-aur health", "corpus pivot",
        "ioc list", "watchlist update", "seed info",
    ):
        assert expected in flat


def test_every_leaf_renders_help():
    failures = []
    for path in _leaves():
        result = runner.invoke(app, [*path, "--help"])
        if result.exit_code != 0 or "Usage" not in result.output:
            failures.append((" ".join(path), result.exit_code))
    assert failures == []


def test_console_entry_point_is_the_exit_wrapper():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["trustsight"] == "trustsight.cli:entrypoint"
