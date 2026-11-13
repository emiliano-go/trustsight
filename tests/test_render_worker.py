"""Rich rendering is confined to the render sandbox."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from trustsight.sandbox import render_client, render_worker

ROOT = Path(__file__).resolve().parents[1] / "src" / "trustsight"


def test_worker_applies_the_read_role_sandbox():
    source = inspect.getsource(render_worker.main)
    assert '_linux_sandbox.apply("read"' in source
    assert "core_sandbox_failures(" in source


def test_worker_imports_no_database_cli_or_network_module():
    tree = ast.parse(Path(render_worker.__file__).read_text())
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append(node.module or "")
    forbidden = ("trustsight.cli", "trustsight.db", "trustsight.fetcher", "socket")
    assert not [
        name for name in names
        if any(name == item or name.startswith(item + ".") for item in forbidden)
    ]


def test_cli_modules_do_not_import_rich():
    offenders = []
    for path in (ROOT / "cli").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(a.name == "rich" or a.name.startswith("rich.")
                       for a in node.names):
                    offenders.append(path.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "rich" or module.startswith("rich."):
                    offenders.append(path.name)
    assert not offenders


def test_render_output_is_inert_and_ordered():
    out = render_client.render("list_table", {"rows": [{
        "name": "p\x1b[31mRED\x1b[0m[/]",
        "version": "1.0", "maintainer": "m", "last_checked": "2026-01-01",
        "score": 40, "risk": "Medium",
    }]})
    assert "\x1b" not in out
    assert "RED" in out


def test_a_finished_progress_bar_ends_with_a_newline(monkeypatch):
    import io

    from trustsight.render import progress

    stream = io.StringIO()

    class FakeProgress:
        transient = False

        def stop(self):
            pass

    monkeypatch.setitem(progress._TASKS, "download", (FakeProgress(), 1))
    monkeypatch.setattr(progress, "_stream", lambda: stream)
    progress.stop(id="download")

    assert stream.getvalue() == "\n"


def test_unknown_op_is_a_named_refusal():
    with pytest.raises(render_client.RenderUnavailable, match="unknown render op"):
        render_client.render("no_such_op", {})
