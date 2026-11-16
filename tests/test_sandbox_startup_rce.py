"""The tokenizer worker must not run attacker code at interpreter startup.

A finding reported that the worker was launched with ``-s`` while inheriting
the parent's ``PYTHONPATH``.  ``-s`` only drops the user site directory; it
does not ignore ``PYTHONPATH``, and ``site`` imports ``sitecustomize`` from
``sys.path`` during startup.  So a writable directory on the inherited
``PYTHONPATH`` let an attacker drop a ``sitecustomize.py`` that ran before the
worker applied its resource limits or its best-effort network drop.

These tests pin the fix: the worker is launched isolated (``-I``) with a
minimal environment, and the poisoned startup file does not run.  The control
proves the poison *would* run under the old launch, so the test cannot pass
because the poison was inert.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from trustsight.sandbox import client


def _poison(directory: Path, sentinel: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "sitecustomize.py").write_text(
        "import pathlib\n"
        f"pathlib.Path({str(sentinel)!r}).write_text('pwned')\n"
    )


def test_the_old_launch_would_run_the_poison(tmp_path):
    """Control: ``-s`` plus PYTHONPATH imports sitecustomize.  If this stops
    being true the regression test below is vacuous."""
    guard = tmp_path / "guard"
    sentinel = tmp_path / "sentinel"
    _poison(guard, sentinel)
    subprocess.run(
        [sys.executable, "-s", "-c", "pass"],
        env={"PATH": "/usr/bin", "PYTHONPATH": str(guard)},
        check=False,
    )
    assert sentinel.exists()


def test_the_worker_ignores_an_inherited_pythonpath(tmp_path, monkeypatch):
    guard = tmp_path / "guard"
    sentinel = tmp_path / "sentinel"
    _poison(guard, sentinel)
    monkeypatch.setenv("PYTHONPATH", str(guard))

    # Force fresh workers so the poisoned environment is the one they see.
    client.reset_after_fork()

    from trustsight import tokenizer

    assert tokenizer.split_lines("a\nb") == ["a", "b"]
    assert not sentinel.exists(), "the worker executed a PYTHONPATH sitecustomize"


def test_the_worker_environment_carries_no_import_path():
    env = client._child_env()
    assert "PYTHONPATH" not in env
    assert not any(key.startswith("PYTHON") for key in env)


def test_the_worker_launch_is_isolated():
    args = client._launch_args()
    assert "-I" in args
    assert "-B" in args
    assert "-s" not in args
    # It still finds the package, through the explicit trusted root.
    bootstrap = args[-1]
    assert "sys.path.insert" in bootstrap
    assert "expand_worker" in bootstrap
