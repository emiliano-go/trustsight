"""Child processes get a minimal environment, never the parent's.

The tokenizer-worker finding was one instance of a general shape: a child
interpreter runs startup code named by an inherited variable.  The loader and
other runtimes have the same shape (``LD_PRELOAD``, ``PERL5LIB``, ...).  This
pins the shared allowlist and the fact that the worker uses it.
"""

from __future__ import annotations

import pytest

from trustsight.subproc import MINIMAL_ENV_KEYS, minimal_env
from trustsight.sandbox import client


@pytest.mark.parametrize("var", [
    "PYTHONPATH", "PYTHONSTARTUP", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "LD_AUDIT", "PERL5LIB", "RUBYOPT", "BASH_ENV", "ENV", "NODE_OPTIONS",
    "GIT_EXTERNAL_DIFF", "GIT_PAGER", "HF_HUB_OFFLINE",
])
def test_startup_and_loader_variables_are_dropped(monkeypatch, var):
    monkeypatch.setenv(var, "/tmp/attacker")
    assert var not in minimal_env()


def test_only_the_allowlist_survives(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    env = minimal_env()
    assert env.get("PATH") == "/usr/bin:/bin"
    assert env.get("LANG") == "C"
    assert set(env) <= set(MINIMAL_ENV_KEYS) | {"PATH"}


def test_the_worker_uses_the_allowlist(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/tmp/attacker")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    env = client._child_env()
    assert "PYTHONPATH" not in env
    assert "LD_PRELOAD" not in env
