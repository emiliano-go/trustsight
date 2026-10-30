"""Negative fixtures for the structural security gates.

A gate that only passes on the current tree is not proven to catch the change
that reopens its invariant.  These tests point each gate at a tiny synthetic
module that is exactly the bypass shape and assert the gate fails.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from gates import _input_bounds as g  # noqa: E402


def _run(monkeypatch, tmp_path, source: str, filename: str = "evil.py"):
    (tmp_path / filename).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / filename).write_text(source, encoding="utf-8")
    monkeypatch.setattr(g, "SRC", tmp_path)
    monkeypatch.setattr(g, "_python_files", lambda: [tmp_path / filename])
    monkeypatch.setattr(g, "_rel", lambda p: p.relative_to(tmp_path).as_posix())


def test_network_gate_rejects_an_unlisted_import(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, "import requests\n")
    assert not g.gate_network_is_confined().passed


def test_network_gate_rejects_from_urllib_import_request(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, "from urllib import request\n")
    assert not g.gate_network_is_confined().passed


def test_network_gate_accepts_a_keyed_fetch_module(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path,
         "from urllib.request import urlopen\nurlopen('https://aur.archlinux.org', timeout=1)\n",
         "release.py")
    assert g.gate_network_is_confined().passed


def test_host_gate_rejects_a_renamed_endpoint(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, 'AUR_ENDPOINT = "https://evil.example/x"\n')
    assert not g.gate_single_network_host().passed


def test_host_gate_rejects_a_host_in_an_f_string(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, 'BASE = f"https://evil.example/{name}/x"\n')
    assert not g.gate_single_network_host().passed


def test_child_process_gate_rejects_an_aliased_run(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path,
         "from subprocess import run\nrun(['echo', 'x'])\n")
    assert not g.gate_every_child_process_gets_an_explicit_environment().passed


def test_child_process_gate_rejects_an_exec_family_call(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, "import os\nos.execv('/bin/sh', ['sh'])\n")
    assert not g.gate_every_child_process_gets_an_explicit_environment().passed


def test_interpreter_gate_rejects_exec_family(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path, "from os import execv\nexecv('/bin/sh', ['sh'])\n")
    assert not g.gate_no_interpreter_calls().passed


def test_child_process_gate_accepts_explicit_env(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path,
         "import subprocess\nsubprocess.run(['echo'], env={})\n")
    assert g.gate_every_child_process_gets_an_explicit_environment().passed


def test_sql_gate_rejects_an_unreviewed_identifier(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path,
         "def f(conn, bad):\n    conn.execute(f'DELETE FROM {bad}')\n")
    assert not g.gate_sql_is_parameterised().passed


def test_sql_gate_accepts_the_reviewed_identifier_list(monkeypatch, tmp_path):
    _run(monkeypatch, tmp_path,
         "def f(conn, table):\n    conn.execute(f'DELETE FROM {table}')\n")
    assert g.gate_sql_is_parameterised().passed


def test_the_libgit2_gate_checks_the_declared_floor_too(tmp_path, monkeypatch):
    """A fixed runtime wheel does not help a fresh install from a low floor.

    The gate used to read only ``pygit2.LIBGIT2_VERSION``.  Lowering
    ``pyproject.toml``/PKGBUILD to the affected 1.9.6 bundle then passed on
    the maintainer's machine while every new install resolved it.
    """
    from scripts.gates import _layers

    (tmp_path / "packaging" / "aur").mkdir(parents=True)
    (tmp_path / "packaging" / "local").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        'dependencies = ["pygit2>=1.20.0"]\n')
    (tmp_path / "packaging/aur/PKGBUILD").write_text(
        "depends=('python-pygit2>=1.20.0')\n")
    (tmp_path / "packaging/local/PKGBUILD").write_text(
        "depends=('python-pygit2')\n")
    (tmp_path / "packaging/aur/.SRCINFO").write_text(
        "depends = python-pygit2>=1.20.0\n")
    monkeypatch.setattr(_layers, "ROOT", tmp_path)

    gate = _layers.gate_libgit2_is_not_the_vulnerable_version()
    assert not gate.passed
    assert "1.20.1" in gate.measured


def test_the_libgit2_gate_passes_on_the_shipped_tree():
    from scripts.gates import _layers

    gate = _layers.gate_libgit2_is_not_the_vulnerable_version()
    assert gate.passed, gate.measured
