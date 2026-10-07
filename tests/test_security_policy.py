"""Tests for the repository's security policy synchronization."""

from scripts import security_gates as sg
from scripts.critical_paths import CRITICAL_PATHS


def test_critical_path_policy_is_synchronised():
    gate = sg.gate_critical_paths_are_synchronised()
    assert gate.passed, gate.detail
    assert set(gate.measured) == CRITICAL_PATHS


def _lock_gate(tmp_path, monkeypatch, script: str):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (tmp_path / "uv.lock").write_text("")
    (workflows / "w.yml").write_text(
        "jobs:\n  x:\n    steps:\n"
        f"      - run: {script}\n"
    )
    monkeypatch.setattr(sg, "ROOT", tmp_path)
    return sg.gate_ci_installs_from_the_lock()


def test_lock_gate_rejects_a_live_resolve(tmp_path, monkeypatch):
    """A bare `uv lock` re-resolves from PyPI; the install check missed it."""
    gate = _lock_gate(tmp_path, monkeypatch, "uv lock")
    assert not gate.passed
    assert any("live resolve" in problem for problem in gate.measured)


def test_lock_gate_rejects_an_unlocked_install(tmp_path, monkeypatch):
    gate = _lock_gate(tmp_path, monkeypatch, "uv sync --all-extras")
    assert not gate.passed
    assert any("without --locked" in problem for problem in gate.measured)


def test_lock_gate_allows_locked_install_and_check_only(tmp_path, monkeypatch):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (tmp_path / "uv.lock").write_text("")
    (workflows / "w.yml").write_text(
        "jobs:\n  x:\n    steps:\n"
        "      - run: uv lock --check\n"
        "      - run: uv sync --locked --extra dev\n"
    )
    monkeypatch.setattr(sg, "ROOT", tmp_path)
    gate = sg.gate_ci_installs_from_the_lock()
    assert gate.passed, gate.detail
