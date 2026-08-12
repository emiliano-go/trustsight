"""Tests for the repository's security policy synchronization."""

from scripts.critical_paths import CRITICAL_PATHS
from scripts.security_gates import gate_critical_paths_are_synchronised


def test_critical_path_policy_is_synchronised():
    gate = gate_critical_paths_are_synchronised()
    assert gate.passed, gate.detail
    assert set(gate.measured) == CRITICAL_PATHS
