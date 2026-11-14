"""The state-and-lifecycles page must describe code that still exists.

The full check lives in the security gate so it runs with
``scripts/security_gates.py``; this wrapper keeps the failure legible in a
targeted pytest run and names the command that repairs the generated table.
"""

from __future__ import annotations

from pathlib import Path

from scripts.gates._state import (
    DOC,
    REGISTRY,
    gate_state_machines_are_documented,
)
from scripts.state_machines import (
    Registry,
    check_registry,
    load_registry,
    resolve_anchor,
    resolve_test,
)


def test_the_page_and_registry_are_present():
    assert REGISTRY.is_file()
    assert DOC.is_file()


def test_state_machines_are_documented_and_exist():
    gate = gate_state_machines_are_documented()
    assert gate.passed, gate.detail


def test_a_renamed_anchor_is_reported():
    assert resolve_anchor(Path(__file__).resolve().parents[1],
                          "trustsight.line_lex:QuoteState") is None
    problem = resolve_anchor(Path(__file__).resolve().parents[1],
                             "trustsight.line_lex:NoSuchState")
    assert problem and "NoSuchState" in problem


def test_a_missing_test_node_is_reported():
    root = Path(__file__).resolve().parents[1]
    assert resolve_test(root, "tests/test_machine_contracts.py::"
                              "test_quote_state_carries_across_lines") is None
    problem = resolve_test(root, "tests/test_machine_contracts.py::"
                                 "test_no_such_contract")
    assert problem and "test_no_such_contract" in problem


def test_a_new_stateful_module_must_be_classified(tmp_path):
    probe = tmp_path / "src" / "trustsight" / "probe.py"
    probe.parent.mkdir(parents=True)
    probe.write_text(
        "def walk(lines):\n"
        "    state = 'code'\n"
        "    for line in lines:\n"
        "        if state == 'code':\n"
        "            state = 'body'\n"
        "    return state\n",
        encoding="utf-8",
    )
    problems = check_registry(tmp_path, Registry(machines=(), exempt=()))
    assert any("unclassified stateful module 'probe.py'" in p for p in problems)
