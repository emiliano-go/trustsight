"""The state-and-lifecycles page and its registry stay true to the code."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from scripts.gates._core import Gate, ROOT

_CONTRACT = Path(__file__).resolve().parents[2]
if str(_CONTRACT) not in sys.path:
    sys.path.insert(0, str(_CONTRACT))

from scripts.state_machines import (  # noqa: E402
    GENERATED_END,
    GENERATED_START,
    REGISTRY,
    check_registry,
    load_registry,
    render_inventory,
)

DOC = ROOT / "docs" / "explanation" / "state-and-lifecycles.md"


def _inventory_is_current(registry) -> str | None:
    if not DOC.is_file():
        return "docs/explanation/state-and-lifecycles.md is missing"
    text = DOC.read_text(encoding="utf-8")
    match = re.search(
        rf"{re.escape(GENERATED_START)}\n(.*?)\n{re.escape(GENERATED_END)}",
        text, re.S)
    if match is None:
        return "generated state-machines markers are missing"
    expected = render_inventory(registry)
    if match.group(1) != expected:
        return ("generated inventory drifted from scripts/state_machines.toml; "
                "run python scripts/build_state_doc.py")
    return None


def gate_state_machines_are_documented() -> Gate:
    """Every documented machine still exists, and no stateful module escapes.

    ``docs/explanation/state-and-lifecycles.md`` is the map a contributor
    reads before changing a lexer, a lifecycle or an orchestration mode.
    A map that names a symbol the code no longer has is worse than no map:
    it sends the reader to a decision point that has moved.  The same gate
    checks the other direction - a module that starts carrying state must be
    documented or explicitly classified - so the page cannot quietly fall
    behind a new subsystem.

    The checks are structural: anchors resolve through ``ast`` (never by
    importing the package), persisted tables and columns must appear in the
    schema module, test node ids must resolve, and the generated inventory
    must equal the registry rendering.  Behavioural persistence stays in the
    round-trip tests the registry names.
    """
    name = "state machines are documented and exist"
    if not REGISTRY.is_file():
        return Gate(name, False, "scripts/state_machines.toml is missing")
    try:
        registry = load_registry(REGISTRY)
    except (OSError, ValueError) as exc:
        return Gate(name, False, f"cannot read registry: {exc}")

    problems = check_registry(ROOT, registry)
    inventory_problem = _inventory_is_current(registry)
    if inventory_problem:
        problems.append(inventory_problem)

    if problems:
        return Gate(name, False, problems[:20])
    return Gate(
        name,
        True,
        f"{len(registry.machines)} machines documented; "
        f"{len(registry.exempt_modules())} modules classified",
    )
