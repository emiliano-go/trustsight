"""A new orphaned definition fails here instead of accumulating silently.

The scanner is deliberately conservative (see ``scripts/dead_code.py``), so a
failure means a module-level name has no reference outside its own definition
in code, tests, docs or configuration.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts.dead_code import orphans  # noqa: E402


def test_no_unreferenced_module_level_definitions():
    dead = orphans()
    assert not dead, "\n".join(
        f"{path}:{line}  {kind} {name}" for name, line, kind, path in dead
    )
