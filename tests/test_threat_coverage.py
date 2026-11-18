"""The generated threat coverage page matches the registry."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _script():
    spec = importlib.util.spec_from_file_location(
        "build_threat_coverage", ROOT / "scripts" / "build_threat_coverage.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_threat_coverage_page_is_current():
    assert _script().OUT.read_text() == _script().render()


def test_threat_coverage_includes_new_boundaries():
    text = (ROOT / "docs" / "reference" / "threat-coverage.md").read_text()
    assert "| C035 | Owned Namespace Occupied |" in text
    assert "| W015 | Archive Structure Ambiguous |" in text
