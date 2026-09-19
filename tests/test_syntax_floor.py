"""Every shipped Python file parses under the declared Python floor.

The package declares ``requires-python = ">=3.11"``, but the 3.11 CI job only
imports what the suite imports. A script with 3.12-only syntax, a backslash
inside an f-string expression, shipped because every interpreter that imported
it was 3.12 or newer. ``ast.parse(..., feature_version=(3, 11))`` checks the
syntax against the floor from any interpreter, so the gap cannot reopen.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TREES = ("src", "scripts", "tests", "zensical_extensions")


def _sources():
    for tree in TREES:
        base = ROOT / tree
        if base.is_dir():
            yield from sorted(base.rglob("*.py"))


@pytest.mark.parametrize(
    "path", list(_sources()), ids=lambda p: str(p.relative_to(ROOT))
)
def test_source_parses_under_the_python_floor(path):
    source = path.read_text(encoding="utf-8")
    try:
        ast.parse(source, filename=str(path), feature_version=(3, 11))
    except SyntaxError as exc:
        pytest.fail(
            f"{path.relative_to(ROOT)}:{exc.lineno}: {exc.msg} "
            "(not Python 3.11 syntax)"
        )
