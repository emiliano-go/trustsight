"""Every shipped Python file parses under the declared Python floor.

The package declares ``requires-python = ">=3.11"``, but the 3.11 CI job only
imports what the suite imports. A script with 3.12-only syntax, a backslash
inside an f-string expression, shipped because every interpreter that imported
it was 3.12 or newer. ``ast.parse(..., feature_version=(3, 11))`` checks the
syntax against the floor from any interpreter, so the gap cannot reopen.
"""

import ast
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TREES = ("src", "scripts", "tests")


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


_SHIPPED = sorted((ROOT / "src" / "trustsight").rglob("*.py"))


@pytest.mark.parametrize(
    "path", _SHIPPED, ids=lambda p: str(p.relative_to(ROOT))
)
def test_source_has_no_invalid_escape_sequences(path):
    """A normal string/docstring may not carry a backslash the parser rejects.

    Python 3.14 surfaces these as ``SyntaxWarning`` (and 3.11 as a
    ``DeprecationWarning``); they are not fatal today but become syntax the
    interpreter may refuse later.  Compile every shipped module with warnings
    recorded rather than grepping for backslashes, so only sequences the
    parser actually rejects fail the build.
    """
    source = path.read_text(encoding="utf-8")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        compile(source, str(path), "exec")
    invalid = [
        warning for warning in caught
        if issubclass(warning.category, (SyntaxWarning, DeprecationWarning))
        and "invalid escape" in str(warning.message)
    ]
    assert not invalid, (
        f"{path.relative_to(ROOT)}:{invalid[0].lineno}: "
        f"{invalid[0].message}"
    )
