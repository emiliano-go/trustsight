"""Import-time cost, and the operations a user waits on.

Every CLI invocation pays import cost - `--version` and `--help` included -
so work done at module level is work every command pays whether it needs it
or not. The Cf scan in `unicode.py` walks all 1,114,112 code points asking
`unicodedata` for each one's category, which is about 360 ms.
"""

import importlib
import sys
import time

import pytest


def _fresh(name: str):
    """Import *name* with no cached module, and return it."""
    for mod in [m for m in sys.modules if m == name or m.startswith(name + ".")]:
        del sys.modules[mod]
    return importlib.import_module(name)


def test_importing_unicode_does_not_run_the_codepoint_scan():
    """The scan is deferred, not deleted.

    Deriving the set is what makes a format-control codepoint added in a
    future Unicode version covered automatically, so it is still derived -
    just on first use rather than at import.
    """
    module = _fresh("trustsight.unicode")

    # The derived names are absent from the module dict until touched.
    for name in ("_UNCONDITIONAL_CF", "COMBINED", "UNCONDITIONAL",
                 "R013_UNCONDITIONAL_PATTERN"):
        assert name not in module.__dict__, f"{name} was built at import"

    # Touching one resolves and caches all of them.
    assert module.COMBINED.search("‮")
    assert "COMBINED" in module.__dict__
    assert len(module._UNCONDITIONAL_CF) > 100


def test_the_derived_set_still_matches_the_unicode_database():
    """Deferring must not change what R013 covers."""
    import unicodedata

    from trustsight import unicode as u

    expected = {
        cp for cp in range(0x110000)
        if unicodedata.category(chr(cp)) == "Cf" and cp not in u._CONTEXTUAL_CF
    }
    assert set(u._UNCONDITIONAL_CF) == expected


def test_importing_the_unicode_module_is_fast():
    start = time.monotonic()
    _fresh("trustsight.unicode")
    elapsed = time.monotonic() - start
    assert elapsed < 0.15, f"import took {elapsed * 1000:.0f} ms"


@pytest.mark.parametrize("text,expected", [
    ("a‮b", True),      # bidi override
    ("a⁦b", True),      # bidi isolate
    ("plain ascii", False),
])
def test_fatal_codepoint_detection_is_unchanged(text, expected):
    from trustsight.unicode import has_fatal_codepoints

    assert has_fatal_codepoints(text) is expected
