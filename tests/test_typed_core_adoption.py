"""The typed-core adoption guard.

The typed diff (diffdoc) and typed recipe (recipedoc) exist so that "read
the diff" is a parse, not a per-module walk.  This module pins the
remaining direct ``split_lines`` loops in ``src/``: every one left is a
whole-file or payload-text read, documented as such during the phase-1
migration.  A *new* raw loop is almost always a diff walker growing
outside the typed core, and this test fails on it.  Removing one of the
pinned loops is fine; lower the pin with the removal.
"""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "trustsight"

_LOOP_RE = re.compile(r"for\s+\w+\s+in\s+split_lines\(")

#: (path relative to src/trustsight, pinned loop count).  Every entry is a
#: whole-file, payload or recipe-text read, not a diff walker.
PINNED_LOOPS = {
    "full_aur/properties.py": 5,   # .SRCINFO/PKGBUILD recipe-text extraction
    "analysis/build.py": 1,        # rebuilds a whole-file text as context lines
    "analysis/delivery.py": 2,     # payload file content, not a diff
    "analysis/ioc.py": 1,          # whole-file text -> synthetic added lines
    "analysis/ioc_match.py": 1,    # same constructor
    "differ.py": 3,                # local_source_names/urls_from_pkgbuild_text/companions
}


def _loop_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in SRC.rglob("*.py"):
        n = sum(1 for line in path.read_text().splitlines() if _LOOP_RE.search(line))
        if n:
            counts[str(path.relative_to(SRC))] = n
    return counts


def test_no_new_raw_split_loops_outside_the_typed_core():
    counts = _loop_counts()
    for path, pinned in PINNED_LOOPS.items():
        assert counts.get(path, 0) <= pinned, (
            f"{path} grew raw split_lines loops ({counts[path]} > {pinned}); "
            "a diff reader belongs on diffdoc.DiffDoc, a recipe reader on "
            "recipedoc.RecipeDoc"
        )
    unexpected = set(counts) - set(PINNED_LOOPS)
    assert not unexpected, (
        f"new raw split_lines loops in {sorted(unexpected)}; "
        "read the typed core (diffdoc/recipedoc) instead, or pin the loop "
        "here with a comment naming why it is not a diff walker"
    )


def test_the_typed_core_exports_its_surface():
    from trustsight import diffdoc, recipedoc

    for name in ("DiffDoc", "DiffFile", "DiffHunk", "DiffLine",
                 "parse_diff", "parse_diff_lines"):
        assert hasattr(diffdoc, name), name
    for name in ("RecipeDoc", "ArrayDelta", "array_diff", "parse_recipe"):
        assert hasattr(recipedoc, name), name
