"""Unit tests for the typed diff core (diffdoc).

Two kinds of assertions live here: structural ones (the parse of a
hand-written diff is exactly the expected document) and parity ones (each
projection equals the legacy ``differ`` walker it replaces, on inputs
chosen to hit the walkers' edge cases).  The corpus-wide parity proof is
``tests/harness/diffdoc_parity.py`` plus the sampled gate in
``tests/test_diffdoc_parity.py``.
"""

import pytest

from trustsight.differ import (
    MAX_DIFF_PATH_BYTES,
    _post_diff_lines,
    _pre_diff_lines,
    map_diff_lines,
)
from trustsight.diffdoc import parse_diff, parse_diff_lines


def assert_parity(text: str) -> None:
    """Every projection equals the legacy walker it replaces."""
    doc = parse_diff(text)
    assert doc.line_map() == map_diff_lines(text)
    assert doc.post_lines() == _post_diff_lines(text)
    assert doc.pre_lines() == _pre_diff_lines(text)


SIMPLE = (
    "diff --git a/PKGBUILD b/PKGBUILD\n"
    "index 111..222 100644\n"
    "--- a/PKGBUILD\n"
    "+++ b/PKGBUILD\n"
    "@@ -1,3 +1,4 @@\n"
    " pkgname=foo\n"
    "-pkgver=1.0\n"
    "+pkgver=2.0\n"
    " pkgrel=1\n"
    "+source=(https://example.com/foo.tar.gz)\n"
)


def test_simple_hunk_structure():
    doc = parse_diff(SIMPLE)
    assert len(doc.files) == 1
    f = doc.files[0]
    assert f.path == "PKGBUILD"
    assert f.old_path == "a/PKGBUILD"
    assert f.status == "modified"
    assert len(f.hunks) == 1
    hunk = f.hunks[0]
    assert (hunk.old_start, hunk.new_start) == (1, 1)
    assert hunk.expected_lines == 4
    assert hunk.actual_lines == 4


def test_simple_hunk_lines():
    doc = parse_diff(SIMPLE)
    sides = [(line.side, line.content) for line in doc.lines if line.is_content]
    assert sides == [
        ("context", "pkgname=foo"),
        ("remove", "pkgver=1.0"),
        ("add", "pkgver=2.0"),
        ("context", "pkgrel=1"),
        ("add", "source=(https://example.com/foo.tar.gz)"),
    ]
    others = [line for line in doc.lines if not line.is_content]
    assert [line.content for line in others] == [
        "diff --git a/PKGBUILD b/PKGBUILD", "index 111..222 100644",
    ]
    assert all(line.side == "other" for line in others)


def test_line_numbers_track_both_sides():
    doc = parse_diff(SIMPLE)
    by_content = {line.content: line for line in doc.lines}
    ctx = by_content["pkgname=foo"]
    assert (ctx.old_lineno, ctx.new_lineno) == (1, 1)
    removed = by_content["pkgver=1.0"]
    assert removed.old_lineno == 2
    # Parity with the legacy map: a removal carries the number the next
    # post-diff line will get, not a gap.
    assert removed.new_lineno == 2
    added = by_content["pkgver=2.0"]
    assert (added.old_lineno, added.new_lineno) == (None, 2)
    tail = by_content["source=(https://example.com/foo.tar.gz)"]
    assert (tail.old_lineno, tail.new_lineno) == (None, 4)


def test_index_is_the_raw_line_index():
    doc = parse_diff(SIMPLE)
    raw = SIMPLE.splitlines()
    for line in doc.lines:
        assert raw[line.index] == line.raw
    assert set(doc.line_map()) == {
        line.index for line in doc.lines if line.is_content
    }


def test_post_and_pre_reconstruction():
    doc = parse_diff(SIMPLE)
    assert doc.post_lines() == [
        "pkgname=foo", "pkgver=2.0", "pkgrel=1",
        "source=(https://example.com/foo.tar.gz)",
    ]
    assert doc.pre_lines() == ["pkgname=foo", "pkgver=1.0", "pkgrel=1"]
    assert doc.post_text().startswith("pkgname=foo\npkgver=2.0")


def test_multi_file_attribution():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-old\n+new\n"
        "--- a/foo.install\n+++ b/foo.install\n@@ -5 +5 @@\n-a\n+b\n"
    )
    doc = parse_diff(text)
    assert [f.path for f in doc.files] == ["PKGBUILD", "foo.install"]
    lines = {line.content: line.file for line in doc.added_lines()}
    assert lines == {"new": "PKGBUILD", "b": "foo.install"}
    assert_parity(text)


def test_added_and_removed_status():
    added = "--- /dev/null\n+++ b/foo.install\n@@ -0,0 +1 @@\n+post_install() { :; }\n"
    removed = "--- a/foo.install\n+++ /dev/null\n@@ -1 +0,0 @@\n-post_install() { :; }\n"
    assert parse_diff(added).files[0].status == "added"
    assert parse_diff(removed).files[0].status == "removed"
    assert_parity(added)
    assert_parity(removed)


def test_headerless_diff_defaults_to_pkgbuild():
    text = "@@ -1 +1 @@\n-old\n+new\n"
    doc = parse_diff(text)
    assert doc.files[0].path == "PKGBUILD"
    assert all(line.file == "PKGBUILD" for line in doc.lines)
    assert_parity(text)


def test_content_before_any_hunk_is_not_mapped_but_is_reconstructed():
    text = "+stray added line\n@@ -1 +1 @@\n-a\n+b\n"
    doc = parse_diff(text)
    stray = doc.lines[0]
    assert stray.side == "add" and not stray.in_hunk
    assert stray.index not in doc.line_map()
    assert "stray added line" in doc.post_lines()
    assert_parity(text)


def test_plus_plus_plus_content_line_is_a_header_legacy_compat():
    # An added line whose body starts with "++ " reads as "+++ " and is a
    # file header, exactly as every legacy walker read it.  The parser
    # decides once; the parity suite locks the decision.
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n ctx\n+++ looks like a header\n"
    doc = parse_diff(text)
    assert [f.path for f in doc.files] == ["PKGBUILD", "looks like a header"]
    assert_parity(text)


def test_plus_plus_plus_without_space_is_content():
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1,2 @@\n ctx\n+++not a header\n"
    doc = parse_diff(text)
    assert [f.path for f in doc.files] == ["PKGBUILD"]
    assert "++not a header" in doc.post_lines()
    assert_parity(text)


def test_dash_dash_dash_content_line_is_not_a_header():
    # The trailing-space guard: "---x" inside a hunk is a removed content
    # line, not a file header (the checksum arrays depend on this).
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1 @@\n ctx\n----weird\n"
    doc = parse_diff(text)
    assert [f.path for f in doc.files] == ["PKGBUILD"]
    assert "---weird" in doc.pre_lines()
    assert_parity(text)


def test_non_matching_at_lines_are_structure():
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n@@ not a header\n-a\n+b\n"
    doc = parse_diff(text)
    junk = [line for line in doc.lines if line.raw == "@@ not a header"]
    assert junk and junk[0].side == "other"
    assert all(
        line.content != "@ not a header"
        for line in doc.lines if line.is_content
    )
    assert_parity(text)


def test_malformed_hunk_header_opens_nothing():
    text = "@@ -x +y @@\n+not mapped\n"
    doc = parse_diff(text)
    assert doc.line_map() == {}
    assert "not mapped" in doc.post_lines()
    assert_parity(text)


def test_no_newline_marker_is_structure():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n"
        "\\ No newline at end of file\n"
    )
    doc = parse_diff(text)
    assert [line.content for line in doc.lines if line.is_content] == ["old", "new"]
    assert sum(1 for line in doc.lines if line.side == "other") == 2
    assert_parity(text)


def test_binary_marker_is_structure():
    text = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        "Binary files a/PKGBUILD and b/PKGBUILD differ\n"
    )
    doc = parse_diff(text)
    assert not any(line.is_content for line in doc.lines)
    assert all(line.side == "other" for line in doc.lines)
    assert doc.post_lines() == []
    assert_parity(text)


def test_empty_diff():
    doc = parse_diff("")
    assert doc.files == ()
    assert doc.lines == ()
    assert doc.post_lines() == []
    assert_parity("")


def test_long_path_is_capped():
    path = "b/" + "x" * (MAX_DIFF_PATH_BYTES + 100)
    text = f"--- /dev/null\n+++ {path}\n@@ -0,0 +1 @@\n+x\n"
    doc = parse_diff(text)
    assert len(doc.files[0].path) == MAX_DIFF_PATH_BYTES
    assert_parity(text)


def test_multiple_hunks_one_file():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1 +1 @@\n-a\n+b\n"
        "@@ -10 +10,2 @@\n-c\n+d\n+e\n"
    )
    doc = parse_diff(text)
    assert len(doc.files) == 1
    assert len(doc.files[0].hunks) == 2
    assert doc.files[0].hunks[1].new_start == 10
    by_content = {line.content: line for line in doc.lines}
    assert by_content["e"].new_lineno == 11
    assert_parity(text)


def test_hunk_count_mismatch_is_reported_not_repaired():
    # Declares 3 post-side lines, carries 2: truncated or malformed, and
    # the document says so instead of guessing.
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n-a\n+b\n"
    doc = parse_diff(text)
    hunk = doc.files[0].hunks[0]
    assert hunk.expected_lines == 3
    assert hunk.actual_lines == 1
    assert_parity(text)


def test_hunk_header_without_counts():
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n"
    doc = parse_diff(text)
    hunk = doc.files[0].hunks[0]
    assert hunk.expected_lines == 1
    assert_parity(text)


def test_parse_diff_lines_skips_the_split():
    lines = ["--- a/PKGBUILD", "+++ b/PKGBUILD", "@@ -1 +1 @@", "-a", "+b"]
    doc = parse_diff_lines(lines)
    assert [line.content for line in doc.lines if line.is_content] == ["a", "b"]


def test_in_hunk_survives_a_file_header_legacy_compat():
    # Malformed: a content line between the +++ header and the next @@ is
    # still mapped by the legacy walk, so the projection maps it too.
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n"
        "+++ b/other.py\n+stray\n"
    )
    doc = parse_diff(text)
    stray = [line for line in doc.lines if line.content == "stray"][0]
    assert stray.in_hunk
    assert doc.line_map()[stray.index] == ("other.py", stray.new_lineno)
    assert_parity(text)


def test_boundary_flags_mark_what_the_legacy_walk_saw():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n"
        "--- a/foo.install\n+++ b/foo.install\n@@ -5 +5 @@\n-c\n+d\n"
    )
    doc = parse_diff(text)
    by_raw = {line.raw: line for line in doc.lines if line.is_content}
    # The first line after a file header sees file_boundary; the first
    # after a hunk header sees hunk_boundary.
    assert by_raw["-a"].file_boundary and by_raw["-a"].hunk_boundary
    assert not by_raw["+b"].file_boundary
    assert by_raw["-c"].file_boundary and by_raw["-c"].hunk_boundary
    assert by_raw["+d"].file_boundary is False
    assert_parity(text)


@pytest.mark.parametrize("text", [
    SIMPLE,
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-old\n+new\n",
    "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1,2 @@\n+'\n+\"quoted (paren)\"\n",
    "--- a/.SRCINFO\n+++ b/.SRCINFO\n@@ -1,2 +1,2 @@\n-\tpkgver = 1\n+\tpkgver = 2\n",
    "@@ -1 +1 @@\n-http://old.example.com\n+https://new.example.com\n",
    "+sha256sums=(\n+  'SKIP'\n+)\n",
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n source=(\n-\t'a.tar.gz'\n+\t'b.tar.gz'\n )\n",
])
def test_projection_parity_on_representative_diffs(text):
    assert_parity(text)
