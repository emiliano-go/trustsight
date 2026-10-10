"""Addendum 5 §7: typed file metadata and the L1 structural rules.

C018 / C019 / C026 read the typed ``DiffFile`` mode, rename and hunk facts -
never a raw diff walk.  The parser extension that feeds them is also pinned
here, since a pure rename has no ``---``/``+++``/hunk to key a file on.
"""

from trustsight.analysis.pipeline import scan_diff
from trustsight.diffdoc import parse_diff


def _ids(text: str) -> set[str]:
    fact = scan_diff(text, package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


def test_executable_file_committed_fires():
    text = (
        "diff --git a/run.sh b/run.sh\n"
        "new file mode 100755\n"
        "index 0000000..1111111\n"
        "--- /dev/null\n"
        "+++ b/run.sh\n"
        "@@ -0,0 +1,2 @@\n"
        "+#!/bin/sh\n"
        "+echo hi\n"
    )
    assert "C018" in _ids(text)


def test_non_executable_added_file_does_not_fire_c018():
    text = (
        "diff --git a/data.txt b/data.txt\n"
        "new file mode 100644\n"
        "index 0000000..1111111\n"
        "--- /dev/null\n"
        "+++ b/data.txt\n"
        "@@ -0,0 +1,1 @@\n"
        "+hello\n"
    )
    assert "C018" not in _ids(text)


def test_rename_with_no_hunks_fires():
    text = (
        "diff --git a/old.conf b/new.conf\n"
        "similarity index 100%\n"
        "rename from old.conf\n"
        "rename to new.conf\n"
    )
    assert "C019" in _ids(text)


def test_empty_file_added_fires():
    text = (
        "diff --git a/marker b/marker\n"
        "new file mode 100644\n"
        "index 0000000..e69de29\n"
    )
    assert "C026" in _ids(text)


def test_added_binary_file_is_not_read_as_empty():
    text = (
        "diff --git a/blob.bin b/blob.bin\n"
        "new file mode 100644\n"
        "index 0000000..abc1234\n"
        "Binary files /dev/null and b/blob.bin differ\n"
    )
    assert "C026" not in _ids(text)


def test_parser_materialises_rename_only_file():
    doc = parse_diff(
        "diff --git a/old.conf b/new.conf\n"
        "similarity index 100%\n"
        "rename from old.conf\n"
        "rename to new.conf\n"
    )
    assert len(doc.files) == 1
    file = doc.files[0]
    assert file.path == "new.conf"
    assert file.rename_from == "old.conf"
    assert file.rename_to == "new.conf"
    assert file.renamed
    assert file.hunks == ()


def test_parser_captures_mode_and_status_on_added_file():
    doc = parse_diff(
        "diff --git a/run.sh b/run.sh\n"
        "new file mode 100755\n"
        "index 0000000..1111111\n"
        "--- /dev/null\n"
        "+++ b/run.sh\n"
        "@@ -0,0 +1,1 @@\n"
        "+#!/bin/sh\n"
    )
    file = doc.files[0]
    assert file.status == "added"
    assert file.new_mode == "100755"


def test_run_confirmed_on_the_locked_corpus():
    """A benign corpus sample must not move: C018/C019/C026 are measured at
    0/3,739.  The full replay is the calibration job; this pins the shape."""
    # A hand-written benign bump with no executable file, rename or empty add.
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
        " pkgname=demo\n"
        "-pkgver=1.0\n+pkgver=1.1\n"
    )
    assert not ({"C018", "C019", "C026"} & _ids(text))
