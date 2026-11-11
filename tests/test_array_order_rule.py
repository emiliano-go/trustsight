"""The reordered-array rule (C014, re-filed from H099).

A checksum array whose entries moved during a content change is the
suspicious composition; a pure reformat stands down by default.  The
SKIP-position move and the arch-suffixed arrays are covered too.
"""

from pathlib import Path

from trustsight.analysis.pipeline import scan_diff
from trustsight.config import load_config

_FIXTURES = Path(__file__).parent / "fixtures"


def _config(require_content_change: bool | None = None):
    config = dict(load_config())
    thresholds = dict(config.get("thresholds", {}))
    if require_content_change is not None:
        thresholds["c014"] = {"require_content_change": require_content_change}
    config["thresholds"] = thresholds
    return config


def _rule_ids(text: str, config=None) -> set[str]:
    fact = scan_diff(text, config=config, package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


_REORDER_ONLY = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,6 +1,6 @@
 pkgname=demo
 pkgver=1.0
 sha256sums=(
-'aaaa'
-'bbbb'
+'bbbb'
+'aaaa'
 )
"""

_REORDER_AND_SWAP = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,7 +1,7 @@
 pkgname=demo
 pkgver=1.0
 sha256sums=(
-'aaaa'
-'bbbb'
-'cccc'
+'cccc'
+'aaaa'
+'dddd'
 )
"""

_SKIP_MOVED = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,6 +1,6 @@
 pkgname=demo
 pkgver=1.0
 sha256sums=(
-'SKIP'
-'aaaa'
+'aaaa'
+'SKIP'
 )
"""

_ARCH_REORDER = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,7 +1,7 @@
 pkgname=demo
 pkgver=1.0
 sha256sums_x86_64=(
-'aaaa'
-'bbbb'
-'cccc'
+'cccc'
+'aaaa'
+'dddd'
 )
"""


def test_reorder_only_stands_down_by_default():
    assert "C014" not in _rule_ids(_REORDER_ONLY, _config())


def test_reorder_only_fires_when_the_gate_is_off():
    assert "C014" in _rule_ids(
        _REORDER_ONLY, _config(require_content_change=False))


def test_reorder_during_a_content_change_fires():
    assert "C014" in _rule_ids(_REORDER_AND_SWAP, _config())


def test_a_moved_skip_fires():
    assert "C014" in _rule_ids(_SKIP_MOVED, _config())


def test_arch_suffixed_arrays_are_handled():
    assert "C014" in _rule_ids(_ARCH_REORDER, _config())


_ISOLATED_INSERTION = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,6 +1,6 @@
 pkgname=demo
 pkgver=1.0
-source=('a.tar.gz' 'b.tar.gz')
-sha256sums=('aaaa' 'bbbb')
+source=('a.tar.gz' 'c.tar.gz' 'b.tar.gz')
+sha256sums=('aaaa' 'bbbb' 'cccc')
"""

_ALIGNED_INSERTION = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,6 +1,6 @@
 pkgname=demo
 pkgver=1.0
-source=('a.tar.gz' 'b.tar.gz')
-sha256sums=('aaaa' 'bbbb')
+source=('a.tar.gz' 'c.tar.gz' 'b.tar.gz')
+sha256sums=('aaaa' 'cccc' 'bbbb')
"""


def test_isolated_insertion_fires_low():
    fact = scan_diff(_ISOLATED_INSERTION, config=_config(), package_name="demo")
    hits = [e for e in fact.score_breakdown if e.rule_id == "C014"]
    assert hits, "an out-of-parity checksum insertion should fire C014"
    assert all(e.severity == "LOW" for e in hits)


def test_aligned_insertion_stands_down():
    assert "C014" not in _rule_ids(_ALIGNED_INSERTION, _config())


_CUT_BY_HUNK_BOUNDARY = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -2,7 +2,7 @@
 pkgver=1.0
 sha256sums=(
 'a1'
-'old'
+'new'
 'a2'
 'a3'
 'a4'
@@ -16,6 +16,6 @@
 prepare() {
   cp x y
-  npm install typescript@5.7.3
-  export PATH=node_modules/.bin:${PATH}
+  npm install
+  echo done
 }
"""


def test_a_partial_array_projection_is_not_an_order_change():
    """pacman-static: removing one zlib patch leaves empty placeholders for
    entries outside the hunk, so the two projections cannot prove a reorder."""
    diff = (_FIXTURES / "pacman-static-partial-array.diff").read_text()
    assert "C014" not in _rule_ids(diff, _config())


def test_a_checksum_array_cut_by_a_hunk_boundary_is_not_reordered():
    """gnome-shell-extension-mosaic: neither hunk shows the closing paren, so
    each projection reads the next hunk's lines as checksum entries.  The
    two sides then differ only in what they swallowed, which is not a
    reorder (or a content change) in the array the recipe declares."""
    assert "C014" not in _rule_ids(_CUT_BY_HUNK_BOUNDARY, _config())
