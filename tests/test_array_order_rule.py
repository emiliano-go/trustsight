"""Spec §6: the reordered-array rule (C014, re-filed from H099).

A checksum array whose entries moved during a content change is the
suspicious composition; a pure reformat stands down by default.  The
SKIP-position move and the arch-suffixed arrays are covered too.
"""

from trustsight.analysis.pipeline import scan_diff
from trustsight.config import load_config


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
