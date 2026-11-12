"""False positives from the 2026-11-12 watcher triage.

Each fix keeps its true-positive twin: the benign shape must clear, and the
same rule must still fire when the evidence is real.
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


def _entries(diff, current_text=None):
    with shipped_config():
        return scan_diff(
            diff, rules=load_rules(), config=load_config(), package_name="p",
            current_text=current_text,
        ).score_breakdown


def _ids(diff, current_text=None):
    return {e.rule_id for e in _entries(diff, current_text)}


def _diff(old, new, n=0):
    return "".join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True),
        "a/PKGBUILD", "b/PKGBUILD", n=n,
    ))


# --- C004: the source array opener can sit outside the changed hunk --------

def test_c004_ignores_a_local_source_removed_outside_the_hunk():
    old = "\n".join([
        "source=(",
        "  'archive.tar.gz'",
        "  'redragon.hook'",
        ")",
        "sha256sums=('a' 'b')",
        "package() {",
        "  install -Dm644 'redragon.hook' \"$pkgdir/usr/share/libalpm/hooks/\"",
        "}",
        "",
    ])
    new = "\n".join([
        "source=(",
        "  'archive.tar.gz'",
        ")",
        "sha256sums=('a')",
        "package() {",
        "}",
        "",
    ])
    assert "C004" not in _ids(_diff(old, new), current_text=new)


def test_c004_still_fires_when_only_the_checksum_leaves_the_hunk():
    old = "\n".join([
        "pkgname=p", "pkgver=1", "pkgrel=1",
        "source=(a.tar.gz b.patch)",
        "sha256sums=('a'", "            'b'", "            'c'",
        "            'd')", "",
    ])
    new = "\n".join([
        "pkgname=p", "pkgver=1", "pkgrel=2",
        "source=(a.tar.gz b.patch)",
        "sha256sums=('a'", "            'b')", "",
    ])
    assert "C004" in _ids(_diff(old, new, n=3), current_text=new)


# --- H100: a printer's continued arguments are still a notice --------------

_NOTICE_HOOK = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,3 @@
 pkgname=p
+install="$pkgname.install"
--- /dev/null
+++ b/p.install
@@ -0,0 +1,12 @@
+post_install() {
+  printf '%s\\n' \\
+    ':: Run: sudo systemctl enable example' \\
+    '   Tray menu -> Quit'
+}
+
+post_upgrade() {
+  printf '%s\\n' \\
+    ':: If the app was running, quit it before restarting' \\
+    '   or: pkill -f /usr/lib/example/example'
+}
"""


def test_h100_a_continued_printer_argument_is_notice_only():
    rows = [e for e in _entries(_NOTICE_HOOK) if e.rule_id == "H100"]
    assert rows and rows[0].severity == "INFO" and rows[0].weight == 0


def test_h100_still_fires_when_the_hook_runs_a_command():
    diff = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,3 @@
 pkgname=p
+install="$pkgname.install"
--- /dev/null
+++ b/p.install
@@ -0,0 +1,3 @@
+post_install() {
+  systemctl enable example.service
+}
"""
    assert "H100" in _ids(diff)


# --- SOURCE_BUCKET and C005: a vendor's own download center ----------------

def test_source_bucket_accepts_the_epson_download_center():
    diff = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,4 @@
 pkgname=p
+source=('https://download-center.epson.com/f/module/x/epson.src.rpm')
+sha256sums=('a')
"""
    assert "SOURCE_BUCKET" not in _ids(diff)
    assert "C005" not in _ids(diff)


def test_source_bucket_still_flags_an_unknown_host():
    diff = """\
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,4 @@
 pkgname=p
+source=('https://evil.test/f/module/x/epson.src.rpm')
+sha256sums=('a')
"""
    assert "SOURCE_BUCKET" in _ids(diff)
