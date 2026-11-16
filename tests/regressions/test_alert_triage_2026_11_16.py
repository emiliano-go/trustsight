"""Malicious false positives from the 2026-11-16 watcher triage.

Each case pins the benign shape the rule misread and the true-positive twin
that must keep firing: a printed systemctl hint is not scheduled work, a JVM
``-D`` property loads no agent, an add-on store is the extension's upstream,
and replacing prose one comment for one shrinks nothing.
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402
from trustsight.tokenizer import split_lines  # noqa: E402


_HEAD = """pkgname=p
pkgver=1.0
pkgrel=1
source=('https://e.example/x.tar.gz')
sha256sums=('SKIP')
"""


def _ids(diff, current_text=None, package_name="p", manifest=None):
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(),
            package_name=package_name, current_text=current_text,
            tree_manifest=manifest,
        )
    return {e.rule_id for e in fact.score_breakdown}


def _new_file(body: str, path: str = "PKGBUILD") -> str:
    lines = body.strip("\n").splitlines()
    added = "".join("+" + line + "\n" for line in lines)
    return (f"--- /dev/null\n+++ b/{path}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{added}")


def _diff(old: str, new: str) -> str:
    return "\n".join(difflib.unified_diff(
        split_lines(old), split_lines(new),
        fromfile="PKGBUILD", tofile="PKGBUILD", n=3,
    ))


# --- X015: a printed install hint schedules nothing ------------------------

def test_x015_an_echoed_systemctl_hint_is_not_scheduled_work():
    body = _HEAD + """
package() {
  echo "Then run systemctl enable lighttpd && systemctl start lighttpd"
}
"""
    assert "X015" not in _ids(_new_file(body))


def test_x015_still_fires_on_a_command_substitution_in_the_printer():
    body = _HEAD + """
package() {
  echo "$(systemctl start lighttpd)"
}
"""
    assert "X015" in _ids(_new_file(body))


def test_x015_still_fires_on_a_real_enable_now():
    body = _HEAD + """
post_install() {
  systemctl enable --now lighttpd
}
"""
    assert "X015" in _ids(_new_file(body))


# --- X014: a JVM property is not an agent ---------------------------------

_JNA_CHECK = """
check() {
  export JAVA_TOOL_OPTIONS="-Djna.boot.library.path=${PWD}/build/native-linux-x86-64"
  ant test-platform
}
"""


def test_x014_a_jvm_system_property_is_not_code():
    diff = _diff(_HEAD, _HEAD + _JNA_CHECK)
    assert "X014" not in _ids(diff, current_text=_HEAD + _JNA_CHECK)


def test_x014_still_fires_on_a_javaagent():
    body = _HEAD + """
build() {
  export JAVA_TOOL_OPTIONS="-javaagent:$srcdir/agent.jar"
}
"""
    assert "X014" in _ids(_new_file(body))


# --- C011/SOURCE_BUCKET: the add-on store is the extension's upstream -----

_AMO_EXTENSION = """pkgname=ext-bin
pkgver=1.0
pkgrel=1
url="https://kagi.com/search"
license=('custom')
arch=('any')
source=("x.xpi::https://addons.mozilla.org/firefox/downloads/file/1/x-1.0.xpi")
sha256sums=('SKIP')
"""


def test_c011_an_amo_xpi_is_the_extension_upstream():
    ids = _ids(_new_file(_AMO_EXTENSION), package_name="ext-bin")
    assert "C011" not in ids
    assert "SOURCE_BUCKET" not in ids


def test_c011_still_fires_on_a_prebuilt_from_an_unrelated_host():
    body = _AMO_EXTENSION.replace(
        "https://addons.mozilla.org/firefox/downloads/file/1/x-1.0.xpi",
        "https://mirror.example.net/x-1.0.xpi")
    ids = _ids(_new_file(body), package_name="ext-bin")
    assert "C011" in ids
    assert "SOURCE_BUCKET" in ids


def test_source_bucket_accepts_a_pinned_googlesource_commit():
    body = _HEAD + (
        'source=("git+https://chromium.googlesource.com/external/'
        'github.com/google/crubit.git#commit=25d2c01b")\n'
    )
    ids = _ids(_diff(_HEAD, body), current_text=body)
    assert "SOURCE_BUCKET" not in ids


# --- C033: replacing prose one comment for one shrinks nothing ------------

def _commented(count: int, word: str) -> str:
    notes = "".join(f"# {word} note {i}\n" for i in range(count))
    return notes + _HEAD


def test_c033_a_rewrite_that_keeps_the_prose_is_not_context_bleed():
    old, new = _commented(10, "old"), _commented(12, "new")
    assert "C033" not in _ids(_diff(old, new), current_text=new)


def test_c033_a_rewrite_that_replaces_most_prose_one_for_one_stands_down():
    old, new = _commented(17, "old"), _commented(13, "new")
    assert "C033" not in _ids(_diff(old, new), current_text=new)


def test_c033_still_fires_when_the_prose_actually_shrinks():
    old, new = _commented(10, "old"), _HEAD
    diff = _diff(old, new) + "\n" + _new_file("# filler\n" * 20, "README.md")
    assert "C033" in _ids(diff, current_text=new)
