"""Remaining malign false positives from the 2026-10-30 14h window.

Checked against HEAD, not the deployed 0.25.0.  X033/X022/X024 (`_icon_path`)
and the zxp Go/Yarn build-env X024/H032 hits are already cleared by the
current code; the tests below pin that too so a regression is visible.

Each case pairs the benign shape with the true-positive twin the fix must
keep.
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


def _ids(diff, current_text=None, package_name="p"):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name=package_name, current_text=current_text)
    return {e.rule_id for e in fact.score_breakdown}


# --- X005: a printed install notice is not a home write --------------------

_SNAC_MESSAGE = (
    "--- a/p.install\n+++ b/p.install\n@@ -0,0 +1,4 @@\n"
    "+post_install() {\n"
    '+  echo "$ echo \\"SNAC_DATA=/home/user/.local/share/snac\\" > '
    '~/.config/snac/snac.conf"\n'
    "+}\n"
)


def test_x005_does_not_fire_on_a_printed_notice():
    assert "X005" not in _ids(_SNAC_MESSAGE)


def test_x005_still_fires_on_a_home_write():
    diff = (
        "--- a/p.install\n+++ b/p.install\n@@ -0,0 +1,4 @@\n"
        "+post_install() {\n"
        "+  cp payload /home/user/.bashrc\n"
        "+}\n"
    )
    assert "X005" in _ids(diff)


# --- H042: a hidden build config is not a hidden payload -------------------

def test_h042_does_not_fire_on_yarnrc():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,9 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        "+build() {\n"
        '+  cd "$srcdir/proj"\n'
        '+  sed -i "s|^registry .*|registry x|" .yarnrc\n'
        "+}\n"
    )
    assert "H042" not in _ids(diff)


def test_h042_still_fires_on_a_bare_hidden_drop():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,7 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        "+build() {\n"
        '+  cd "$srcdir/proj"\n'
        "+  install -Dm755 payload .evil.sh\n"
        "+}\n"
    )
    assert "H042" in _ids(diff)


# --- Already clear at HEAD: keep it that way -------------------------------

def test_x033_ignores_a_declared_appimage_with_carch():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,10 @@\n"
        "+pkgname=eusoft-dehelper-bin\n+pkgver=13.5.2\n+pkgrel=1\n"
        '+source=("${pkgname%-bin}-${pkgver}-x86_64.AppImage::'
        'https://static.eudic.net/pkg/dehelper.AppImage")\n'
        "+sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n"
        "+prepare() {\n"
        '+  chmod +x "${srcdir}/${pkgname%-bin}-${pkgver}-${CARCH}.AppImage"\n'
        '+  "${srcdir}/${pkgname%-bin}-${pkgver}-${CARCH}.AppImage" '
        "--appimage-extract >/dev/null\n"
        "+}\n"
    )
    assert "X033" not in _ids(diff, package_name="eusoft-dehelper-bin")


def test_x022_ignores_a_pkgver_scratch_file():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,10 @@\n"
        "+pkgname=apifox-bin\n+pkgver=2.8.53\n+pkgrel=1\n"
        "+prepare() {\n"
        '+  grep X-AppImage-Version app.desktop | sed s/x// > "${srcdir}/.pkgver"\n'
        "+}\n"
        "+pkgver() {\n"
        '+  cat "${srcdir}/.pkgver" 2>/dev/null || echo "${pkgver}"\n'
        "+}\n"
    )
    assert "X022" not in _ids(diff, package_name="apifox-bin")


def test_x024_ignores_a_local_icon_path():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,7 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
        "+package() {\n"
        '+  _icon_path="${_i#*share/icons/}"\n'
        "+}\n"
    )
    assert "X024" not in _ids(diff)


def test_x024_h032_ignore_build_local_go_env():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,13 @@\n"
        "+pkgname=ghost-chat\n+pkgver=1\n+pkgrel=1\n"
        "+_set_go_build_env() {\n"
        '+  export HOME="${srcdir}/.home"\n'
        '+  export GOPATH="${HOME}/go"\n'
        '+  export PATH="${GOPATH}/bin:${PATH}"\n'
        "+}\n"
        "+build() {\n"
        '+  cd "$srcdir/proj"\n'
        "+  _set_go_build_env\n"
        "+  go build ./...\n"
        "+}\n"
    )
    found = _ids(diff, package_name="ghost-chat")
    assert "X024" not in found
    assert "H032" not in found
