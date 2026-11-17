"""Malicious false positives from the 2026-11-17 watcher triage.

Each case pins the benign shape the rule misread and the true-positive twin
that must keep firing: per-architecture checksum arrays are not an emptied
list, a Renovate comment is not part of ``pkgver``, and a vendor's own
download host is not an unknown bucket.
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
from trustsight.buckets import classify_url  # noqa: E402
from trustsight.config import load_config, load_domains, load_rules  # noqa: E402
from trustsight.recipedoc import parse_recipe  # noqa: E402
from trustsight.tokenizer import split_lines  # noqa: E402


_HEAD = """pkgname=p
pkgver=1.0
pkgrel=1
url="https://e.example"
arch=('x86_64')
license=('MIT')
source=("https://e.example/x.tar.gz")
sha256sums=('SKIP')
"""

_SHA_A = "a" * 64
_SHA_B = "b" * 64


def _ids(diff, current_text=None, package_name="p"):
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(),
            package_name=package_name, current_text=current_text,
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


# --- H002: an empty generic array with per-arch backing is not "emptied" ---

_PER_ARCH = f"""pkgname=ov-bin
pkgver=1.0
pkgrel=1
url="https://e.example"
arch=('x86_64' 'aarch64')
license=('MIT')
source=()
sha256sums=()
source_x86_64=("x.whl::https://e.example/x.whl")
sha256sums_x86_64=('{_SHA_A}')
source_aarch64=("y.whl::https://e.example/y.whl")
sha256sums_aarch64=('{_SHA_B}')
"""


def test_h002_per_arch_checksums_are_not_an_emptied_array():
    assert "H002" not in _ids(_diff(_HEAD, _PER_ARCH), current_text=_PER_ARCH)


def test_h002_still_fires_with_no_arch_backing():
    body = _PER_ARCH.replace("source_x86_64", "_source_x86_64").replace(
        "source_aarch64", "_source_aarch64")
    assert "H002" in _ids(_diff(_HEAD, body), current_text=body)


def test_an_arch_checksum_of_skip_is_still_an_integrity_finding():
    # H001 owns a SKIP-backed source, so the finding is not H002; what must
    # not happen is the per-arch shape silencing the integrity family.
    body = _PER_ARCH.replace(_SHA_A, "SKIP")
    ids = _ids(_diff(_HEAD, body), current_text=body)
    assert ids & {"H001", "H002", "H003"}


# --- H031: a Renovate comment is not part of pkgver ----------------------

_RENOVATE = """pkgname=af-bin
pkgver=4.16.1 # renovate: datasource=github-tags depName=Azure/azure-functions-core-tools
pkgrel=1
url="https://github.com/Azure/azure-functions-core-tools"
arch=('x86_64')
license=('MIT')
source=("https://github.com/Azure/azure-functions-core-tools/releases/download/${pkgver}/cli.zip")
sha256sums=('SKIP')
"""


def test_h031_renovate_comment_is_not_part_of_pkgver():
    assert "H031" not in _ids(_new_file(_RENOVATE))


def test_h031_still_fires_on_an_unsafe_version():
    body = _RENOVATE.replace("4.16.1 # renovate", "1.0@evil # renovate")
    assert "H031" in _ids(_new_file(body))


# --- recipe scalars: comments are shell syntax, not value ----------------

def test_recipedoc_strips_an_assignment_comment():
    recipe = parse_recipe('pkgver=1.0 # renovate: anything\n')
    assert recipe.scalars["pkgver"] == "1.0"


def test_recipedoc_keeps_a_hash_inside_quotes():
    recipe = parse_recipe('pkgdesc="a # b"\n')
    assert recipe.scalars["pkgdesc"] == "a # b"


def test_recipedoc_keeps_a_commit_fragment_in_a_source():
    recipe = parse_recipe('source=("git+https://e.example/x#commit=abc")\n')
    assert tuple(recipe.arrays["source"]) == ("git+https://e.example/x#commit=abc",)


# --- SOURCE_BUCKET: vendor-owned download hosts are official -------------

def test_vendor_owned_download_hosts_are_official():
    domains = load_domains()
    for url in (
        "https://orthanc.uclouvain.be/downloads/sources/x.tar.gz",
        "https://getomniget.com/dl/v1.0.0/omniget.deb",
        "https://hub.spigotmc.org/jenkins/job/BungeeCord/x.jar",
        "https://qoder-app.oss-cn-beijing.aliyuncs.com/qoder-app/x.deb",
        "https://dl.cloudsmith.io/public/saga-soft/stable/x.deb",
    ):
        assert classify_url(url, domains)[0] == "official", url


def test_an_unrelated_host_still_pays_source_bucket():
    body = _HEAD.replace("https://e.example/x.tar.gz", "https://evil.example/x.tar.gz")
    assert "SOURCE_BUCKET" in _ids(_new_file(body))
