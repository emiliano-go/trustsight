"""C011 provenance decisions from the 2026-10-31 watcher window.

A declared documentation source is not the prebuilt artifact, and a vendor
release host is a C011-only exemption (`[source_host_divergence] allow`), not
an `official` bucket.  Each benign case keeps its divergent-artifact twin.
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


def _ids(diff, package_name):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name=package_name)
    return {e.rule_id for e in fact.score_breakdown}


def _new_file(body: str) -> str:
    lines = body.strip("\n").splitlines()
    added = "".join("+" + line + "\n" for line in lines)
    return (f"--- /dev/null\n+++ b/PKGBUILD\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{added}")


_IDS = "0" * 64

_DOC_SOURCE = _new_file(f"""
pkgname=snishaper-bin
pkgver=1
pkgrel=1
url="https://github.com/vendor/snishaper"
source=("snishaper.tar.gz::https://github.com/vendor/snishaper/releases/download/v1/snishaper.tar.gz"
        "LICENSE::https://docs.unknown.example/LICENSE")
sha256sums=('{_IDS}' '{_IDS}')
""")


def test_a_declared_documentation_source_is_not_a_c011_divergence():
    """The LICENSE URL is declared; it cannot supply the prebuilt host."""
    assert "C011" not in _ids(_DOC_SOURCE, "snishaper-bin")


_DIVERGENT_SOURCE = _new_file(f"""
pkgname=snishaper-bin
pkgver=1
pkgrel=1
url="https://github.com/vendor/snishaper"
source=("snishaper.tar.gz::https://repo.unknown.example/snishaper.tar.gz")
sha256sums=('{_IDS}')
""")


def test_a_divergent_prebuilt_artifact_still_fires_c011():
    assert "C011" in _ids(_DIVERGENT_SOURCE, "snishaper-bin")


_VENDOR_ALLOWED = _new_file(f"""
pkgname=hex-bin
pkgver=1
pkgrel=1
url="https://github.com/anomalyco/hex"
source=("hex.tar.gz::https://cdn.anoma.ly/hex/hex-1.tar.gz")
sha256sums=('{_IDS}')
""")


def test_a_project_owned_release_host_is_a_c011_only_exemption():
    """`anoma.ly` is in the allow list, not in `[official_projects]`."""
    ids = _ids(_VENDOR_ALLOWED, "hex-bin")
    assert "C011" not in ids
    assert "SOURCE_BUCKET" in ids


_VENDOR_REPORTED = _new_file(f"""
pkgname=wyrwood-bin
pkgver=1
pkgrel=1
url="https://github.com/wyrd-company/wyrwood"
source=("wyrwood.tar.gz::https://repo.wyrd.foo/artifacts/wyrwood-1.tar.gz")
sha256sums=('{_IDS}')
""")


def test_a_new_zero_vote_vendor_host_is_still_reported():
    """`repo.wyrd.foo` does not meet the official-domain trust bar."""
    assert "C011" in _ids(_VENDOR_REPORTED, "wyrwood-bin")
