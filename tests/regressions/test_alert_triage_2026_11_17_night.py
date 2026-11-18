"""Malicious false positives from the 2026-11-17 night watcher batch.

Two shapes: a project's own release host and GitHub's PR-patch endpoint were
bucketed unknown, and a Mesa replacement's capability provides were read as
hijacking an unrelated established package.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import dependencies as deps_rules  # noqa: E402
from trustsight.analysis.dependencies import is_established_package  # noqa: E402
from trustsight.buckets import classify_url  # noqa: E402
from trustsight.config import load_domains  # noqa: E402
from trustsight.deps import is_virtual_provide  # noqa: E402


# --- the two project-owned hosts -----------------------------------------

def test_github_pr_patch_endpoint_is_a_forge():
    domains = load_domains()
    url = "https://patch-diff.githubusercontent.com/raw/OrcaSlicer/OrcaSlicer/pull/17523.patch"
    assert classify_url(url, domains)[0] == "trusted_forge"


def test_ghostty_release_host_is_official():
    domains = load_domains()
    url = "https://release.files.ghostty.org/libghostty-vt/1.0.1/libghostty-vt-1.0.1.tar.gz"
    assert classify_url(url, domains)[0] == "official"


def test_unrelated_hosts_stay_unknown():
    domains = load_domains()
    for url in ("https://patch-diff.evil.example/x.patch",
                "https://release.files.evil.example/x.tar.gz"):
        assert classify_url(url, domains)[0] == "unknown", url


# --- capability provides are not impersonable packages -------------------

@pytest.mark.parametrize("name", [
    "libva-driver", "opengl-driver", "vulkan-driver", "java-runtime", "ttf-font",
])
def test_capability_tokens_are_not_established(name):
    assert is_virtual_provide(name)


@pytest.mark.parametrize("name", ["libglvnd", "openssl", "mesa", "polkit"])
def test_real_packages_are_not_capability_tokens(name):
    assert not is_virtual_provide(name)


def test_is_established_package_ignores_a_capability_token(monkeypatch):
    """The observation fallback certifies libva-driver; the guard wins."""
    monkeypatch.setattr(deps_rules._db, "official_package_names", lambda: [])
    monkeypatch.setattr(deps_rules, "dependency_observation_count", lambda _n: 500)
    assert not is_established_package("libva-driver")
    assert is_established_package("openssl")


def test_mesa_capability_provides_do_not_fire_d004():
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config, load_rules

    head = """pkgname=mesa-kraid-git
pkgver=1.0
pkgrel=1
url="https://gitlab.freedesktop.org/mesa/mesa"
provides=('opengl-driver' 'vulkan-driver' 'libva-driver')
source=("mesa::git+https://gitlab.freedesktop.org/mesa/mesa.git#branch=main")
sha256sums=('SKIP')
"""
    with shipped_config():
        fact = scan_diff(
            "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,8 @@\n"
            + "".join("+" + line + "\n" for line in head.splitlines()),
            rules=load_rules(), config=load_config(),
            package_name="mesa-kraid-git", current_text=head,
        )
    assert "D004" not in {e.rule_id for e in fact.score_breakdown}
