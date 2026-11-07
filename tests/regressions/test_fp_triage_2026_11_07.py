"""Malicious false positives from the 2026-11-04..2026-11-07 watcher window.

Each case pins the benign shape the rule fired on and the true-positive twin
the fix must keep.  The batch is the 72h window ending 2026-11-07T02:00Z.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis.longitudinal import _h049_findings  # noqa: E402
from trustsight.buckets import classify_urls  # noqa: E402
from trustsight.full_aur.corpus import run_corpus_sweep  # noqa: E402
from trustsight.full_aur.properties import PropertyBreak  # noqa: E402
from trustsight.full_aur.temporal_engine import (  # noqa: E402
    HistorySnapshot,
    _name_repo_divergence_findings,
    source_repos_from_pkgbuild,
)

NOW = 1_800_000_000


def _meta(names, maintainer, modified=None):
    return {
        name: {
            "Name": name,
            "PackageBase": name,
            "Maintainer": maintainer,
            "LastModified": (modified if modified is not None else NOW - i),
        }
        for i, name in enumerate(names)
    }


def _h058(new, old, **kwargs):
    return [f for f in run_corpus_sweep(new, old, **kwargs)
            if f["rule_id"] == "H058"]


HISTORY = [{"maintainer": "alice", "cycle_time": c, "activity": 1}
           for c in (1, 2, 3, 4)]


# --- H058: new packages are H045/H074, not baseline activity ---------------

def test_h058_new_package_batch_is_not_a_deviation():
    old = _meta([f"p{i}" for i in range(10)], "alice")
    new = copy.deepcopy(old)
    new.update(_meta([f"n{i}" for i in range(5)], "alice", modified=NOW))
    assert _h058(new, old, maintainer_history=HISTORY) == []


def test_h058_new_packages_do_not_hide_an_existing_surge():
    names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"]
    old = _meta(names + ["eta", "theta", "iota", "kappa"], "alice",
                modified=NOW - 1000)
    new = copy.deepcopy(old)
    for name in names:
        new[name]["LastModified"] = NOW
    new.update(_meta([f"n{i}" for i in range(5)], "alice", modified=NOW))
    findings = _h058(new, old, maintainer_history=HISTORY)
    assert len(findings) == 1
    assert findings[0]["params"]["activity"] == 6


def test_h058_routine_vendor_batch_is_not_a_deviation():
    """The nvidia-beta family is one upstream release from nine recipes."""
    names = [
        "lib32-nvidia-utils-beta", "lib32-opencl-nvidia-beta", "nvidia-beta",
        "nvidia-beta-dkms", "nvidia-open-beta", "nvidia-open-beta-dkms",
        "nvidia-settings-beta", "nvidia-utils-beta", "opencl-nvidia-beta",
    ]
    old = _meta(names, "dbermond")
    new = _meta(names, "dbermond", modified=NOW)
    assert _h058(new, old, maintainer_history=HISTORY,
                 routine_only=set(names)) == []


# --- H059: separators are spelling, not divergence -------------------------

_MOSAICO = """\
pkgbase=mosaico
pkgname=(mosaico mosaicod python-mosaicolabs)
pkgver=0.7.0
url='https://mosaico.dev/'
source=("git+https://github.com/mosaico-labs/mosaico.git#tag=v$pkgver")
"""


def test_h059_hyphenated_repo_matches_the_joined_package_name():
    snapshot = HistorySnapshot(
        new_meta={}, old_meta=None,
        changes={"python-mosaicolabs": "added"}, transitions={},
        source_repos={"python-mosaicolabs":
                      source_repos_from_pkgbuild(_MOSAICO)},
    )
    assert _name_repo_divergence_findings(snapshot) == []


def test_h059_unrelated_repo_still_fires():
    snapshot = HistorySnapshot(
        new_meta={}, old_meta=None,
        changes={"quantum-widget": "added"}, transitions={},
        source_repos={"quantum-widget":
                      {"https://github.com/other/llama-tools"}},
    )
    assert [f["rule_id"] for f in _name_repo_divergence_findings(snapshot)] == [
        "H059"]


# --- H049: adding a source host is not moving the origin -------------------

def _host_break(old, new, key="source_hosts"):
    return PropertyBreak(key, f'"{old}"', f'"{new}"', 23, 1.0)


def test_h049_pure_source_host_addition_is_not_an_origin_move():
    assert _h049_findings([
        _host_break('["github.com"]', '["github.com", "git.proxmox.com"]')
    ]) == []


def test_h049_replacing_the_source_host_still_fires():
    findings = _h049_findings([
        _host_break('["github.com"]', '["evil.example"]')
    ])
    assert [f["rule_id"] for f in findings] == ["H049"]


# --- SOURCE_BUCKET: project-owned release hosts ----------------------------

def test_source_bucket_accepts_project_release_hosts():
    urls = [
        "https://cpan.metacpan.org/authors/id/E/ET/ETHER/ORLite-2.00.tar.gz",
        "https://download.eclipse.org/jdtls/milestones/1.63.0/x.tar.gz",
        "https://hangeul.pstatic.net/hangeul_static/webfont/zips/x.zip",
        "https://git.corbet.ch/corbet-libs/cfetch.git#tag=v0.10.3",
        "https://get.izoone.com/emqutiti/v0.8.0/x.tar.gz",
        "https://packages.domicile-desktop.com/arch/x86_64/x.pkg.tar.zst",
        "https://clever-tools.clever-cloud.com/releases/5.4.0/x.tar.gz",
        "https://kepler-static-artifacts.kepler.labcollab.net/d8/x.tar.gz",
        "https://git.gay/Veridian-Zenith/Voix/releases/download/v4.15.0",
    ]
    with shipped_config():
        buckets = classify_urls(urls)
    assert set(buckets.values()) <= {"official", "trusted_forge"}, buckets


def test_source_bucket_still_flags_unknown_hosts():
    with shipped_config():
        buckets = classify_urls([
            "https://repo.wyrd.foo/a/x.tar.gz",
            "https://evil.example/x.tar.gz",
        ])
    assert set(buckets.values()) == {"unknown"}
