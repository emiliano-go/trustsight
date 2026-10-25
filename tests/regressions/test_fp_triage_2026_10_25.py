"""False positives from the 2026-10-25 watcher batch.

Each case pins the false positive and its true-positive twin, per the
false-positive workflow: a fix that merely stops firing is not a fix.
"""

import sys
import difflib
import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.analysis.correlation import shared_gained_host  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402
from trustsight.full_aur.pipeline import CycleResult  # noqa: E402
from trustsight.notify import alert_payload  # noqa: E402


def _ids(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(), package_name="p",
            current_text=current_text,
        )
    return {e.rule_id for e in fact.score_breakdown}


def _diff(old, new):
    return "".join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True),
        "a/PKGBUILD", "b/PKGBUILD", n=3,
    ))


# ---------------------------------------------------------------------------
# C004 - pi-hole-core removed local sources with their checksums
# ---------------------------------------------------------------------------

def test_c004_a_dollar_prefixed_local_source_removed_with_its_sum_is_quiet():
    old = "\n".join([
        "pkgname=pi-hole-core", "pkgver=6.5", "pkgrel=1",
        "source=(pi-hole.tar.gz $_pkgname-logtruncate.service "
        "$_pkgname-logtruncate.timer pihole.sudo)",
        "sha256sums=('a'", "            'b'", "            'c'",
        "            'd')", "",
    ])
    new = "\n".join([
        "pkgname=pi-hole-core", "pkgver=6.5", "pkgrel=2",
        "source=(pi-hole.tar.gz)",
        "sha256sums=('a')", "",
    ])
    assert "C004" not in _ids(_diff(old, new), current_text=new)


def test_c004_a_checksum_removed_while_its_source_stays_still_fires():
    old = "\n".join([
        "pkgname=p", "pkgver=1", "pkgrel=1",
        "source=(a.tar.gz b.patch)",
        "sha256sums=('a'", "            'b'", "            'c'",
        "            'd')", "",
    ])
    new = "\n".join([
        "pkgname=p", "pkgver=1", "pkgrel=2",
        "source=(a.tar.gz b.patch)",
        "sha256sums=('a'", "            'b')", "",
    ])
    assert "C004" in _ids(_diff(old, new), current_text=new)


# ---------------------------------------------------------------------------
# H067 - systemd-detect-virt --chroot is a udev guard, not an analysis probe
# ---------------------------------------------------------------------------

def _shipped_ids(lines, fn="build"):
    with shipped_config():
        fact = scan_diff(
            "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,9 @@\n"
            + f"pkgname=p\npkgver=1\npkgrel=1\n+{fn}() {{\n"
            + "".join(f"+{line}\n" for line in lines)
            + "+}\n",
            rules=load_rules(), config=load_config(), package_name="p",
        )
    return {e.rule_id for e in fact.score_breakdown}


def test_h067_a_udev_chroot_guard_is_quiet():
    assert "H067" not in _shipped_ids([
        'if systemd-detect-virt --chroot --quiet; then :; fi',
    ], fn="package")


def test_h067_a_virtualization_probe_still_fires():
    assert "H067" in _shipped_ids(["systemd-detect-virt -q"], fn="build")


# ---------------------------------------------------------------------------
# X024 - CMAKE_PREFIX_PATH is build plumbing, not a loader path
# ---------------------------------------------------------------------------

def test_x024_cmake_prefix_path_is_quiet():
    assert "X024" not in _shipped_ids([
        'cmake -DCMAKE_PREFIX_PATH="$PWD/w/install" .',
    ])


def test_x024_ld_library_path_still_fires():
    assert "X024" in _shipped_ids([
        'export LD_LIBRARY_PATH="$PWD/lib"',
    ])


# ---------------------------------------------------------------------------
# H085 - a directory the recipe creates is declared
# ---------------------------------------------------------------------------

def test_h085_a_recipe_created_bin_dir_is_quiet():
    assert "H085" not in _shipped_ids([
        'mkdir -p "$srcdir/bin"',
        'export PATH="$srcdir/bin:$PATH"',
    ])


def test_h085_an_undeclared_build_tree_dir_still_fires():
    assert "H085" in _shipped_ids([
        'export PATH="$srcdir/evil:$PATH"',
    ])


# ---------------------------------------------------------------------------
# G001 - one maintainer's family is a batch, not a shared-host campaign
# ---------------------------------------------------------------------------

def _host_records(*maintainers):
    return [
        {"package": f"firefox-nightly-i18n-{lang}", "pkgbase": f"i18n-{lang}",
         "maintainer": maintainer, "hosts_gained": ["i18n.example"]}
        for lang, maintainer in zip(("pl", "de", "fr"), maintainers)
    ]


def test_g001_one_maintainers_family_is_quiet():
    assert shared_gained_host(_host_records("Sving1024", "Sving1024",
                                            "Sving1024"), 3) == []


def test_g001_two_maintainers_still_fire():
    found = shared_gained_host(_host_records("Sving1024", "other",
                                             "Sving1024"), 3)
    assert [f["rule_id"] for f in found] == ["G001"]


# ---------------------------------------------------------------------------
# G010 - a first-seen-host census never becomes the notification headline
# ---------------------------------------------------------------------------

def test_g010_does_not_headline_a_census():
    cycle = CycleResult(
        cluster_findings=[{
            "rule_id": "G010", "severity": "INFO",
            "match": "first-seen host cdn.example gained by 3 packages in the window",
            "params": {"members": ["a", "b", "c"], "host": "cdn.example"},
        }],
        over_threshold=[("sfptool-bin", 50)],
        detail={"sfptool-bin": {"score": 50, "rules": ["C005"],
                                "findings": [{"rule_id": "C005", "weight": 15,
                                              "reason": "unknown bucket"}]}},
    )
    payload = alert_payload(cycle)
    assert "Campaign across" not in payload["title"]
    assert payload["title"].startswith("TrustSight: sfptool-bin scored 50")
    assert [c["rule_id"] for c in payload["campaign_cluster"]] == ["G010"]
    cluster = payload["campaign_cluster"][0]
    assert cluster["host"] == "cdn.example"
    assert cluster["match"] == "first-seen host cdn.example gained by 3 packages in the window"


# ---------------------------------------------------------------------------
# zenworks - file collisions and notice-only hooks are not hijacks
# ---------------------------------------------------------------------------


def _zenworks_entries(field, monkeypatch):
    monkeypatch.setattr(
        "trustsight.analysis.dependencies.is_established_package",
        lambda name: name == "zen-browser",
    )
    monkeypatch.setattr(
        "trustsight.analysis.dependencies.dependency_observation_count",
        lambda name: 0,
    )
    old = "pkgname=zenworks\npkgver=0.0.5\npkgrel=1\n"
    new = old + f"{field}=('zen-browser')\n"
    with shipped_config():
        return scan_diff(
            _diff(old, new), rules=load_rules(), config=load_config(),
            package_name="zenworks", current_text=new,
        ).score_breakdown


def test_zenworks_conflict_is_unscored_and_does_not_compose(monkeypatch):
    entries = _zenworks_entries("conflicts", monkeypatch)
    by_id = {entry.rule_id: entry for entry in entries}
    assert "D004" not in by_id
    assert "H098" not in by_id
    assert by_id["H064"].severity == "INFO"
    assert by_id["H064"].weight == 0


def test_zenworks_provides_claim_still_composes(monkeypatch):
    from trustsight.analysis.composition import naming_cluster_annotation

    entries = _zenworks_entries("provides", monkeypatch)
    by_id = {entry.rule_id: entry for entry in entries}
    assert {"D004", "H064"} <= set(by_id)
    assert by_id["H064"].weight > 0
    annotation = naming_cluster_annotation(
        [{"rule_id": rule_id} for rule_id in by_id], load_config())
    assert annotation["rule_id"] == "H098"


def _install_change(command):
    return (
        "--- a/zenworks.install\n+++ b/zenworks.install\n"
        "@@ -1,3 +1,4 @@\n"
        " post_upgrade() {\n"
        "   echo old\n"
        f"+  {command}\n"
        " }\n"
    )


def test_notice_only_install_change_has_no_r007():
    assert "R007" not in _ids(_install_change("echo new"))


def test_behavioral_install_change_keeps_r007():
    assert "R007" in _ids(_install_change("chmod u+s /usr/bin/zen"))


# ---------------------------------------------------------------------------
# H049 - source_orgs on a non-forge host is a directory, not an owner
# ---------------------------------------------------------------------------

def test_h049_org_extraction_is_forge_only_and_case_normalised():
    from trustsight.full_aur.properties import _extract_host_org

    hosts: set[str] = set()
    orgs: set[str] = set()
    _extract_host_org("https://www.heidisql.com/builds/a.exe", hosts, orgs)
    assert hosts == {"www.heidisql.com"}
    assert orgs == set()
    _extract_host_org("https://github.com/Ceereals/whispy/a.tar.gz", hosts, orgs)
    assert "github.com/ceereals" in orgs


def _break(key, old, new):
    from trustsight.full_aur.properties import PropertyBreak

    return PropertyBreak(key=key, old_value=json.dumps(sorted(old)),
                         new_value=json.dumps(sorted(new)),
                         stable_for_n=20, weight=15)


def test_h049_a_subset_org_change_is_a_representation_change():
    from trustsight.analysis.longitudinal import _h049_findings

    assert _h049_findings([
        _break("source_orgs", {"github.com/a", "x/builds"}, {"github.com/a"}),
    ]) == []


def test_h049_an_owner_or_host_change_still_fires():
    from trustsight.analysis.longitudinal import _h049_findings

    assert _h049_findings([
        _break("source_orgs", {"github.com/a"}, {"github.com/b"}),
    ])
    assert _h049_findings([
        _break("source_hosts", {"a.example"}, {"b.example"}),
    ])


# ---------------------------------------------------------------------------
# H097 - a scriptlet helper is not makepkg function shadowing
# ---------------------------------------------------------------------------

def test_h097_a_helper_in_an_install_scriptlet_is_quiet():
    install = (
        "--- /dev/null\n+++ b/foo.install\n@@ -0,0 +1,3 @@\n"
        "+msg() {\n+  :\n+}\n"
    )
    assert "H097" not in _ids(install)


def test_h097_a_helper_in_the_pkgbuild_still_fires():
    pkgbuild = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
        " pkgname=p\n pkgver=1\n pkgrel=1\n+msg() { :; }\n"
    )
    assert "H097" in _ids(pkgbuild)
