"""False positives from the 2026-10-24 watcher triage.

Each case pins the benign shape that fired and the true-positive twin the
fix must keep.  The taxonomy is the triage agent's: these are *malicious*
false positives - bad rule triggers with no bad practice behind them.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.analysis.longitudinal import longitudinal_findings  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402
from trustsight.differ import extract_urls_from_diff  # noqa: E402
from trustsight.full_aur.corpus import run_corpus_sweep  # noqa: E402
from trustsight.full_aur.properties import PropertyBreak, extract_properties  # noqa: E402

NOW = 1_800_000_000


def _ids(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=current_text)
    return {e.rule_id for e in fact.score_breakdown}


@pytest.fixture
def thresholds(monkeypatch):
    def set_values(values: dict):
        monkeypatch.setattr(
            "trustsight.full_aur.temporal_engine.load_thresholds", lambda: values
        )
        monkeypatch.setattr("trustsight.config.load_thresholds", lambda: values)
    return set_values


def _meta(names, maintainer, *, base=None, modified=None):
    return {
        name: {
            "Name": name,
            "PackageBase": base or name,
            "Maintainer": maintainer,
            "LastModified": modified if modified is not None else NOW,
        }
        for name in names
    }


def _fire(rule, new, old, **kwargs):
    return [f for f in run_corpus_sweep(new, old, **kwargs)
            if f["rule_id"] == rule]


_TTF = [f"ttf-kreativekorp-lisa-{suffix}" for suffix in (
    "calc", "emptyfolders", "engelbart", "graph", "guide", "priamwhamos",
    "project", "sketch", "someacronym", "startupfrom", "terminal", "twiggy",
)]

_SQLDEF = ["mysqldef", "sqlite3def", "mssqldef", "psqldef",
           "mysqldef-bin", "sqlite3def-bin", "mssqldef-bin", "psqldef-bin"]

_HISTORY = [{"maintainer": "alice", "cycle_time": c, "activity": 1}
            for c in (1, 2, 3)]


# --- H045: a split package is one adoption, not twelve ---------------------

def test_h045_split_outputs_of_one_base_are_not_mass_adoption(thresholds):
    thresholds({"h045": {"min_packages": 5, "window_days": 7}})
    old = _meta([f"p{i}" for i in range(10)], "existing")
    new = dict(old)
    new.update(_meta(_TTF, "fbf", base="ttf-kreativekorp-lisa"))

    assert _fire("H045", new, old) == []


def test_h045_still_fires_on_distinct_bases(thresholds):
    thresholds({"h045": {"min_packages": 5, "window_days": 7}})
    old = _meta([f"p{i}" for i in range(10)], "existing")
    new = dict(old)
    new.update(_meta([f"bulk{i}" for i in range(6)], "bulk"))

    findings = _fire("H045", new, old)
    assert len(findings) == 1
    assert len(findings[0]["params"]["members"]) == 6


# --- H055: a split update is one modified base, not a burst ---------------

def test_h055_split_outputs_of_one_base_are_not_a_burst(thresholds):
    thresholds({"h055": {"min_packages": 3, "window_hours": 24}})
    old = _meta(_TTF, "alice", base="ttf-kreativekorp-lisa",
                modified=NOW - 86400)
    new = copy.deepcopy(old)
    for name in _TTF:
        new[name]["LastModified"] = NOW

    assert _fire("H055", new, old) == []


def test_h055_still_fires_on_distinct_bases(thresholds):
    thresholds({"h055": {"min_packages": 3, "window_hours": 24}})
    old = _meta([f"p{i}" for i in range(10)], "churner",
                modified=NOW - 86400 * 10)
    new = copy.deepcopy(old)
    for i in range(4):
        new[f"p{i}"]["LastModified"] = NOW

    assert len(_fire("H055", new, old)) == 1


# --- H053: canonical subdomains and the ecosystem's own distribution host --

def _added(meta, name, maintainer="alice"):
    meta = dict(meta)
    meta[name] = {"Name": name, "PackageBase": name,
                  "Maintainer": maintainer, "LastModified": NOW}
    return meta


def test_h053_accepts_a_canonical_subdomain(thresholds):
    thresholds({})
    old = _meta(["base"], "alice")
    new = _added(old, "perl-date-holidays-de")
    repos = {"perl-date-holidays-de": {
        "https://search.cpan.org/CPAN/authors/id/F/FR/FROGGS/Date-Holidays-DE-2.07.tar.gz"}}

    assert _fire("H053", new, old, source_repos=repos) == []


def test_h053_accepts_the_nodejs_distribution_host(thresholds):
    thresholds({})
    old = _meta(["base"], "alice")
    new = _added(old, "nodejs-lts-iron")
    repos = {"nodejs-lts-iron": {
        "https://nodejs.org/dist/v20.20.2/node-v20.20.2.tar.xz"}}

    assert _fire("H053", new, old, source_repos=repos) == []


def test_h053_still_fires_on_an_unrelated_host(thresholds):
    thresholds({})
    old = _meta(["base"], "alice")
    new = _added(old, "perl-date-holidays-de")
    repos = {"perl-date-holidays-de": {
        "https://evil.test/Date-Holidays-DE-2.07.tar.gz"}}

    assert len(_fire("H053", new, old, source_repos=repos)) == 1


# --- H058: bases, not package names, decide relatedness -------------------

def test_h058_split_outputs_of_one_base_are_not_a_deviation(thresholds):
    thresholds({"h058": {"min_history_cycles": 3, "z_score": 2.0,
                         "min_activity": 2}})
    old = _meta(_TTF, "alice", base="ttf-kreativekorp-lisa")
    new = copy.deepcopy(old)
    for name in _TTF:
        new[name]["LastModified"] = NOW + 1

    assert _fire("H058", new, old, maintainer_history=_HISTORY) == []


def test_h058_related_source_and_bin_bases_are_not_a_deviation(thresholds):
    thresholds({"h058": {"min_history_cycles": 3, "z_score": 2.0,
                         "min_activity": 2}})
    bases = {name: ("sqldef-bin" if name.endswith("-bin") else "sqldef")
             for name in _SQLDEF}
    old = {}
    for name in _SQLDEF:
        old[name] = {"Name": name, "PackageBase": bases[name],
                     "Maintainer": "alice", "LastModified": NOW}
    new = copy.deepcopy(old)
    for name in _SQLDEF:
        new[name]["LastModified"] = NOW + 1

    assert _fire("H058", new, old, maintainer_history=_HISTORY) == []


def test_h058_distinct_bases_still_fire(thresholds):
    thresholds({"h058": {"min_history_cycles": 3, "z_score": 2.0,
                         "min_activity": 2}})
    names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"]
    old = _meta(names, "alice")
    new = copy.deepcopy(old)
    for name in names:
        new[name]["LastModified"] = NOW + 1

    assert len(_fire("H058", new, old,
                     maintainer_history=_HISTORY)) == 1


# --- H101: a #tag= is a declared pin (P006), not a lost pin ----------------

def test_h101_tag_pin_is_not_a_lost_pin():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -5,3 +5,3 @@\n"
        " source=(\n"
        '-        "prikk::https://github.com/prikk-vcs/prikk/archive/refs/'
        'tags/0.54.1.tar.gz"\n'
        '+        "prikk::git+https://github.com/prikk-vcs/prikk.git'
        '#tag=0.54.1?signed"\n'
        " )\n"
    )
    assert "H101" not in _ids(diff)


def test_h101_still_fires_when_a_commit_pin_becomes_a_branch():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -5,3 +5,3 @@\n"
        " source=(\n"
        '-        "demo::git+https://github.com/example/demo'
        '#commit=0123456789abcdef0123456789abcdef01234567"\n'
        '+        "demo::git+https://github.com/example/demo#branch=main"\n'
        " )\n"
    )
    assert "H101" in _ids(diff)


# --- SOURCE_BUCKET: a rotating signed path token is not a new source ------

_YANDEX_A = "a" * 64
_YANDEX_B = "b" * 64
_YANDEX_TAIL = (
    "fKqInKw3d7bLFOeFnMGnhNWxCpe349obSYmly8cW7zZJ_fniSbaCrlwjQTbvB92IUPUnX"
    "itKQ2ltyzIVVtHF0RfdGUpZH039231ae3iQvySr8npumZHI4midPdWhecNq"
)
_YANDEX_QUERY = (
    "uid=0&filename=Yandex_Messenger_2.155.0_amd64.deb"
    "&disposition=attachment&fsize=73548980"
)
_YANDEX_SUM = "b22f77140bf2ee7e7c70a6ab9e96d45a3b8f568386ddcadb7e57c4e5bd6f57e9"


def _yandex_url(token: str, host: str = "downloader.disk.yandex.ru",
                path_token: str = "6adce411") -> str:
    return (
        "yandex-messenger_2.155.0_amd64.deb::https://" + host
        + f"/disk/{token}/{path_token}/{_YANDEX_TAIL}?{_YANDEX_QUERY}"
    )


def test_source_bucket_ignores_a_rotated_signed_path_token():
    old, new = _yandex_url(_YANDEX_A), _yandex_url(_YANDEX_B)
    current = f"pkgname=yandex-messenger\nb2sums=('{_YANDEX_SUM}')\nsource=(\"{new}\")\n"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            f'-source=("{old}")\n'
            f'+source=("{new}")\n')

    assert "SOURCE_BUCKET" not in _ids(diff, current_text=current)
    assert "C003" not in _ids(diff, current_text=current)


def test_source_bucket_still_fires_on_a_host_change():
    old, new = _yandex_url(_YANDEX_A), _yandex_url(_YANDEX_B, host="evil.test")
    current = f"pkgname=yandex-messenger\nb2sums=('{_YANDEX_SUM}')\nsource=(\"{new}\")\n"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            f'-source=("{old}")\n'
            f'+source=("{new}")\n')

    assert "SOURCE_BUCKET" in _ids(diff, current_text=current)


def test_source_bucket_still_fires_when_the_checksum_changes():
    old, new = _yandex_url(_YANDEX_A), _yandex_url(_YANDEX_B)
    old_sum, new_sum = "a" * 64, "b" * 64
    current = f"pkgname=yandex-messenger\nb2sums=('{new_sum}')\nsource=(\"{new}\")\n"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
            f'-source=("{old}")\n'
            f'+source=("{new}")\n'
            f"-b2sums=('{old_sum}')\n"
            f"+b2sums=('{new_sum}')\n")

    # With the checksum gone, a changed URL is exactly what must keep firing.
    assert "SOURCE_BUCKET" in _ids(diff, current_text=current)


def test_source_bucket_still_fires_when_the_version_changes_without_a_bump():
    old = _yandex_url(_YANDEX_A)
    new = old.replace("2.155.0", "2.156.0")
    current = f"pkgname=yandex-messenger\nb2sums=('{_YANDEX_SUM}')\nsource=(\"{new}\")\n"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            f'-source=("{old}")\n'
            f'+source=("{new}")\n')

    # The changed segment is a version, not a lease token: keep the finding.
    assert "SOURCE_BUCKET" in _ids(diff, current_text=current)


# --- source extraction reads the recipe, not committed prose ---------------

def test_url_in_a_non_metadata_file_is_not_a_source():
    diff = ("--- /dev/null\n+++ b/LICENSE-NHIICC\n@@ -0,0 +1,2 @@\n"
            "+Distributed free of charge from\n"
            "+https://cloudicweb.nhi.gov.tw/cloudic/system/SMC/Eventesting.aspx\n")

    changes = extract_urls_from_diff(diff)
    assert changes.added_urls == []


def test_a_respelled_unchanged_source_is_not_added():
    url = "https://e.example/pkg.zip"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
            f'-source=("pkg-1.0.zip"::"{url}")\n'
            f'+source=("pkg-${{pkgver}}.zip::{url}")\n')

    changes = extract_urls_from_diff(diff)
    assert changes.added_urls == []
    assert changes.removed_urls == []


def test_documentation_source_does_not_score():
    a = "a" * 64
    url = "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1f/LICENSE"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            f"+source=('OPENSSL-LICENSE::{url}')\n"
            f"+sha256sums=('{a}')\n")
    current = (f"pkgname=p\nsource=('OPENSSL-LICENSE::{url}')\n"
               f"sha256sums=('{a}')\n")

    ids = _ids(diff, current_text=current)
    assert "SOURCE_BUCKET" not in ids
    assert "NOVELTY" not in ids


def test_documentation_source_is_not_a_source_host():
    text = (
        "pkgname=p\n"
        "source=('https://example.org/p-1.0.tar.gz'\n"
        "        'OPENSSL-LICENSE::https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1f/LICENSE')\n"
    )
    props = extract_properties(text)
    # Exact set equality: the documentation source contributes no host.
    assert props["source_hosts"] == frozenset({"example.org"})


# --- D003: a VCS client is not a new network reach -------------------------

def test_d003_ignores_git_for_a_vcs_source():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
            " pkgname=p\n"
            "+source=('git+https://github.com/example/p.git')\n"
            "+makedepends=('git')\n")
    current = ("pkgname=p\nsource=('git+https://github.com/example/p.git')\n"
               "makedepends=('git')\n")

    assert "D003" not in _ids(diff, current_text=current)


def test_d003_still_fires_on_a_fetch_tool_without_a_vcs_source():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            "+makedepends=('curl')\n")
    current = "pkgname=p\nmakedepends=('curl')\n"

    assert "D003" in _ids(diff, current_text=current)


# --- H051/H054: a declared version move explains the change ----------------

def _break(key, old, new, stable=20):
    return PropertyBreak(key=key, old_value=old, new_value=new,
                         stable_for_n=stable, weight=1.0)


def test_h051_stands_down_when_the_version_moved():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            "-pkgver=1.0\n+pkgver=1.1\n")
    found = longitudinal_findings(
        diff, "p", [_break("pkgdesc_tokens", '{"old"}', '{"new"}')], {})
    assert not [f for f in found if f["rule_id"] == "H051"]


def test_h051_still_fires_without_a_version_move():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            "-pkgdesc=old\n+pkgdesc=new\n")
    found = longitudinal_findings(
        diff, "p", [_break("pkgdesc_tokens", '{"old"}', '{"new"}')], {})
    assert [f for f in found if f["rule_id"] == "H051"]


def test_h054_stands_down_when_the_version_moved():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            "-pkgver=1.0\n+pkgver=1.1\n")
    found = longitudinal_findings(
        diff, "p", [_break("build_line_count", "6-15", "0-5")], {})
    assert not [f for f in found if f["rule_id"] == "H054"]


def test_h054_still_fires_without_a_version_move():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            "-build() {\n+build() { :; }\n")
    found = longitudinal_findings(
        diff, "p", [_break("build_line_count", "6-15", "0-5")], {})
    assert [f for f in found if f["rule_id"] == "H054"]


def test_an_unchanged_url_is_kept_when_the_checksum_is_weakened():
    url = "https://github.com/trusted/project/archive/v1.0.0.tar.gz"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
            f'-source=("{url}")\n'
            f'+source=("{url}")\n'
            "-sha256sums=('" + "a" * 64 + "')\n"
            "+sha256sums=('SKIP')\n")

    changes = extract_urls_from_diff(diff)
    assert url in changes.added_urls
