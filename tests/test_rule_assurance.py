"""Explicit executable assurance for every previously implicit rule direction.

The stateful, tree and cycle rules use their native interfaces rather than
constructed report entries.  ``AUDITED_NEGATIVE_GAPS`` records the 62 rules
whose negative direction was reviewed here; all 62 have an applicable benign
or gate-closed twin, so none needed a not-applicable exemption.
"""

from __future__ import annotations

import copy
import time

import pytest

from trustsight.analysis import _structural_findings
from trustsight.analysis.artifact import inspect_manifest
from trustsight.analysis.composition import _meta_annotations
from trustsight.analysis.correlation import (
    shared_adoption_window,
    shared_fetch_target,
    shared_payload_signal,
    shared_upstream_dependency,
)
from trustsight.analysis.dependencies import _dependency_findings
from trustsight.analysis.entropy import entropy_findings
from trustsight.analysis.meta import weak_layer_span
from trustsight.analysis.pipeline import scan_diff
from trustsight.analysis.pipeline._analyze_helpers import _campaign_corroboration
from trustsight.analysis.temporal import (
    _package_is_new,
    _recent_update,
    _stale_revival,
    t_domain_findings,
    t_key_findings,
    t_key_rotation,
)
from trustsight.analysis.upstream_release import upstream_release_findings
from trustsight.changes import change_delta
from trustsight.db import init_db, record_observed_domain, record_observed_key
from trustsight.differ import extract_urls_from_diff
from trustsight.full_aur.corpus import run_corpus_sweep
from trustsight.full_aur.properties import metadata_divergence
from trustsight.ioc_baseline import IocMatch


AUDITED_NEGATIVE_GAPS = frozenset("""
A001 A002 A003 A004 A006 A007 A008 C008 C009 C010 C015 C019 C020 C025 C030
C031 E001 E002 E003 G004 G007 G012 G013 G014 H018 H019 H020 H021 H022 H027
H036 H037 H084 H089 H094 H102 H103 H104 M002 R056 S003 S004 S005 S006 S007
S008 T001 T002 T003 U001 U005 W002 W004 W005 W006 W007 X007 X010 X018 X023
X029 X032
""".split())


def _ids(diff: str, **kwargs) -> set[str]:
    return {entry.rule_id for entry in scan_diff(diff, package_name="demo", **kwargs).score_breakdown}


def _recipe(*lines: str) -> str:
    body = "".join(f"+{line}\n" for line in lines)
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
        f" pkgname=demo\n pkgver=1.0\n{body}"
    )


def _structural_ids(diff: str) -> set[str]:
    return {
        finding["rule_id"]
        for finding in _structural_findings(
            diff, extract_urls_from_diff(diff), {}, config={}, package_name="demo"
        )
    }


def _collect_entropy(diff: str, config: dict) -> set[str]:
    emitted = []
    entropy_findings(diff, config, lambda rule_id, *args, **kwargs: emitted.append(rule_id))
    return set(emitted)


class _Commit:
    def __init__(self, oid="head", commit_time=0, parents=()):
        self.id = oid
        self.commit_time = commit_time
        self.parents = list(parents)


class _Project:
    def __init__(self, records=(), walked=()):
        self.records = list(records)
        self.walked = list(walked)

    def commit_meta(self, oids):
        wanted = set(oids)
        return [record for record in self.records if record.id in wanted]

    def walk(self, head, limit=None):
        return self.walked


# --- Explicit positive behaviour -------------------------------------------


def test_c009_positive_versioned_unread_carrier_change():
    diff = (
        "-Subproject commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "+Subproject commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "-pkgver=1.0\n+pkgver=2.0\n"
    )
    assert "C009" in _structural_ids(diff)


def test_c029_positive_backup_set_gains_an_entry():
    diff = "-backup=('etc/a.conf')\n+backup=('etc/a.conf' 'etc/b.conf')\n"
    assert "C029" in _structural_ids(diff)


def test_c030_positive_epoch_removed_without_version_move():
    assert "C030" in _structural_ids("-epoch=1\n")


def test_h020_positive_native_recent_commit():
    project = _Project(records=[_Commit(commit_time=time.time() - 3600)])
    finding = _recent_update(project, "head")
    assert finding is not None and finding["rule_id"] == "H020"


def test_h021_positive_native_recent_root_commit(monkeypatch):
    monkeypatch.setattr("trustsight.analysis.temporal.get_package", lambda name: None)
    project = _Project(walked=[_Commit(commit_time=time.time() - 86400)])
    finding = _package_is_new(project, "head", "demo")
    assert finding is not None and finding["rule_id"] == "H021"


def test_h022_positive_native_stale_revival():
    now = int(time.time())
    project = _Project(records=[
        _Commit("old", now - 400 * 86400), _Commit("head", now),
    ])
    finding = _stale_revival(project, "old", "head")
    assert finding is not None and finding["rule_id"] == "H022"


def test_h027_positive_native_capability_composition():
    triggered = [
        {"rule_id": "R001", "category": "network"},
        {"rule_id": "H023", "category": "persistence"},
        {"rule_id": "C001", "category": "integrity"},
    ]
    assert "H027" in {finding["rule_id"] for finding in _meta_annotations(triggered, {})}


def test_h030_positive_native_dependency_expansion(monkeypatch):
    monkeypatch.setattr("trustsight.analysis.dependencies._rarities_of", lambda names: [1.0] * len(names))
    fired = []
    _dependency_findings(
        _recipe("depends=('rare-a' 'rare-b' 'rare-c')"), "demo", {},
        lambda rule_id, *args, **kwargs: fired.append(rule_id),
    )
    assert "H030" in fired


_NOW = 1_800_000_000


def _snapshot(names, maintainer="alice", deps=(), modified=_NOW):
    return {
        name: {
            "Name": name, "PackageBase": name, "Maintainer": maintainer,
            "Version": "1.0", "Depends": list(deps), "LastModified": modified,
        }
        for name in names
    }


def _corpus_ids(new, old, **kwargs):
    return {finding["rule_id"] for finding in run_corpus_sweep(new, old, **kwargs)}


@pytest.fixture
def corpus_thresholds(monkeypatch):
    def set_values(values):
        monkeypatch.setattr(
            "trustsight.full_aur.temporal_engine.load_thresholds", lambda: values
        )
        monkeypatch.setattr("trustsight.config.load_thresholds", lambda: values)
    return set_values


def test_h057_positive_native_transitive_adoption(corpus_thresholds):
    corpus_thresholds({"h057": {"min_hops": 2}})
    old = _snapshot(["victim", "mid", "top"])
    old["victim"]["Maintainer"] = ""
    new = copy.deepcopy(old)
    new["victim"]["Maintainer"] = "mallory"
    new["mid"]["Depends"] = ["victim"]
    new["top"]["Depends"] = ["mid"]
    assert "H057" in _corpus_ids(new, old)


def test_h060_positive_native_transitive_orphan(corpus_thresholds):
    corpus_thresholds({"h060": {"min_hops": 2}})
    old = _snapshot(["corelib", "mid", "top"])
    new = copy.deepcopy(old)
    new["corelib"]["Maintainer"] = ""
    new["mid"]["Depends"] = ["corelib"]
    new["mid"]["LastModified"] = _NOW + 1
    new["top"] = _snapshot(["top"], maintainer="carol", deps=("mid",), modified=_NOW + 2)["top"]
    assert "H060" in _corpus_ids(new, old)


def test_h061_positive_native_dependency_hub(corpus_thresholds):
    corpus_thresholds({"h061": {"min_dependents": 3}})
    old = _snapshot(["hub", "p0", "p1", "p2"])
    new = copy.deepcopy(old)
    for name in ("p0", "p1", "p2"):
        new[name]["Depends"] = ["hub"]
        new[name]["LastModified"] = _NOW + 1
    assert "H061" in _corpus_ids(new, old)


def test_h073_positive_native_introduction_rate_spike(corpus_thresholds):
    corpus_thresholds({
        "h073": {"min_history_cycles": 3, "z_score": 2.0, "min_introduced": 3}
    })
    old = _snapshot(["base"])
    new = dict(old)
    new.update(_snapshot(["n0", "n1", "n2", "n3"], maintainer="bulk"))
    history = [
        {"cycle_time": 1, "introduced": 0},
        {"cycle_time": 2, "introduced": 1},
        {"cycle_time": 3, "introduced": 0},
    ]
    assert "H073" in _corpus_ids(new, old, prior_history=history)


def test_h092_positive_native_metadata_host_divergence():
    pkgbuild = 'source=("https://good.example/pkg.tar.gz")\n'
    srcinfo = "\tsource = https://evil.example/pkg.tar.gz\n"
    assert metadata_divergence(pkgbuild, srcinfo) == ["evil.example"]


def test_m003_positive_native_unowned_composition():
    found = weak_layer_span([], None)  # keep this native module import exercised
    assert found == []
    from trustsight.analysis.meta import composition_not_owned

    fired = composition_not_owned([
        {"rule_id": "R001", "category": "network"},
        {"rule_id": "H015", "category": "context"},
    ], None)
    assert [finding["rule_id"] for finding in fired] == ["M003"]


def test_u007_positive_native_federated_upstream_match():
    repo = "github.com/owner/repo"
    diff = _recipe("pkgrel=2")
    delta = change_delta(diff, "demo")
    fired = []
    upstream_release_findings(
        diff, delta,
        lambda rule_id, name, severity, category, match, **extra: fired.append(rule_id),
        {}, "demo",
        current_text='url="https://github.com/owner/repo"\n',
        matches=[IocMatch(type="upstream_repo", value=repo, source="feed", shape="exfil")],
    )
    assert "U007" in fired


def test_w006_positive_generated_file_names_build_tree():
    diff = _recipe("build() {", '  printf "Exec=$srcdir/run\\n" > /tmp/demo.desktop', "}")
    assert "W006" in _ids(diff)


# --- Negative twins for the 62 audited gaps --------------------------------


@pytest.mark.parametrize("rule_id,manifest,declared", [
    ("A001", [{"path": "/usr/bin/tool", "setuid": True}], {"mode_intent": "documented setuid"}),
    ("A002", [{"path": "/usr/lib/systemd/system/demo.service"}], {"units": ["/usr/lib/systemd/system/demo.service"]}),
    ("A003", [{"path": "/usr/bin/demo", "links": ["libz.so.1"]}], {"depends": ["libz.so.1"]}),
    ("A004", [], {"install_text": "post_install() { :; }", "built_install_text": "post_install() { :; }"}),
    ("A006", [{"path": "/usr/bin/tool", "mode": 0o755}], None),
    ("A007", [{"path": "/usr/share/demo/policy.conf", "mode": 0o640}], None),
    ("A008", [{"path": "/usr/lib/demo/helper.o"}], None),
])
def test_artifact_negative_twins(rule_id, manifest, declared):
    assert rule_id not in {finding["rule_id"] for finding in inspect_manifest(manifest, declared)}


@pytest.mark.parametrize("rule_id,diff", [
    ("C008", "-Subproject commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n+Subproject commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n-pkgver=1\n+pkgver=2\n"),
    ("C009", "-Subproject commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n+Subproject commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"),
    ("C015", "+sha256sums=('abcdef1234567890')\n"),
    ("C019", "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgver=1\n+pkgver=2\n"),
    ("C020", "+source=('https://example.com/pkg.tar.gz')\n"),
    ("C025", "+options=('strip' 'debug')\n"),
    ("C030", "-epoch=1\n+epoch=2\n"),
])
def test_structural_negative_twins(rule_id, diff):
    assert rule_id not in _structural_ids(diff)


def test_c010_negative_text_metadata_is_not_binary():
    assert "C010" not in _ids(_recipe("pkgrel=2"))


@pytest.mark.parametrize("rule_id,body,config", [
    ("E001", "pkgver=1.0\npkgrel=2\n", {"thresholds": {"e001": {"max_ratio": 0.01}}}),
    ("E002", "pkgver=1.0\npkgrel=2\n", {"thresholds": {"e002": {"min_fraction": 0.5}}}),
    ("E003", "_alpha=1\n_beta=2\n_gamma=3\n", {"thresholds": {"e003": {"min_entropy": 0.01}}}),
])
def test_entropy_negative_twins(rule_id, body, config):
    assert rule_id not in _collect_entropy(_recipe(*body.splitlines()), config)


def test_g004_negative_one_project_is_not_a_campaign():
    records = [
        {"package": "demo", "pkgbase": "demo", "upstream_dep_additions": [("serde", "github.com")]},
        {"package": "demo-bin", "pkgbase": "demo", "upstream_dep_additions": [("serde", "github.com")]},
    ]
    assert shared_upstream_dependency(records) == []


def test_g007_negative_unrelated_package_gets_no_attribution(monkeypatch):
    monkeypatch.setattr("trustsight.db.active_campaigns", lambda: [{
        "campaign_id": "campaign", "scope": {"package_names": ["other"]},
    }])
    score, breakdown = _campaign_corroboration(0, [], "demo", [])
    assert score == 0 and breakdown == []


def _payload_records():
    return [
        {"package": "a", "maintainer": "a@x", "rules": ["R001"], "payload_urls": ["https://evil.example/x"]},
        {"package": "b", "maintainer": "b@x", "rules": ["R001"], "payload_urls": ["https://evil.example/x"]},
        {"package": "c", "maintainer": "c@x", "rules": ["R001"], "payload_urls": ["https://other.example/y"]},
    ]


def test_g012_negative_single_maintainer_is_not_cross_account():
    records = [dict(record, maintainer="same@x") for record in _payload_records()]
    assert shared_payload_signal(records) == []


def test_g013_negative_single_maintainer_is_not_cross_account():
    records = _payload_records()
    records[1]["maintainer"] = records[0]["maintainer"]
    assert shared_fetch_target(records) == []


def test_g014_negative_active_adoptions_are_not_dormant():
    records = [
        {"package": name, "maintainer": f"{name}@x", "adoption": True, "last_modified": time.time()}
        for name in ("a", "b", "c")
    ]
    assert shared_adoption_window(records) == []


@pytest.mark.parametrize("rule_id,diff", [
    ("H018", _recipe("build() {", "  make", "}")),
    ("H019", _recipe("pkgrel=2")),
    ("H036", _recipe("build() {", "  make -j2", "}")),
    ("H084", _recipe("build() {", "  make", "}")),
    ("H089", _recipe("package() {", '  install -Dm644 demo.conf "$pkgdir/etc/demo.conf"', "}")),
    ("H094", _recipe("build() {", "  make", "}")),
    ("H102", _recipe("pkgrel=2")),
    ("H104", _recipe("pkgdesc='A useful demo application'")),
    ("R056", _recipe("build() {", "  curl -o archive.tar https://example.com/archive.tar", "}")),
    ("S003", _recipe("build() {", "  dd if=input of=output bs=1M", "}")),
    ("S004", _recipe("build() {", '  shred "$srcdir/generated-secret"', "}")),
    ("S005", _recipe("package() {", '  chmod 777 "$pkgdir/usr/share/demo"', "}")),
    ("S006", _recipe("build() {", "  systemctl --version", "}")),
    ("S007", _recipe("build() {", "  make miner", "}")),
    ("S008", _recipe("build() {", "  history", "}")),
    ("U001", _recipe("pkgrel=2")),
    ("U005", "--- /dev/null\n+++ b/requirements.txt\n@@ -0,0 +1 @@\n+requests==2.32.0\n"),
    ("W002", _recipe("build() {", "  make", "}")),
    ("W004", _recipe("build() {", "  make", "}")),
    ("W005", _recipe("build() {", "  make install", "}")),
    ("W006", _recipe("build() {", '  printf "Name=demo\\n" > /tmp/demo.desktop', "}")),
    ("X010", _recipe("build() {", "  python -c 'print(1)'", "}")),
    ("X018", _recipe("build() {", "  python -c 'import os'", "}")),
    ("X023", _recipe("build() {", "  printf 'hello\\n' | cat", "}")),
    ("X032", _recipe("build() {", "  curl https://example.com/archive.tar", "}")),
])
def test_recipe_negative_twins(rule_id, diff):
    assert rule_id not in _ids(diff)


def test_h020_negative_native_old_commit():
    project = _Project(records=[_Commit(commit_time=time.time() - 96 * 3600)])
    assert _recent_update(project, "head") is None


def test_h021_negative_native_old_root_commit(monkeypatch):
    monkeypatch.setattr("trustsight.analysis.temporal.get_package", lambda name: None)
    project = _Project(walked=[_Commit(commit_time=time.time() - 40 * 86400)])
    assert _package_is_new(project, "head", "demo") is None


def test_h022_negative_native_short_revision_gap():
    now = int(time.time())
    project = _Project(records=[
        _Commit("old", now - 30 * 86400), _Commit("head", now),
    ])
    assert _stale_revival(project, "old", "head") is None


def test_h027_negative_two_categories_are_not_density():
    triggered = [
        {"rule_id": "R001", "category": "network"},
        {"rule_id": "H023", "category": "persistence"},
    ]
    assert "H027" not in {finding["rule_id"] for finding in _meta_annotations(triggered, {})}


def test_h037_negative_no_property_breaks():
    from trustsight.analysis.longitudinal import longitudinal_findings

    assert longitudinal_findings(_recipe("pkgrel=2"), "demo", [], {}) == []


def test_h103_negative_metadata_and_recipe_agree():
    from trustsight.analysis.crossfile import metadata_recipe_divergence

    text = 'pkgname=demo\nsource=("https://example.com/demo.tar.gz")\n'
    assert metadata_recipe_divergence(text, text) == []


def test_m002_negative_strong_signal_stops_weak_span_escalation():
    triggered = [
        {"rule_id": "R001", "severity": "CRITICAL", "category": "network"},
        {"rule_id": "H015", "severity": "MEDIUM", "category": "context"},
        {"rule_id": "C001", "severity": "INFO", "category": "integrity"},
    ]
    assert weak_layer_span(triggered, None) == []


def test_c031_negative_ordinary_build_does_not_rewrite_boot_images():
    assert "C031" not in _ids(_recipe("build() {", "  make", "}"))


def test_t003_negative_key_addition_is_not_rotation():
    assert t_key_rotation({"pgp_keys": {"gained": ["NEW"], "lost": []}}) == []


def test_x007_negative_single_evasion_technique_is_not_a_cluster():
    assert "X007" not in _ids(_recipe("build() {", "  ${A[0]} https://example.com", "}"))


def test_x029_negative_plain_literal_is_not_staged_encoded_material():
    assert "X029" not in _ids(_recipe("build() {", "  _note='ordinary build notes'", "}"))


def test_w007_negative_warm_dependency_index_does_not_decline(monkeypatch):
    monkeypatch.setattr("trustsight.analysis.dependencies.dependency_table_populated", lambda: True)
    assert "W007" not in _ids(_recipe("depends=('demo-lib')"))


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()


@pytest.mark.usefixtures("history_db")
def test_t001_negative_previously_observed_key():
    record_observed_key("KNOWN")
    assert t_key_findings({"pgp_keys": {"gained": ["KNOWN"]}}, None) == []


@pytest.mark.usefixtures("history_db")
def test_t002_negative_long_observed_maintainer_domain():
    record_observed_domain("known.example", observed_at="2020-01-01 00:00:00")
    assert t_domain_findings("me@known.example", None) == []


def test_audited_negative_gap_inventory_is_complete():
    assert len(AUDITED_NEGATIVE_GAPS) == 62
