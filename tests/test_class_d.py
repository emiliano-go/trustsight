"""Phase 6 - Class D corpus sweep tests (R092/R100/R105/R125).

Covers the corpus.py detectors, the cycle_events adoption feed plumbing in
db.py, the threshold/template registrations, and the pipeline wiring.
"""

import copy

import pytest

from trustsight.config import DEFAULT_THRESHOLDS
from trustsight.db import (
    init_db,
    introduction_rate_history,
    latest_cycle_time,
    record_cycle_events,
)
from trustsight.findings import TEMPLATES
from trustsight.full_aur.corpus import (
    run_corpus_sweep,
    source_repos_from_pkgbuild,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


@pytest.fixture
def thresholds(monkeypatch):
    """Pin corpus thresholds to small values so tests need small clusters."""
    def set_values(values: dict):
        monkeypatch.setattr(
            "trustsight.full_aur.corpus.load_thresholds", lambda: values
        )
        monkeypatch.setattr(
            "trustsight.config.load_thresholds", lambda: values
        )
    return set_values


NOW = 1_800_000_000


def _meta(names, maintainer, modified=None, package_base=None):
    out = {}
    for i, name in enumerate(names):
        out[name] = {
            "Name": name,
            "PackageBase": package_base or name,
            "Maintainer": maintainer,
            "LastModified": (modified if modified is not None else NOW - i),
        }
    return out


def _fire(rule, new, old, **kwargs):
    return [f for f in run_corpus_sweep(new, old, **kwargs) if f["rule_id"] == rule]


# --- no-baseline gate -------------------------------------------------------


def test_no_baseline_is_silent(thresholds):
    thresholds({})
    new = _meta([f"p{i}" for i in range(20)], "bulk", modified=NOW)
    assert run_corpus_sweep(new, None) == []


def test_all_rules_quiet_when_nothing_changed():
    old = _meta([f"p{i}" for i in range(5)], "a")
    new = dict(old)
    assert run_corpus_sweep(new, old) == []


# --- R092 mass adoption ------------------------------------------------------


def test_r092_fires_on_mass_adoption(thresholds):
    thresholds({"r092": {"min_packages": 5, "window_days": 7}})
    old = _meta([f"p{i}" for i in range(10)], "existing")
    new = dict(old)
    new.update(_meta([f"bulk{i}" for i in range(6)], "bulk", modified=NOW))
    findings = _fire("R092", new, old)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["params"]["maintainer"] == "bulk"
    assert len(findings[0]["params"]["members"]) == 6


def test_r092_below_min_packages_is_quiet(thresholds):
    thresholds({"r092": {"min_packages": 5, "window_days": 7}})
    old = _meta([f"p{i}" for i in range(10)], "existing")
    new = dict(old)
    new.update(_meta([f"bulk{i}" for i in range(4)], "bulk", modified=NOW))
    assert _fire("R092", new, old) == []


def test_r092_ignores_maintainerless_additions(thresholds):
    thresholds({"r092": {"min_packages": 2, "window_days": 7}})
    old = _meta([f"p{i}" for i in range(5)], "existing")
    new = dict(old)
    for i in range(3):
        new[f"anon{i}"] = {"Name": f"anon{i}", "PackageBase": f"anon{i}",
                           "Maintainer": "", "LastModified": NOW}
    assert _fire("R092", new, old) == []


# --- R105 attribute burst ----------------------------------------------------


def test_r105_fires_on_modification_burst(thresholds):
    thresholds({"r105": {"min_packages": 3, "window_hours": 24}})
    old = _meta([f"p{i}" for i in range(10)], "churner", modified=NOW - 86400 * 10)
    new = dict(old)
    new.update(_meta([f"p{i}" for i in range(4)], "churner", modified=NOW))
    findings = _fire("R105", new, old)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert len(findings[0]["params"]["members"]) == 4


def test_r105_ignores_additions(thresholds):
    thresholds({"r105": {"min_packages": 3, "window_hours": 24}})
    old = _meta([f"p{i}" for i in range(5)], "existing")
    new = dict(old)
    new.update(_meta([f"bulk{i}" for i in range(5)], "bulk", modified=NOW))
    assert _fire("R105", new, old) == []


def test_r105_burst_outside_window_is_quiet(thresholds):
    thresholds({"r105": {"min_packages": 3, "window_hours": 24}})
    old = _meta([f"p{i}" for i in range(10)], "slow")
    new = dict(old)
    for i in range(4):
        new[f"p{i}"]["LastModified"] = NOW - i * 86400 * 5
    assert _fire("R105", new, old) == []


# --- R100 shared source repo cluster ----------------------------------------


def test_r100_fires_on_shared_repo(thresholds):
    thresholds({"r100": {"min_packages": 3}})
    old = _meta([f"p{i}" for i in range(10)], "existing")
    new = dict(old)
    new.update(_meta([f"x{i}" for i in range(3)], "a", modified=NOW))
    shared = {"https://github.com/acme/tool", "https://github.com/acme/tool.git"}
    repos = {f"x{i}": set(shared) for i in range(3)}
    findings = _fire("R100", new, old, source_repos=repos)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "https://github.com/acme/tool" in findings[0]["params"]["repo"]
    assert len(findings[0]["params"]["members"]) == 3


def test_r100_split_packages_do_not_fire(thresholds):
    thresholds({"r100": {"min_packages": 3}})
    old = _meta([f"p{i}" for i in range(5)], "existing")
    new = dict(old)
    # three packages, all part of one package base
    new.update(_meta([f"x{i}" for i in range(3)], "a", modified=NOW,
                     package_base="xbase"))
    repos = {f"x{i}": {"https://github.com/acme/tool"} for i in range(3)}
    assert _fire("R100", new, old, source_repos=repos) == []


def test_r100_below_min_packages_is_quiet(thresholds):
    thresholds({"r100": {"min_packages": 3}})
    old = _meta([f"p{i}" for i in range(5)], "existing")
    new = dict(old)
    new.update(_meta([f"x{i}" for i in range(2)], "a", modified=NOW))
    repos = {f"x{i}": {"https://github.com/acme/tool"} for i in range(2)}
    assert _fire("R100", new, old, source_repos=repos) == []


# --- R125 introduction-rate deviation ---------------------------------------


def _additions(count, maintainer="bulk"):
    return _meta([f"n{i}" for i in range(count)], maintainer, modified=NOW)


def test_r125_fires_on_rate_spike(thresholds):
    thresholds({"r125": {"min_history_cycles": 3, "z_score": 2.0, "min_introduced": 3}})
    old = _meta([f"p{i}" for i in range(10)], "existing")
    new = dict(old)
    new.update(_additions(20))
    history = [{"cycle_time": 1, "introduced": 2},
               {"cycle_time": 2, "introduced": 3},
               {"cycle_time": 3, "introduced": 2}]
    findings = _fire("R125", new, old, prior_history=history)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert len(findings[0]["params"]["members"]) == 20
    assert findings[0]["params"]["introduced"] == 20


def test_r125_immature_history_is_quiet(thresholds):
    thresholds({"r125": {"min_history_cycles": 3, "z_score": 2.0, "min_introduced": 3}})
    old = _meta([f"p{i}" for i in range(5)], "existing")
    new = dict(old)
    new.update(_additions(20))
    history = [{"cycle_time": 1, "introduced": 2},
               {"cycle_time": 2, "introduced": 3}]
    assert _fire("R125", new, old, prior_history=history) == []


def test_r125_below_z_score_is_quiet(thresholds):
    thresholds({"r125": {"min_history_cycles": 3, "z_score": 5.0, "min_introduced": 3}})
    old = _meta([f"p{i}" for i in range(10)], "existing")
    new = dict(old)
    new.update(_additions(20))
    history = [{"cycle_time": 1, "introduced": 18},
               {"cycle_time": 2, "introduced": 21},
               {"cycle_time": 3, "introduced": 19}]
    assert _fire("R125", new, old, prior_history=history) == []


def test_r125_quiet_cycle_is_quiet(thresholds):
    thresholds({"r125": {"min_history_cycles": 3, "z_score": 2.0, "min_introduced": 3}})
    old = _meta([f"p{i}" for i in range(10)], "existing")
    new = dict(old)  # no additions at all
    history = [{"cycle_time": 1, "introduced": 2},
               {"cycle_time": 2, "introduced": 3},
               {"cycle_time": 3, "introduced": 2}]
    assert _fire("R125", new, old, prior_history=history) == []


# --- source URL extraction ---------------------------------------------------


def test_source_repos_from_pkgbuild_extracts_normalized_urls():
    text = (
        "source=(\n"
        "  'https://github.com/acme/tool/archive/v2.0.0.tar.gz'\n"
        "  'https://example.com/downloads/pkg-1.2.3.tgz'\n"
        ")\n"
    )
    repos = source_repos_from_pkgbuild(text)
    assert "https://github.com/acme/tool/archive/v0.tar.gz" in repos
    assert "https://example.com/downloads/pkg-0.tgz" in repos  # version-stripped
    assert "https://github.com/acme/tool/archive/v2.0.0.tar.gz" not in repos


def test_source_repos_from_pkgbuild_empty():
    assert source_repos_from_pkgbuild(None) == set()
    assert source_repos_from_pkgbuild("") == set()


# --- cycle_events adoption feed ----------------------------------------------


def test_cycle_feed_round_trip(db):
    assert latest_cycle_time() == 0
    assert introduction_rate_history() == []
    record_cycle_events([
        {"package_name": "a", "cycle_time": 1, "status": "added",
         "maintainer": "m", "last_modified": NOW},
        {"package_name": "b", "cycle_time": 1, "status": "modified",
         "maintainer": "m", "last_modified": NOW},
    ])
    assert latest_cycle_time() == 1
    history = introduction_rate_history()
    assert len(history) == 1
    assert history[0]["introduced"] == 1


def test_cycle_feed_replay_does_not_duplicate(db):
    events = [
        {"package_name": "a", "cycle_time": 1, "status": "added",
         "maintainer": "m", "last_modified": NOW},
    ]
    record_cycle_events(events)
    record_cycle_events(events)
    assert introduction_rate_history() == [{"cycle_time": 1, "introduced": 1}]


def test_cycle_feed_empty_is_noop(db):
    record_cycle_events([])
    assert latest_cycle_time() == 0


# --- registrations ------------------------------------------------------------


def test_class_d_thresholds_registered():
    for rule in ("r092", "r100", "r105", "r125", "r126", "r107", "r111", "r112", "r108"):
        assert f"[{rule}]" in DEFAULT_THRESHOLDS


def test_class_d_templates_registered():
    for rule in ("R092", "R100", "R105", "R125", "R090", "R126", "R093",
                 "R101", "R107", "R108", "R110", "R111", "R112"):
        assert rule in TEMPLATES


# --- helpers for the identity / consensus / graph rules ----------------------


def _snapshot(names, maintainer, version="1.0", deps=(), modified=None):
    out = {}
    for i, name in enumerate(names):
        out[name] = {
            "Name": name,
            "PackageBase": name,
            "Maintainer": maintainer,
            "Version": version,
            "Depends": list(deps),
            "LastModified": (modified if modified is not None else NOW - i),
        }
    return out


# --- R090 ownership transition -----------------------------------------------


def test_r090_fires_on_maintainer_transition(thresholds):
    thresholds({})
    old = _snapshot(["pkg"], "alice")
    new = copy.deepcopy(old)
    new["pkg"]["Maintainer"] = "mallory"
    new["pkg"]["LastModified"] = NOW + 1
    findings = _fire("R090", new, old)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["params"]["new"] == "mallory"


def test_r090_added_packages_are_not_transitions(thresholds):
    thresholds({})
    old = _snapshot(["pkg"], "alice")
    new = copy.deepcopy(old)
    new["brandnew"] = _snapshot(["brandnew"], "mallory")["brandnew"]
    assert _fire("R090", new, old) == []


def test_r090_same_maintainer_is_quiet(thresholds):
    thresholds({})
    old = _snapshot(["pkg"], "alice")
    new = copy.deepcopy(old)
    new["pkg"]["Version"] = "2.0"
    new["pkg"]["LastModified"] = NOW + 1
    assert _fire("R090", new, old) == []


def test_r071_ships_with_r090_for_an_unseen_maintainer(thresholds):
    """Plan §8: an ownership transition to an account the previous snapshot
    never saw carries R071 as well as R090."""
    thresholds({})
    old = _snapshot(["pkg", "other"], "alice")
    new = copy.deepcopy(old)
    new["pkg"]["Maintainer"] = "mallory"
    new["pkg"]["LastModified"] = NOW + 1
    fired = {f["rule_id"] for f in run_corpus_sweep(new, old)}
    assert {"R090", "R071"} <= fired
    r071 = _fire("R071", new, old)[0]
    assert r071["severity"] == "HIGH"
    assert r071["params"]["members"] == ["pkg"]
    assert r071["params"]["current_maintainer"] == "mallory"


def test_r071_quiet_when_the_new_maintainer_already_maintains_something(thresholds):
    """A handover between established packagers is R090 alone."""
    thresholds({})
    old = _snapshot(["pkg", "other"], "alice")
    old["other"]["Maintainer"] = "bob"
    new = copy.deepcopy(old)
    new["pkg"]["Maintainer"] = "bob"
    new["pkg"]["LastModified"] = NOW + 1
    fired = {f["rule_id"] for f in run_corpus_sweep(new, old)}
    assert "R090" in fired
    assert "R071" not in fired


def test_r071_quiet_on_abandonment(thresholds):
    """A move to an empty maintainer is orphan state, not a takeover."""
    thresholds({})
    old = _snapshot(["pkg"], "alice")
    new = copy.deepcopy(old)
    new["pkg"]["Maintainer"] = ""
    assert _fire("R071", new, old) == []


def test_r071_silent_without_a_baseline(thresholds):
    thresholds({})
    new = _snapshot(["pkg"], "mallory")
    assert run_corpus_sweep(new, None) == []


# --- R126 adopt-then-modify ---------------------------------------------------


def test_r126_fires_on_adopt_plus_immediate_modify(thresholds):
    thresholds({"r126": {"window_days": 14}})
    old = _snapshot(["pkg"], "alice", version="1.0")
    new = copy.deepcopy(old)
    new["pkg"]["Maintainer"] = "mallory"
    new["pkg"]["Version"] = "2.0"
    new["pkg"]["LastModified"] = NOW
    findings = _fire("R126", new, old, now=NOW)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["params"]["maintainer"] == "mallory"


def test_r126_adoption_without_version_change_is_quiet(thresholds):
    thresholds({"r126": {"window_days": 14}})
    old = _snapshot(["pkg"], "alice", version="1.0")
    new = copy.deepcopy(old)
    new["pkg"]["Maintainer"] = "mallory"
    new["pkg"]["LastModified"] = NOW
    assert _fire("R126", new, old, now=NOW) == []


def test_r126_stale_modify_outside_window_is_quiet(thresholds):
    thresholds({"r126": {"window_days": 1}})
    old = _snapshot(["pkg"], "alice", version="1.0")
    new = copy.deepcopy(old)
    new["pkg"]["Maintainer"] = "mallory"
    new["pkg"]["Version"] = "2.0"
    new["pkg"]["LastModified"] = NOW - 2 * 86400
    assert _fire("R126", new, old, now=NOW) == []


def test_r126_fires_on_the_first_package_of_a_replayed_campaign(thresholds):
    """Plan §10: R126 must fire on package *one* of a campaign timeline.

    A campaign is only recognisable as one by its third or fourth package;
    the whole point of R126 is that the shape - adopt a package, change it
    immediately - is already present in the first, before any pattern the
    later rules key on (mass adoption, a shared host, a known payload)
    exists to be seen.
    """
    thresholds({"r126": {"window_days": 14}, "r092": {"cluster_size": 3}})
    timeline = ["pkg-one", "pkg-two", "pkg-three", "pkg-four"]
    state = _snapshot(timeline, "alice", version="1.0")
    fired_at: list[str] = []

    for step, name in enumerate(timeline):
        old = copy.deepcopy(state)
        state[name]["Maintainer"] = "mallory"
        state[name]["Version"] = "2.0"
        state[name]["LastModified"] = NOW + step
        findings = _fire("R126", state, old, now=NOW + step)
        if findings:
            fired_at.extend(findings[0]["params"]["members"])

    assert fired_at[0] == "pkg-one"
    assert fired_at == timeline


# --- R093 orphan/adoption dependency ------------------------------------------


def test_r093_fires_on_dep_adopted_this_cycle(thresholds):
    thresholds({})
    old = _snapshot(["dep", "leaf"], "alice")
    new = copy.deepcopy(old)
    new["dep"]["Maintainer"] = "mallory"
    new["dep"]["LastModified"] = NOW + 1
    new["leaf"]["Depends"] = ["dep"]
    new["leaf"]["LastModified"] = NOW + 1
    findings = _fire("R093", new, old)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["params"]["dep"] == "dep"


def test_r093_fires_on_dep_orphaned_this_cycle(thresholds):
    thresholds({})
    old = _snapshot(["dep", "leaf"], "alice")
    new = copy.deepcopy(old)
    new["dep"]["Maintainer"] = ""
    new["dep"]["LastModified"] = NOW + 1
    new["leaf"]["Depends"] = ["dep"]
    new["leaf"]["LastModified"] = NOW + 1
    findings = _fire("R093", new, old)
    assert len(findings) == 1
    assert "orphaned" in findings[0]["match"]


def test_r093_longstanding_orphan_dep_is_quiet(thresholds):
    thresholds({})
    old = _snapshot(["dep", "leaf"], "alice")
    old["dep"]["Maintainer"] = ""
    new = copy.deepcopy(old)
    new["leaf"]["Depends"] = ["dep"]
    new["leaf"]["LastModified"] = NOW + 1
    assert _fire("R093", new, old) == []


# --- R107 / R111 transitive rules ---------------------------------------------


def test_r107_fires_on_adopted_from_orphan_in_closure(thresholds):
    thresholds({"r107": {"min_hops": 2}})
    old = _snapshot(["victim", "mid", "top"], "alice")
    old["victim"]["Maintainer"] = ""
    new = copy.deepcopy(old)
    new["victim"]["Maintainer"] = "mallory"  # adopted from orphan
    new["victim"]["LastModified"] = NOW + 1
    new["mid"]["Depends"] = ["victim"]
    new["mid"]["LastModified"] = NOW + 1
    new["top"] = _snapshot(["top"], "carol", deps=("mid",), modified=NOW + 2)["top"]
    findings = _fire("R107", new, old)
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["params"]["dep"] == "victim"
    assert findings[0]["params"]["distance"] == 2


def test_r107_direct_adoption_is_quiet(thresholds):
    thresholds({"r107": {"min_hops": 2}})
    old = _snapshot(["victim", "leaf"], "alice")
    old["victim"]["Maintainer"] = ""
    new = copy.deepcopy(old)
    new["victim"]["Maintainer"] = "mallory"
    new["victim"]["LastModified"] = NOW + 1
    new["leaf"]["Depends"] = ["victim"]  # only 1 hop away
    new["leaf"]["LastModified"] = NOW + 1
    assert _fire("R107", new, old) == []


def test_r111_fires_on_transitive_orphan(thresholds):
    thresholds({"r111": {"min_hops": 2}})
    old = _snapshot(["corelib", "mid", "top"], "alice")
    new = copy.deepcopy(old)
    new["corelib"]["Maintainer"] = ""  # orphaned (static)
    new["mid"]["Depends"] = ["corelib"]
    new["mid"]["LastModified"] = NOW + 1
    new["top"] = _snapshot(["top"], "carol", deps=("mid",), modified=NOW + 2)["top"]
    findings = _fire("R111", new, old)
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["params"]["dep"] == "corelib"


# --- R112 centrality -----------------------------------------------------------


def test_r112_fires_on_dependency_hub(thresholds):
    thresholds({"r112": {"min_dependents": 3}})
    old = _snapshot(["hub", "p0", "p1", "p2"], "alice")
    new = copy.deepcopy(old)
    for i in range(3):
        new[f"p{i}"]["Depends"] = ["hub"]
        new[f"p{i}"]["LastModified"] = NOW + 1
    findings = _fire("R112", new, old)
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["params"]["members"] == ["hub"]
    assert findings[0]["params"]["dependents"] == 3


def test_r112_below_threshold_is_quiet(thresholds):
    thresholds({"r112": {"min_dependents": 3}})
    old = _snapshot(["hub", "p0", "p1"], "alice")
    new = copy.deepcopy(old)
    for i in range(2):
        new[f"p{i}"]["Depends"] = ["hub"]
        new[f"p{i}"]["LastModified"] = NOW + 1
    assert _fire("R112", new, old) == []


# --- R101 name-token / host consensus -----------------------------------------


def test_r101_fires_on_ecosystem_host_divergence(thresholds):
    thresholds({})
    old = _snapshot(["base"], "alice")
    new = copy.deepcopy(old)
    new["python-evil"] = _snapshot(["python-evil"], "mallory")["python-evil"]
    findings = _fire("R101", new, old,
                     source_repos={"python-evil": {"https://evil.example/x"}})
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["params"]["prefix"] == "python"


def test_r101_python_on_pypi_or_forge_is_quiet(thresholds):
    thresholds({})
    old = _snapshot(["base"], "alice")
    new = copy.deepcopy(old)
    new["python-requests"] = _snapshot(["python-requests"], "alice")["python-requests"]
    for repo in ("https://pypi.org/project/requests",
                 "https://github.com/psf/requests"):
        assert _fire("R101", new, old,
                     source_repos={"python-requests": {repo}}) == []


def test_r101_non_prefixed_name_is_quiet(thresholds):
    thresholds({})
    old = _snapshot(["base"], "alice")
    new = copy.deepcopy(old)
    new["sneaky-tool"] = _snapshot(["sneaky-tool"], "mallory")["sneaky-tool"]
    assert _fire("R101", new, old,
                 source_repos={"sneaky-tool": {"https://evil.example/x"}}) == []


# --- R108 maintainer baseline deviation ---------------------------------------


def test_r108_fires_on_activity_deviation(thresholds):
    thresholds({"r108": {"min_history_cycles": 3, "z_score": 2.0, "min_activity": 2}})
    old = _snapshot([f"p{i}" for i in range(10)], "alice")
    new = copy.deepcopy(old)
    for i in range(6):
        new[f"p{i}"]["LastModified"] = NOW + 1
    history = [{"maintainer": "alice", "cycle_time": 1, "activity": 1},
               {"maintainer": "alice", "cycle_time": 2, "activity": 1},
               {"maintainer": "alice", "cycle_time": 3, "activity": 1}]
    findings = _fire("R108", new, old, maintainer_history=history)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["params"]["activity"] == 6


def test_r108_immature_history_is_quiet(thresholds):
    thresholds({"r108": {"min_history_cycles": 3, "z_score": 2.0, "min_activity": 2}})
    old = _snapshot([f"p{i}" for i in range(10)], "alice")
    new = copy.deepcopy(old)
    for i in range(6):
        new[f"p{i}"]["LastModified"] = NOW + 1
    history = [{"maintainer": "alice", "cycle_time": 1, "activity": 1}]
    assert _fire("R108", new, old, maintainer_history=history) == []


# --- R110 name/repo divergence -------------------------------------------------


def test_r110_fires_on_name_repo_divergence(thresholds):
    thresholds({})
    old = _snapshot(["base"], "alice")
    new = copy.deepcopy(old)
    new["chrome-helper"] = _snapshot(["chrome-helper"], "mallory")["chrome-helper"]
    findings = _fire("R110", new, old,
                     source_repos={"chrome-helper": {"https://evil.example/malware"}})
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_r110_matching_repo_is_quiet(thresholds):
    thresholds({})
    old = _snapshot(["base"], "alice")
    new = copy.deepcopy(old)
    new["chrome-helper"] = _snapshot(["chrome-helper"], "alice")["chrome-helper"]
    assert _fire("R110", new, old, source_repos={
        "chrome-helper": {"https://github.com/acme/chrome-helper"}}) == []


# --- maintainer_activity_history feed -----------------------------------------


def test_maintainer_activity_history(db):
    from trustsight.db import maintainer_activity_history
    record_cycle_events([
        {"package_name": "a", "cycle_time": 1, "status": "added",
         "maintainer": "m", "last_modified": NOW},
        {"package_name": "b", "cycle_time": 1, "status": "modified",
         "maintainer": "m", "last_modified": NOW},
        {"package_name": "c", "cycle_time": 1, "status": "added",
         "maintainer": "n", "last_modified": NOW},
    ])
    history = maintainer_activity_history()
    assert {"maintainer": "m", "cycle_time": 1, "activity": 2} in history
    assert {"maintainer": "n", "cycle_time": 1, "activity": 1} in history
