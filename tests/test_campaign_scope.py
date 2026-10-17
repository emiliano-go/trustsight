"""Typed campaign scope: members, hosts and impersonated targets stay apart.

A campaign's scope used to be one untyped list of package names, while the
neighbourhood check compared it against gained hosts.  A host never equals a
package name, so G006 never fired; and treating G005's impersonated targets as
members meant reviewing a legitimate target could be scored.  These tests pin
the full path from a correlation finding to an activated campaign to a later
neighbourhood result, one per campaign kind.
"""

import json

import pytest

from trustsight.db import init_db


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
            "trustsight.full_aur.temporal_engine.load_thresholds", lambda: values
        )
        monkeypatch.setattr(
            "trustsight.config.load_thresholds", lambda: values
        )
    return set_values


def test_g001_host_campaign_elevates_a_neighbours_gained_host(db):
    from trustsight.db import activate_campaign, observation_seq
    from trustsight.full_aur.pipeline import (
        _campaign_identity, _neighborhood_elevation,
    )

    finding = {"rule_id": "G001",
               "params": {"members": ["a", "b", "c"], "host": "new.cdn"}}
    campaign_id, scope = _campaign_identity(finding)
    assert scope == {"package_names": ["a", "b", "c"], "hosts": ["new.cdn"]}
    activate_campaign(campaign_id, scope, "G001", ttl_obs=50,
                      now_obs=observation_seq())

    # A different package gaining the shared host lands in the neighbourhood.
    out = _neighborhood_elevation(
        [{"package": "neighbour", "hosts_gained": ["new.cdn"]}])
    assert [f["rule_id"] for f in out] == ["G006"]
    assert out[0]["params"]["members"] == ["neighbour"]

    # A campaign member gaining the same host is the campaign, not a neighbour.
    assert _neighborhood_elevation(
        [{"package": "a", "hosts_gained": ["new.cdn"]}]) == []


def test_g005_separates_targets_from_members(db):
    from trustsight.db import activate_campaign, observation_seq
    from trustsight.full_aur.pipeline import (
        _campaign_identity, _neighborhood_elevation,
    )

    finding = {"rule_id": "G005",
               "params": {"members": ["parru", "yyay"], "targets": ["yay"],
                          "maintainer": "m"}}
    campaign_id, scope = _campaign_identity(finding)
    assert scope == {"package_names": ["parru", "yyay"], "targets": ["yay"]}
    activate_campaign(campaign_id, scope, "G005", ttl_obs=50,
                      now_obs=observation_seq())

    # A *new clone* of the impersonated target is elevated - its own
    # impersonated_target matches the campaign's targets.
    out = _neighborhood_elevation(
        [{"package": "yaay", "impersonated_target": "yay"}])
    assert [f["rule_id"] for f in out] == ["G006"]

    # The legitimate target alone is not: existing is not touching anything.
    assert _neighborhood_elevation([{"package": "yay"}]) == []
    # Nor is a member a neighbour of its own campaign.
    assert _neighborhood_elevation(
        [{"package": "yyay", "impersonated_target": "yay"}]) == []


def test_legacy_g005_scope_cannot_match_a_target():
    """A pre-typed G005 list conflated members and targets and cannot be told
    apart, so it is kept unmatchable rather than risk flagging a target."""
    from trustsight.db._campaigns import _read_scope

    legacy = json.dumps(["yyay", "yay"])
    scope = _read_scope(legacy, "G005")
    assert scope == {"untyped_legacy": ["yay", "yyay"]}
    # None of the matchable typed keys are present.
    assert not ({"package_names", "hosts", "targets"} & set(scope))


def test_legacy_non_g005_scope_is_read_as_package_names():
    from trustsight.db._campaigns import _read_scope

    assert _read_scope(json.dumps(["a", "b"]), "G001") == {
        "package_names": ["a", "b"]}


def test_a_typed_scope_round_trips_through_storage():
    from trustsight.db._campaigns import _read_scope

    stored = json.dumps({"package_names": ["p"], "hosts": ["h"],
                         "targets": ["t"], "dependencies": ["d"]})
    assert _read_scope(stored, "G004") == {
        "package_names": ["p"], "hosts": ["h"], "targets": ["t"],
        "dependencies": ["d"]}


def _yay_typosquat_meta():
    """A popular ``yay`` and three name-clones under one fresh account."""
    def pkg(name, maintainer, votes=0):
        return {"Name": name, "PackageBase": name, "Maintainer": maintainer,
                "Version": "1", "LastModified": 100, "NumVotes": votes}
    return {
        "yay": pkg("yay", "jguer", 2649),
        "yyay": pkg("yyay", "marchos1as"),
        "yaay": pkg("yaay", "marchos1as"),
        "yayy": pkg("yayy", "marchos1as"),
    }


def test_yay_impersonation_campaign_is_detected(db):
    """The reported incident: several name-clones of `yay` under one account
    are one G005 campaign, not N per-package findings."""
    from trustsight.analysis.correlation import correlate
    from trustsight.full_aur.pipeline import (
        _correlation_records, _popular_candidates,
    )

    new_meta = _yay_typosquat_meta()
    processed = {"yyay", "yaay", "yayy", "yay"}
    popular = _popular_candidates(new_meta)
    records = _correlation_records(new_meta, {}, processed, popular, {})
    findings = correlate(records, {})

    g005 = [f for f in findings if f["rule_id"] == "G005"]
    assert len(g005) == 1
    params = g005[0]["params"]
    assert params["maintainer"] == "marchos1as"
    assert params["targets"] == ["yay"]
    assert set(params["members"]) == {"yyay", "yaay", "yayy"}


def test_the_yay_campaign_primes_and_notifies(db):
    from trustsight.analysis.correlation import correlate
    from trustsight.db import active_campaigns
    from trustsight.full_aur.pipeline import (
        CycleResult, _activate_campaigns, _correlation_records,
        _popular_candidates,
    )
    from trustsight.notify import alert_payload

    new_meta = _yay_typosquat_meta()
    processed = {"yyay", "yaay", "yayy", "yay"}
    findings = correlate(
        _correlation_records(new_meta, {}, processed,
                             _popular_candidates(new_meta), {}), {})
    assert _activate_campaigns(findings, {}) == []
    assert any(c["campaign_id"].startswith("g005:")
               for c in active_campaigns())

    payload = alert_payload(CycleResult(
        cluster_findings=findings, new_alerts=[("yyay", "G005")]))
    assert payload["impersonation"][0]["targets"] == ["yay"]
    assert payload["title"].startswith("TrustSight: impersonation campaign")


def test_impersonation_scores_members_but_correlation_clusters_do_not(db):
    """#9: G005 (impersonation) scores its members; G001 (a correlation
    cluster) keeps its alert but must not inflate a member's score."""
    from trustsight.db import get_package_profile
    from trustsight.full_aur.pipeline import (
        _apply_cluster_weights, _popular_candidates,
    )

    new_meta = _yay_typosquat_meta()
    popular = _popular_candidates(new_meta)

    # G005 scores the clones.
    _apply_cluster_weights(
        [{"rule_id": "G005", "severity": "HIGH",
          "params": {"members": ["yyay", "yaay", "yayy"],
                     "maintainer": "marchos1as", "targets": ["yay"]}}],
        new_meta, popular, {})
    assert (get_package_profile("yyay") or {}).get("last_score", 0) > 0

    # G001 does not score its members.
    _apply_cluster_weights(
        [{"rule_id": "G001", "severity": "HIGH",
          "params": {"members": ["a", "b", "c"], "host": "new.cdn"}}],
        {}, None, {})
    assert (get_package_profile("a") or {}).get("last_score", 0) == 0


_BURST_NOW = 1_800_000_000


def _burst_meta(maintainer, count, clone=None):
    """*count* packages under one maintainer, each with a distinct upstream."""
    meta = {}
    for i in range(count):
        name = f"tool-{i}"
        meta[name] = {"Name": name, "PackageBase": name, "Maintainer": maintainer,
                      "Version": "1", "LastModified": _BURST_NOW, "NumVotes": 0}
    if clone:
        meta[clone] = {"Name": clone, "PackageBase": clone,
                       "Maintainer": maintainer, "Version": "1",
                       "LastModified": _BURST_NOW, "NumVotes": 0}
    return meta


def _previous(meta, days=30):
    """The same snapshot, one observation older, so everything reads modified."""
    return {name: {**entry, "LastModified": _BURST_NOW - 86400 * days}
            for name, entry in meta.items()}


def test_a_benign_attribute_burst_is_context_not_scored(db, thresholds):
    """One maintainer modifying six of their own packages is H055 - detected,
    but context: it is not an impersonation, so it scores nobody.  This is the
    shape the feed reported as a campaign (``zxp19821005``)."""
    from trustsight.db import get_package_profile
    from trustsight.full_aur.corpus import run_corpus_sweep
    from trustsight.full_aur.pipeline import (
        _apply_cluster_weights, _popular_candidates,
    )

    thresholds({"h055": {"min_packages": 3, "window_hours": 24}})
    new = _burst_meta("dominiquini", 6)

    findings = run_corpus_sweep(new, _previous(new), now=_BURST_NOW)
    h055 = [f for f in findings if f["rule_id"] == "H055"]
    assert len(h055) == 1, "the burst must still be detected"

    _apply_cluster_weights(findings, new, _popular_candidates(new), {})

    assert h055[0]["params"]["impersonated"] is False
    for name in h055[0]["params"]["members"]:
        assert (get_package_profile(name) or {}).get("last_score", 0) == 0


def test_an_impersonating_attribute_burst_scores(db, thresholds):
    """The gate is two-sided: when a burst member is a name-clone of a popular
    package the burst is impersonation, and it must score - otherwise the
    suppression would swallow the attack it exists to catch."""
    from trustsight.db import get_package_profile
    from trustsight.full_aur.corpus import run_corpus_sweep
    from trustsight.full_aur.pipeline import (
        _apply_cluster_weights, _popular_candidates,
    )

    thresholds({"h055": {"min_packages": 3, "window_hours": 24}})
    popular = {"Name": "yay", "PackageBase": "yay", "Maintainer": "jguer",
               "Version": "1", "LastModified": _BURST_NOW, "NumVotes": 2649}
    new = _burst_meta("marchos1as", 5, clone="yayy")
    new["yay"] = popular
    old = _previous(new)
    old["yay"] = {**popular, "LastModified": _BURST_NOW - 86400 * 30}

    findings = run_corpus_sweep(new, old, now=_BURST_NOW)
    h055 = [f for f in findings if f["rule_id"] == "H055"]
    assert len(h055) == 1
    assert "yayy" in h055[0]["params"]["members"]

    _apply_cluster_weights(findings, new, _popular_candidates(new), {})

    assert h055[0]["params"]["impersonated"] is True
    assert (get_package_profile("yayy") or {}).get("last_score", 0) > 0


def test_a_full_campaign_cap_reports_the_refused_campaign(db):
    """Silently dropping an activation would violate the transparency the
    campaign-memory mechanism is built on."""
    from trustsight.full_aur.pipeline import _activate_campaigns

    config = {"alerts": {"max_active_campaigns": 1,
                         "campaign_ttl_observations": 50}}
    findings = [
        {"rule_id": "G001", "params": {"members": ["a"], "host": "h1"}},
        {"rule_id": "G001", "params": {"members": ["b"], "host": "h2"}},
    ]
    refused = _activate_campaigns(findings, config)
    assert len(refused) == 1
    assert refused[0].startswith("G001:")
