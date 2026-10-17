"""The G-series cross-package correlation."""

from trustsight.analysis.correlation import (
    coordinated_adoption,
    correlate,
    shared_added_literal,
    shared_gained_host,
)


def _records():
    return [
        {"package": "a", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": ["B" * 300]},
        {"package": "b", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": ["B" * 300]},
        {"package": "c", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": []},
        {"package": "d", "hosts_gained": [], "maintainer": "other@y",
         "adoption": False, "added_literals": []},
    ]


def test_shared_gained_host_fires_at_threshold():
    found = shared_gained_host(_records(), min_packages=3)
    assert [f["rule_id"] for f in found] == ["G001"]
    assert found[0]["params"]["members"] == ["a", "b", "c"]
    assert shared_gained_host(_records(), min_packages=4) == []


def test_shared_added_literal_fires_and_redacts_content():
    found = shared_added_literal(_records(), min_packages=2, min_length=64)
    assert [f["rule_id"] for f in found] == ["G002"]
    assert "B" * 300 not in found[0]["match"]
    assert found[0]["params"]["literal_length"] == 300


def test_coordinated_adoption_fires_at_threshold():
    found = coordinated_adoption(_records(), min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]
    assert coordinated_adoption(_records(), min_members=4) == []


def test_coordinated_adoption_cites_the_temporal_predicates():
    records = [
        {"package": "a", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H044"]},
        {"package": "b", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H086"]},
        {"package": "c", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H044"]},
    ]
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["params"]["predicates"] == ["H044", "H086"]


def test_coordinated_adoption_requires_unrelated_members():
    """A maintainer adopting one variant family (all from one repo) is H052's
    shape, not a coordinated adoption."""
    related = [
        {"package": "a", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
        {"package": "b", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
        {"package": "c", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
    ]
    assert coordinated_adoption(related, min_members=3) == []

    unrelated = [dict(r, source_repos=[f"https://x/{r['package']}"])
                 for r in related]
    found = coordinated_adoption(unrelated, min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]
    assert found[0]["params"]["repos"] == [
        "https://x/a", "https://x/b", "https://x/c"]


def test_coordinated_adoption_keeps_firing_without_repo_data():
    """An unproven relationship is not evidence of one: missing repo data
    preserves the group rather than quietly dropping it."""
    records = [
        {"package": "a", "maintainer": "m", "adoption": True},
        {"package": "b", "maintainer": "m", "adoption": True},
        {"package": "c", "maintainer": "m", "adoption": True},
    ]
    assert [f["rule_id"] for f in coordinated_adoption(records, 3)] == ["G003"]


def test_correlate_honors_configured_thresholds():
    config = {"thresholds": {
        "g_host": {"min_packages": 3},
        "g_blob": {"min_packages": 2, "min_length": 64},
        "g_adopt": {"min_members": 3},
    }}
    ids = {f["rule_id"] for f in correlate(_records(), config)}
    assert ids == {"G001", "G002", "G003"}


def test_correlate_is_empty_without_clusters():
    assert correlate([{"package": "only"}], None) == []


def test_impersonation_campaign_groups_clones_by_maintainer():
    from trustsight.analysis.correlation import impersonation_campaign

    records = [
        {"package": "yyay", "maintainer": "marchos1as",
         "impersonated_target": "yay"},
        {"package": "parru", "maintainer": "marchos1as",
         "impersonated_target": "paru"},
        {"package": "yau", "maintainer": "marchos1as",
         "impersonated_target": "yay"},
        {"package": "koboldcpp-cuda", "maintainer": "TheBill2001",
         "impersonated_target": ""},
    ]
    found = impersonation_campaign(records, min_members=3)
    assert [f["rule_id"] for f in found] == ["G005"]
    assert found[0]["severity"] == "HIGH"
    assert found[0]["params"]["members"] == ["parru", "yau", "yyay"]
    assert found[0]["params"]["targets"] == ["paru", "yay"]


def test_a_lone_clone_is_not_a_campaign():
    from trustsight.analysis.correlation import impersonation_campaign

    records = [{"package": "yyay", "maintainer": "m",
                "impersonated_target": "yay"}]
    assert impersonation_campaign(records, min_members=2) == []


def test_ownerless_clones_are_not_grouped_into_a_campaign():
    """An empty maintainer is not evidence that unrelated ownerless clones
    share an operator; they stay individual H029 findings."""
    from trustsight.analysis.correlation import impersonation_campaign

    records = [
        {"package": name, "maintainer": "", "impersonated_target": "yay"}
        for name in ("yyay", "yau", "yayy")
    ]
    assert impersonation_campaign(records, min_members=3) == []


def test_correlate_includes_the_impersonation_campaign():
    records = [
        {"package": name, "maintainer": "m", "impersonated_target": "yay"}
        for name in ("yyay", "yau", "yayy")
    ]
    ids = {f["rule_id"] for f in correlate(records, None)}
    assert "G005" in ids
