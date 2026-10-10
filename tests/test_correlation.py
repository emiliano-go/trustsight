"""Addendum 5 §6.2: the G-series cross-package correlation."""

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
