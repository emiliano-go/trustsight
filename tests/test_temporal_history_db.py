"""Durable, bounded history feeds for the cross-window temporal rules."""

import pytest

from trustsight.db import (
    init_db,
    insert_analysis,
    record_cycle_events,
    record_property_transition,
    temporal_rule_history,
    upsert_package,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


def test_history_excludes_current_analysis_and_preserves_prior_rules(db):
    package_id = upsert_package("demo", "1")
    insert_analysis(package_id, "1", "1.1", "a", "b", 0, "", "{}", [
        {"rule_id": "H049", "severity": "MEDIUM"},
    ])
    current_id = insert_analysis(package_id, "1.1", "1.2", "b", "c", 0, "", "{}", [
        {"rule_id": "R001", "severity": "CRITICAL"},
    ])

    history = temporal_rule_history(["demo"])["prior_rule_history"]["demo"]

    assert len(history) == 1
    assert history[0]["rules"] == ["H049"]
    assert history[0]["history_id"] != current_id


def test_history_feeds_are_bounded_and_scoped_to_requested_packages(db):
    for name in ("demo", "other"):
        upsert_package(name, "1")
        record_property_transition(name, "maintainer", "", "alice")
        record_cycle_events([{
            "package_name": name, "cycle_time": 4, "status": "removed",
            "maintainer": "alice", "last_modified": 10,
        }])

    history = temporal_rule_history(["demo"], per_package_limit=1)

    assert set(history["maintainer_transitions"]) == {"demo"}
    assert history["maintainer_transitions"]["demo"][0]["new_value"] == '"alice"'
    assert history["package_cycle_events"]["demo"][0]["status"] == "removed"
    assert "other" not in history["package_cycle_events"]


def test_empty_history_request_performs_no_synthetic_observation(db):
    assert temporal_rule_history([]) == {
        "maintainer_transitions": {},
        "prior_rule_history": {},
        "package_cycle_events": {},
    }
