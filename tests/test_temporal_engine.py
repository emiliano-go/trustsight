"""The temporal engine's instance table and shared read layer."""

from pathlib import Path

import pytest

from trustsight.db import init_db
from trustsight.full_aur.temporal_engine import (
    CYCLE_INSTANCES,
    GRAPH_INSTANCES,
    PER_PACKAGE_INSTANCES,
    PREDICATES,
    HistorySnapshot,
    clear_history_cache,
    read_cycle_history,
    run_cycle_instances,
)

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    clear_history_cache()
    yield
    clear_history_cache()
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


# The 16 history-backed ids the engine consolidates.
_TARGET_IDS = {
    "H020", "H021", "H022", "H026", "H028", "H037", "H044", "H045",
    "H046", "H057", "H058", "H060", "H073", "H074", "H086", "H088",
}


def test_every_instance_names_a_known_predicate():
    for instance in (*CYCLE_INSTANCES, *GRAPH_INSTANCES, *PER_PACKAGE_INSTANCES):
        assert instance.predicate in PREDICATES, instance
        assert instance.scope in ("cycle", "package"), instance


def test_every_instance_carries_a_doc_fragment_and_fixture_pair():
    for instance in (*CYCLE_INSTANCES, *GRAPH_INSTANCES, *PER_PACKAGE_INSTANCES):
        assert (ROOT / instance.doc).exists(), (instance.rule_id, instance.doc)
        assert instance.fixtures, instance
        for fixture in instance.fixtures:
            assert (ROOT / fixture).exists(), (instance.rule_id, fixture)


def test_the_engine_covers_the_phase_2_ids():
    covered = {
        inst.rule_id
        for inst in (*CYCLE_INSTANCES, *GRAPH_INSTANCES, *PER_PACKAGE_INSTANCES)
    }
    assert _TARGET_IDS <= covered, sorted(_TARGET_IDS - covered)


def test_run_cycle_instances_is_silent_without_a_baseline():
    snapshot = HistorySnapshot.from_cycle({"p": {}}, None)
    assert run_cycle_instances(snapshot) == []


def test_snapshot_captures_changes_and_transitions():
    old = {"p": {"Name": "p", "Maintainer": "alice", "Version": "1.0"}}
    new = {"p": {"Name": "p", "Maintainer": "mallory", "Version": "2.0"}}
    snapshot = HistorySnapshot.from_cycle(new, old)
    assert snapshot.changes
    assert snapshot.transitions["p"] == ("alice", "mallory")


def test_read_cycle_history_returns_the_rate_and_rule_timelines(db):
    history = read_cycle_history()
    assert set(history) == {
        "prior_history", "maintainer_history", "maintainer_transitions",
        "prior_rule_history", "package_cycle_events",
    }


def test_read_cycle_history_is_cached(db):
    assert read_cycle_history() is read_cycle_history()
