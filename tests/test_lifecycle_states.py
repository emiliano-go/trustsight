"""Contracts for the persisted lifecycle state types."""

from datetime import datetime, timedelta, timezone

import pytest

from trustsight.channel_state import ChannelPull
from trustsight.db._lifecycles import (
    AlertOutboxState,
    CampaignState,
    IllegalTransition,
    OrphanState,
)

NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)


# --- alert outbox ---------------------------------------------------------


def _outbox(**kwargs):
    return AlertOutboxState(created_at=NOW - timedelta(minutes=5), **kwargs)


def test_outbox_is_due_until_both_sinks_accept():
    state = _outbox()
    assert state.due(NOW)
    state = state.with_sink("ntfy")
    assert state.due(NOW)
    state = state.with_sink("feed")
    assert state.delivered
    assert not state.due(NOW)


def test_outbox_failure_schedules_a_retry_and_increments_attempts():
    state, parked = _outbox().failed(
        NOW, "down", max_attempts=10, max_age=timedelta(hours=24),
        backoff_base_seconds=30, backoff_max_seconds=3600)
    assert not parked
    assert state.attempts == 1
    assert state.next_attempt_at == NOW + timedelta(seconds=30)
    assert not state.due(NOW)


def test_outbox_parks_at_max_attempts():
    state = _outbox(attempts=9)
    state, parked = state.failed(
        NOW, "down", max_attempts=10, max_age=timedelta(hours=24),
        backoff_base_seconds=30, backoff_max_seconds=3600)
    assert parked
    assert state.parked
    assert state.parked_at == NOW
    assert state.attempts == 10


def test_outbox_parks_when_older_than_max_age():
    old = AlertOutboxState(created_at=NOW - timedelta(days=2))
    state, parked = old.failed(
        NOW, "down", max_attempts=10, max_age=timedelta(hours=24),
        backoff_base_seconds=30, backoff_max_seconds=3600)
    assert parked
    assert state.parked


def test_outbox_parked_is_terminal():
    state = _outbox(attempts=1, parked_at=NOW)
    with pytest.raises(IllegalTransition):
        state.with_sink("ntfy")
    with pytest.raises(IllegalTransition):
        state.failed(
            NOW, "down", max_attempts=10, max_age=timedelta(hours=24),
            backoff_base_seconds=30, backoff_max_seconds=3600)


def test_outbox_rejects_negative_attempts():
    with pytest.raises(IllegalTransition):
        AlertOutboxState(created_at=NOW, attempts=-1)


# --- campaign -------------------------------------------------------------


def test_campaign_expiry_is_structural():
    state = CampaignState("c", activated_at_obs=100, ttl_obs=10)
    assert state.is_active(109)
    assert state.is_expired(110)
    assert state.is_expired_unannounced(110)
    assert state.expires_at_obs == 110


def test_campaign_reactivation_refreshes_and_counts():
    state = CampaignState("c", activated_at_obs=100, ttl_obs=10)
    new = state.reactivated(120, 10)
    assert new.activated_at_obs == 120
    assert new.activation_count == 2
    assert new.first_activated_at_obs == 100
    assert new.last_activated_at_obs == 120
    assert new.is_active(129)


def test_campaign_reactivation_never_shortens_a_live_window():
    state = CampaignState("c", activated_at_obs=100, ttl_obs=50)
    new = state.reactivated(110, 5)
    assert new.ttl_obs == 50
    assert new.is_active(159)


def test_campaign_rejects_a_zero_ttl():
    with pytest.raises(IllegalTransition):
        CampaignState("c", activated_at_obs=100, ttl_obs=0)


# --- orphan tri-state -----------------------------------------------------


def test_orphan_observation_mapping():
    assert OrphanState.observe(None) is OrphanState.UNKNOWN
    assert OrphanState.observe(False) is OrphanState.MAINTAINED
    assert OrphanState.observe(True) is OrphanState.ORPHANED


def test_orphan_from_db_keeps_unknown_for_bad_values():
    assert OrphanState.from_db(None) is OrphanState.UNKNOWN
    assert OrphanState.from_db("nonsense") is OrphanState.UNKNOWN
    assert OrphanState.from_db(1) is OrphanState.ORPHANED


# --- channel pull ---------------------------------------------------------


def test_channel_pull_matches_channel_and_tag():
    pull = ChannelPull(tag="t1", channel="someone/else")
    assert pull.matches("t1", "someone/else")
    assert not pull.matches("t1", "official")
    assert not pull.matches("t2", "someone/else")
    assert not pull.matches("", "someone/else")


def test_channel_pull_without_a_channel_is_a_legacy_match():
    pull = ChannelPull(tag="t1")
    assert pull.matches("t1", "anything")


# --- integration ----------------------------------------------------------


@pytest.fixture
def db(tmp_path, monkeypatch):
    from trustsight.db import init_db

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


def test_outbox_rows_follow_the_state_type(db):
    from trustsight.db import (
        alert_outbox_stats, enqueue_alert_payload, mark_alert_attempt,
        pending_alert_payloads,
    )

    row_id = enqueue_alert_payload(
        {"event": "test"}, "", 0, now=NOW)
    assert [row["id"] for row in pending_alert_payloads(now=NOW)] == [row_id]
    assert not mark_alert_attempt(row_id, "down", now=NOW)
    assert pending_alert_payloads(now=NOW) == []
    assert alert_outbox_stats(now=NOW)["pending"] == 1


def test_orphan_state_round_trips_through_the_database(db):
    from trustsight.db import (
        get_aur_orphan_state, update_aur_orphan_state, upsert_package,
    )

    upsert_package("demo", "1")
    assert get_aur_orphan_state("demo") == int(OrphanState.UNKNOWN)
    update_aur_orphan_state("demo", True)
    assert get_aur_orphan_state("demo") == int(OrphanState.ORPHANED)
    update_aur_orphan_state("demo", None)
    assert get_aur_orphan_state("demo") == int(OrphanState.UNKNOWN)
    assert get_aur_orphan_state("absent") == int(OrphanState.UNKNOWN)
