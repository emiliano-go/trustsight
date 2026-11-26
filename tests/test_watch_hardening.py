"""Durable delivery, liveness and single-instance behaviour for the watcher."""

from datetime import datetime, timedelta, timezone

import pytest

import trustsight.db as db_module
from trustsight.db import (
    ALERT_OUTBOX_MAX_AGE,
    ALERT_OUTBOX_MAX_ATTEMPTS,
    alert_outbox_stats,
    init_db,
    mark_alert_attempt,
    pending_alert_payloads,
)
from trustsight.full_aur.pipeline import CycleResult
from trustsight.full_aur.watch_lock import WatchAlreadyRunning, watch_lock


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path)
    init_db()
    return tmp_path


def test_a_failed_alert_stays_in_the_outbox_and_is_retried(data_dir, monkeypatch):
    from trustsight import notify

    sent = []
    monkeypatch.setattr(notify, "feed_url", lambda *a, **k: "")

    def _fail(*_args, **_kwargs):
        raise OSError("receiver down")

    monkeypatch.setattr(notify, "post_webhook", _fail)
    cycle = CycleResult(new_alerts=[("pkg", "R001")])
    assert notify.maybe_notify(cycle, "https://example.invalid/hook") is False
    assert alert_outbox_stats()["pending"] == 1

    def _succeed(url, payload):
        sent.append((url, payload))

    monkeypatch.setattr(notify, "post_webhook", _succeed)
    later = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert notify.flush_outbox("https://example.invalid/hook", now=later) is True
    assert alert_outbox_stats()["pending"] == 0
    assert len(sent) == 1
    # Delivered rows are not sent again.
    assert notify.flush_outbox("https://example.invalid/hook", now=later) is False
    assert len(sent) == 1


def test_the_outbox_parks_after_the_attempt_cap(data_dir, monkeypatch):
    from trustsight import notify

    monkeypatch.setattr(notify, "feed_url", lambda *a, **k: "")
    monkeypatch.setattr(
        notify, "post_webhook",
        lambda *a, **k: (_ for _ in ()).throw(OSError("down")),
    )
    notify.maybe_notify(
        CycleResult(new_alerts=[("pkg", "R001")]), "https://example.invalid/hook"
    )
    later = datetime.now(timezone.utc) + timedelta(minutes=5)
    row = pending_alert_payloads(now=later)[0]
    for _ in range(ALERT_OUTBOX_MAX_ATTEMPTS):
        mark_alert_attempt(row["id"], "down")
    assert pending_alert_payloads() == []
    assert alert_outbox_stats()["parked"] == 1


def test_a_retry_is_signed_again_instead_of_replaying_its_queued_timestamp(
    data_dir, monkeypatch,
):
    """The receiver refuses a stale signature, and the signature is bound to
    the timestamp carried in the queue row.  A document signed when it was
    queued therefore stops being deliverable minutes later: on 24/11/26 that
    turned an hour of rejected deliveries into a day-long stall."""
    from trustsight import notify

    captured = {}

    def _post(url, payload, key_b64, key_id, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(notify, "feed_url", lambda *a, **k: "https://feed.invalid/api/ingest")
    monkeypatch.setattr(notify, "_feed_key", lambda: ("k1", "not-a-real-key"))
    monkeypatch.setattr(notify, "post_feed", _post)
    from trustsight.db import enqueue_alert_payload

    enqueue_alert_payload({"event": "trustsight.alerts"}, "webhook-abc", 1_600_000_000)
    later = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert notify.flush_outbox("", now=later) is True

    # Same identity, so the feed still deduplicates it; new timestamp, so it
    # is not refused as stale.
    assert captured["webhook_id"] == "webhook-abc"
    assert captured["timestamp"] is None


def test_a_day_old_document_is_still_retried(data_dir):
    """Parking on age is a last resort, not a way to drop a weekend outage."""
    from trustsight.db._lifecycles import AlertOutboxState

    now = datetime.now(timezone.utc)
    state = AlertOutboxState(created_at=now - timedelta(hours=25))
    _, parked = state.failed(
        now, "receiver down",
        max_attempts=ALERT_OUTBOX_MAX_ATTEMPTS,
        max_age=ALERT_OUTBOX_MAX_AGE,
        backoff_base_seconds=30,
        backoff_max_seconds=6 * 60 * 60,
    )
    assert parked is False


def test_parking_a_document_pushes_a_heartbeat(data_dir, monkeypatch):
    """Parking is terminal and otherwise silent: it has to say so."""
    from trustsight import notify
    import trustsight.db._outbox as outbox

    monkeypatch.setattr(outbox, "MAX_ATTEMPTS", 1)
    monkeypatch.setattr(notify, "feed_url", lambda *a, **k: "")
    sent = []

    def _hook(url, payload):
        sent.append(payload)
        if payload.get("event") == "trustsight.alerts":
            raise OSError("receiver down")

    monkeypatch.setattr(notify, "post_webhook", _hook)
    assert notify.maybe_notify(
        CycleResult(new_alerts=[("pkg", "R001")]), "https://example.invalid/hook"
    ) is False

    titles = [payload.get("title") for payload in sent]
    assert "TrustSight: alert delivery parked" in titles
    announcement = sent[titles.index("TrustSight: alert delivery parked")]
    assert announcement["outbox"]["parked"] == 1
    assert announcement["status"] == "degraded"

    # Throttled: a second parking event within the day does not page again.
    assert notify.announce_parked_alerts(1, "https://example.invalid/hook") is False


def test_parked_documents_are_pruned_once_they_cannot_be_delivered(data_dir):
    """A parked payload is dead weight after the receiver's window passes."""
    from trustsight.db import enqueue_alert_payload, get_connection, prune_parked_alerts

    now = datetime.now(timezone.utc)
    keep = enqueue_alert_payload({"event": "trustsight.alerts"}, "keep", int(now.timestamp()))
    drop = enqueue_alert_payload({"event": "trustsight.alerts"}, "drop", int(now.timestamp()))
    with get_connection() as conn:
        conn.execute(
            "UPDATE alert_outbox SET parked_at = ?, created_at = ? WHERE id = ?",
            (now.isoformat(), (now - timedelta(days=2)).isoformat(), keep),
        )
        conn.execute(
            "UPDATE alert_outbox SET parked_at = ?, created_at = ? WHERE id = ?",
            (now.isoformat(), (now - timedelta(days=45)).isoformat(), drop),
        )
        conn.commit()

    assert prune_parked_alerts(now=now) == 1
    with get_connection() as conn:
        remaining = [row["id"] for row in conn.execute("SELECT id FROM alert_outbox")]
    assert remaining == [keep]


def test_a_secret_file_is_used_for_the_feed_key(tmp_path, monkeypatch):
    from trustsight.notify import _feed_key

    key = tmp_path / "feed.key"
    key.write_text("base64-key\n")
    monkeypatch.delenv("TRUSTSIGHT_FEED_KEY", raising=False)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_FILE", str(key))
    assert _feed_key() == ("k1", "base64-key")


def test_watch_health_distinguishes_alive_from_failing(data_dir):
    from trustsight.full_aur import watch_state

    watch_state.record_start(60)
    assert watch_state.health()["healthy"] is False

    watch_state.record_success()
    assert watch_state.health()["healthy"] is True

    for _ in range(3):
        watch_state.record_failure("network down")
    state = watch_state.health()
    assert state["healthy"] is False
    assert state["consecutive_failures"] == 3


def test_one_watcher_per_data_directory(data_dir):
    with watch_lock():
        with pytest.raises(WatchAlreadyRunning):
            with watch_lock():
                pass
