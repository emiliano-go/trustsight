"""Durable delivery, liveness and single-instance behaviour for the watcher."""

from datetime import datetime, timedelta, timezone

import pytest

import trustsight.db as db_module
from trustsight.db import (
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
    for _ in range(10):
        mark_alert_attempt(row["id"], "down")
    assert pending_alert_payloads() == []
    assert alert_outbox_stats()["parked"] == 1


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
