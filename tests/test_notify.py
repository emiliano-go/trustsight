"""The watch-cycle alert webhook.

An unattended watcher announces a cluster once and never again; the
webhook is how that one announcement reaches anyone.  These tests pin the
payload shape, the delivery, and the rule that a dead receiver must never
kill the loop.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from trustsight.full_aur.pipeline import CycleResult, run_watch
from trustsight.notify import alert_payload, maybe_notify, notify_url, post_webhook


class _Receiver:
    """A one-file HTTP sink that records what was POSTed to it."""

    def __init__(self):
        self.requests: list[tuple[str, dict]] = []
        self.headers_seen: list = []
        server = HTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{server.server_address[1]}/hook"
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        self._server = server

    def _handler(self):
        captured = self.requests
        headers_seen = self.headers_seen

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                captured.append((self.path, body))
                headers_seen.append(self.headers)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        return Handler

    def stop(self):
        self._server.shutdown()


@pytest.fixture
def receiver():
    r = _Receiver()
    yield r
    r.stop()


def _cycle(**kw):
    kw.setdefault("new_alerts", [("evil-pkg", "H026"), ("evil-pkg2", "R001")])
    return CycleResult(**kw)


def test_payload_carries_the_alerts_and_the_cycle_counts():
    payload = alert_payload(_cycle(added=3, changed=2, removed=1, processed=5))
    assert payload["event"] == "trustsight.alerts"
    assert payload["priority"] == "default"
    assert payload["alerts"] == [
        {"package": "evil-pkg", "rule_id": "H026"},
        {"package": "evil-pkg2", "rule_id": "R001"},
    ]
    assert payload["cycle"] == {
        "added": 3, "changed": 2, "removed": 1, "processed": 5,
    }
    assert payload["over_threshold"] == []


def test_over_threshold_stays_at_the_default_priority():
    cycle = CycleResult(over_threshold=[("hot-pkg", 45), ("warm-pkg", 31)])
    payload = alert_payload(cycle)
    assert payload["priority"] == "default"
    assert payload["over_threshold"] == [
        {"package": "hot-pkg", "score": 45,
         "aur": "https://aur.archlinux.org/packages/hot-pkg"},
        {"package": "warm-pkg", "score": 31,
         "aur": "https://aur.archlinux.org/packages/warm-pkg"},
    ]
    assert "day" not in payload


def test_the_payload_carries_what_fired_and_when():
    """A notification should say what happened, not only that it did: the
    version transition, the AUR change date, the rules, and the replayed
    day while backfilling."""
    cycle = CycleResult(
        over_threshold=[("hot-pkg", 45)],
        backfilling=True,
        backfill_day="2026-05-01",
        detail={
            "hot-pkg": {
                "score": 45,
                "old_version": "1.0",
                "new_version": "1.1",
                "last_modified": 1777593600,
                "rules": ["H001", "R001"],
            }
        },
    )
    payload = alert_payload(cycle)
    assert payload["day"] == "2026-05-01"
    assert payload["title"] == "TrustSight: 1 package(s) over threshold (2026-05-01)"
    assert payload["over_threshold"] == [{
        "package": "hot-pkg",
        "score": 45,
        "aur": "https://aur.archlinux.org/packages/hot-pkg",
        "version": "1.0 -> 1.1",
        "last_modified": "2026-05-01 00:00 UTC",
        "rules": ["H001", "R001"],
    }]


def test_the_title_and_tags_reach_the_headers(receiver):
    cycle = CycleResult(over_threshold=[("hot-pkg", 45)],
                        backfill_day="2026-05-01")
    post_webhook(receiver.url, alert_payload(cycle))
    headers = receiver.headers_seen[0]
    assert headers.get("Title") == "TrustSight: 1 package(s) over threshold (2026-05-01)"
    assert headers.get("Tags") == "eye"


def test_the_heartbeat_beats_low_and_daily():
    from trustsight.notify import HEARTBEAT_SECONDS, maybe_heartbeat
    from trustsight.full_aur.pipeline import run_watch

    assert HEARTBEAT_SECONDS == 86400
    receiver = _Receiver()
    try:
        assert maybe_heartbeat(
            CycleResult(backfill_day="2026-05-02"), receiver.url) is True
        body = receiver.requests[0][1]
        assert body["event"] == "trustsight.heartbeat"
        assert body["priority"] == "low"
        assert body["day"] == "2026-05-02"
        assert receiver.headers_seen[0].get("Priority") == "2"
    finally:
        receiver.stop()

    receiver = _Receiver()
    try:
        outcomes = iter([CycleResult(), CycleResult()])
        import unittest.mock as mock
        import trustsight.full_aur.pipeline as pipeline_mod
        with mock.patch.object(pipeline_mod, "run_baseline_build",
                               lambda **kwargs: next(outcomes)):
            run_watch(interval=60, cycles=2, sleep=lambda s: None,
                      notify_url=receiver.url)
        # One beat for the first cycle; the second is inside the same day.
        beats = [b for _p, b in receiver.requests
                 if b.get("event") == "trustsight.heartbeat"]
        assert len(beats) == 1
    finally:
        receiver.stop()


def test_an_alert_never_carries_the_ntfy_priority_header(receiver):
    """The Priority: 5 tier paged at night; alerts stay at the default."""
    cycle = CycleResult(over_threshold=[("hot-pkg", 45)])
    post_webhook(receiver.url, alert_payload(cycle))
    [(path, body)] = receiver.requests
    assert body["priority"] == "default"
    assert receiver.headers_seen[0].get("Priority") is None


def test_default_payload_carries_no_priority_header(receiver):
    post_webhook(receiver.url, alert_payload(_cycle()))
    assert receiver.headers_seen[0].get("Priority") is None


def test_over_threshold_alone_triggers_a_notification(receiver):
    cycle = CycleResult(over_threshold=[("hot-pkg", 45)])
    assert maybe_notify(cycle, receiver.url) is True
    assert receiver.requests[0][1]["over_threshold"][0]["package"] == "hot-pkg"


def test_post_webhook_delivers_json(receiver):
    post_webhook(receiver.url, alert_payload(_cycle()))
    [(path, body)] = receiver.requests
    assert path == "/hook"
    assert body["alerts"][0]["package"] == "evil-pkg"


def test_maybe_notify_is_quiet_without_alerts(receiver):
    assert maybe_notify(CycleResult(), receiver.url) is False
    assert receiver.requests == []


def test_maybe_notify_is_quiet_without_a_url(monkeypatch):
    monkeypatch.setattr("trustsight.config.load_config", lambda: {})
    assert maybe_notify(_cycle(), None) is False


def test_a_dead_receiver_returns_false_and_never_raises():
    assert maybe_notify(_cycle(), "http://127.0.0.1:1/dead") is False


def test_the_flag_overrides_the_configured_webhook(monkeypatch, receiver):
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"notify": {"webhook": "http://127.0.0.1:1/configured"}},
    )
    assert maybe_notify(_cycle(), receiver.url) is True
    assert len(receiver.requests) == 1


def test_configured_webhook_is_used_when_no_flag(monkeypatch, receiver):
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"notify": {"webhook": receiver.url}},
    )
    assert notify_url() == receiver.url
    assert maybe_notify(_cycle()) is True


def test_a_watch_cycle_with_alerts_posts_once(monkeypatch, receiver):
    cycles = iter([
        CycleResult(new_alerts=[("pkg-a", "H088")]),
        CycleResult(),  # a quiet cycle must not POST
    ])
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: next(cycles),
    )
    results = run_watch(interval=60, cycles=2, sleep=lambda s: None,
                        notify_url=receiver.url)
    assert len(results) == 2
    alert_docs = [b for _p, b in receiver.requests
                  if b.get("event") == "trustsight.alerts"]
    assert len(alert_docs) == 1
    assert alert_docs[0]["alerts"] == [
        {"package": "pkg-a", "rule_id": "H088"}
    ]


def test_an_ioc_match_alone_notifies(receiver):
    """The IOC tier reports outside the score, so a known-bad match on a
    clean-looking package never crosses the alerting bar - and it is
    exactly the package the watcher exists for."""
    cycle = CycleResult(ioc_hits=[("bad-pkg", "hash:deadbeef")])
    assert maybe_notify(cycle, receiver.url) is True
    [(path, body)] = receiver.requests
    assert body["priority"] == "default"
    assert "IOC" in body["title"]
    assert body["ioc_matches"] == [{
        "package": "bad-pkg",
        "indicator": "hash:deadbeef",
        "aur": "https://aur.archlinux.org/packages/bad-pkg",
    }]
    assert receiver.headers_seen[0].get("Priority") is None


def test_a_single_shot_cycle_notifies_too(receiver, monkeypatch):
    """python-npx scored 40 inside a bootstrap chunk and nobody was told:
    the notify call lived only in the watch loop.  The single-shot CLI
    path posts too."""
    monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: CycleResult(over_threshold=[("hot-pkg", 45)]),
    )
    from trustsight.cli.app import app
    from typer.testing import CliRunner

    result = CliRunner().invoke(app, ["full-aur", "--notify", receiver.url])
    assert result.exit_code == 0, result.output
    assert len(receiver.requests) == 1
    assert receiver.requests[0][1]["priority"] == "default"


def test_payload_carries_campaign_clusters():
    cycle = _cycle(cluster_findings=[
        {"rule_id": "G001", "params": {"members": ["a", "b", "c"]}},
    ])
    payload = alert_payload(cycle)
    assert payload["campaign_cluster"] == [
        {"rule_id": "G001", "members": ["a", "b", "c"], "count": 3},
    ]
