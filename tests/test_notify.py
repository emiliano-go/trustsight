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


def test_over_threshold_marks_the_payload_urgent():
    cycle = CycleResult(over_threshold=[("hot-pkg", 45), ("warm-pkg", 31)])
    payload = alert_payload(cycle)
    assert payload["priority"] == "urgent"
    assert payload["over_threshold"] == [
        {"package": "hot-pkg", "score": 45},
        {"package": "warm-pkg", "score": 31},
    ]


def test_urgent_payload_carries_the_ntfy_priority_header(receiver):
    cycle = CycleResult(over_threshold=[("hot-pkg", 45)])
    post_webhook(receiver.url, alert_payload(cycle))
    [(path, body)] = receiver.requests
    assert body["priority"] == "urgent"
    assert receiver.headers_seen[0].get("Priority") == "5"


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
    assert len(receiver.requests) == 1
    assert receiver.requests[0][1]["alerts"] == [
        {"package": "pkg-a", "rule_id": "H088"}
    ]
