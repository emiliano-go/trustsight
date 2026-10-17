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
    assert payload["title"] == "TrustSight: hot-pkg scored 45 (H001) (2026-05-01)"
    assert payload["over_threshold"] == [{
        "package": "hot-pkg",
        "score": 45,
        "aur": "https://aur.archlinux.org/packages/hot-pkg",
        "version": "1.0 -> 1.1",
        "last_modified": "2026-05-01 00:00 UTC",
        "rules": ["H001", "R001"],
    }]


def test_the_payload_carries_the_line_that_triggered_each_rule():
    """A reader should be able to point at the exact line: each over-threshold
    entry carries the located findings, and the rule-only list is derived from
    them so the two cannot disagree."""
    cycle = CycleResult(
        over_threshold=[("hot-pkg", 45)],
        detail={
            "hot-pkg": {
                "score": 45,
                "rules": ["R001"],
                "findings": [
                    {"rule_id": "R001", "severity": "HIGH", "weight": 30,
                     "file": "PKGBUILD", "line": 12,
                     "reason": "Remote Script Execution: curl | bash"},
                    {"rule_id": "NOVELTY", "severity": "MEDIUM", "weight": 15,
                     "file": "", "line": None,
                     "reason": "Source URL first seen globally: https://evil.sh"},
                ],
            }
        },
    )
    payload = alert_payload(cycle)
    entry = payload["over_threshold"][0]
    assert entry["rules"] == ["R001"]
    assert entry["findings"][0] == {
        "rule_id": "R001", "severity": "HIGH", "weight": 30,
        "file": "PKGBUILD", "line": 12,
        "reason": "Remote Script Execution: curl | bash",
    }
    assert entry["findings"][1]["rule_id"] == "NOVELTY"
    assert entry["findings"][1]["line"] is None


def test_the_title_and_tags_reach_the_headers(receiver):
    cycle = CycleResult(over_threshold=[("hot-pkg", 45)],
                        backfill_day="2026-05-01")
    post_webhook(receiver.url, alert_payload(cycle))
    headers = receiver.headers_seen[0]
    assert headers.get("Title") == "TrustSight: hot-pkg scored 45 (2026-05-01)"
    assert headers.get("Tags") == "eye"


def test_the_heartbeat_beats_low_and_every_quiet_cycle(tmp_path, monkeypatch):
    from trustsight.notify import maybe_heartbeat
    from trustsight.full_aur.pipeline import run_watch

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

    # Every cycle that raises no alert beats, so silence on the channel means
    # the watcher is dead rather than quiet.
    import trustsight.config as config_module

    monkeypatch.setattr(config_module, "CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "CACHE_DIR", tmp_path / ".cache")
    receiver = _Receiver()
    try:
        outcomes = iter([CycleResult(), CycleResult()])
        import unittest.mock as mock
        import trustsight.full_aur.pipeline as pipeline_mod
        with mock.patch.object(pipeline_mod, "run_baseline_build",
                               lambda **kwargs: next(outcomes)):
            run_watch(interval=60, cycles=2, sleep=lambda s: None,
                      notify_url=receiver.url)
        beats = [b for _p, b in receiver.requests
                 if b.get("event") == "trustsight.heartbeat"]
        assert len(beats) == 2
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


def test_a_modest_payload_keeps_located_findings_with_reasons():
    from trustsight.notify import _payload_size, _PAYLOAD_BUDGET_BYTES

    cycle = CycleResult(
        over_threshold=[("hot-pkg", 45)],
        detail={"hot-pkg": {"score": 45, "rules": ["R001"], "findings": [
            {"rule_id": "R001", "severity": "HIGH", "weight": 30,
             "file": "PKGBUILD", "line": 12, "reason": "curl | bash"}]}},
    )
    payload = alert_payload(cycle)
    assert _payload_size(payload) <= _PAYLOAD_BUDGET_BYTES
    assert payload["over_threshold"][0]["findings"][0]["reason"] == "curl | bash"


def _wide_cycle(packages: int, findings_each: int, reason_len: int) -> CycleResult:
    names = [f"pkg-{i:04d}" for i in range(packages)]
    detail = {
        name: {
            "score": 50, "old_version": "1.0.0", "new_version": "1.0.1",
            "last_modified": 1777593600,
            "rules": [f"H{i:03d}" for i in range(findings_each)],
            "findings": [
                {"rule_id": f"H{n:03d}", "severity": "HIGH", "weight": 25,
                 "file": "PKGBUILD", "line": n, "reason": "x" * reason_len}
                for n in range(findings_each)
            ],
        }
        for name in names
    }
    return CycleResult(
        over_threshold=[(name, 50) for name in names], detail=detail,
        refusals=["refused-pkg"],
    )


def test_a_large_cycle_keeps_full_detail():
    """The feed reads the attachment a >4096-byte document arrives as, so a
    large cycle keeps every finding, reason and rule instead of being trimmed
    to an inline limit it no longer has to fit."""
    from trustsight.notify import _payload_size, _MAX_MESSAGE_BYTES

    payload = alert_payload(_wide_cycle(40, 30, 120))
    assert _payload_size(payload) > _MAX_MESSAGE_BYTES  # it is an attachment now
    assert payload["over_threshold"][0]["findings"][0]["reason"] == "x" * 120
    assert payload["refusals"]


def test_a_pathological_payload_is_bounded():
    """A cycle far past any real one is still bounded below the feed's own
    attachment cap, so the watcher never emits a document the feed would drop;
    the headline, top signal and refusal tier survive the trim."""
    from trustsight.notify import _payload_size, _PAYLOAD_BUDGET_BYTES

    payload = alert_payload(_wide_cycle(300, 40, 200))
    assert _payload_size(payload) <= _PAYLOAD_BUDGET_BYTES
    assert payload["event"] == "trustsight.alerts"
    assert payload["title"].startswith("TrustSight:")
    assert payload["over_threshold"]  # the top signal survives
    assert payload["refusals"]  # the refusal tier survives


def test_a_refusal_carries_what_could_not_be_read():
    """A feed must be able to say *what* was incomplete, not only that a
    package could not be fully read; the refusing X026/X027 findings ride
    along with the package."""
    cycle = CycleResult(
        refusals=["pilinara"],
        detail={"pilinara": {"findings": [
            {"rule_id": "X026", "severity": "MEDIUM", "file": "PKGBUILD",
             "line": None, "reason": "Unresolved Constructs: _v <- package()"},
            {"rule_id": "W008", "severity": "INFO", "file": "PKGBUILD",
             "line": None, "reason": "unresolved assignment"},
        ]}},
    )
    payload = alert_payload(cycle)
    [entry] = payload["refusals"]
    assert entry["package"] == "pilinara"
    assert entry["aur"].endswith("/pilinara")
    assert entry["reason"].startswith("Unresolved Constructs")
    assert [f["rule_id"] for f in entry["findings"]] == ["X026"]


def test_payload_carries_campaign_clusters():
    cycle = _cycle(cluster_findings=[
        {"rule_id": "G001", "params": {"members": ["a", "b", "c"]}},
    ])
    payload = alert_payload(cycle)
    assert payload["campaign_cluster"] == [
        {"rule_id": "G001", "members": ["a", "b", "c"], "count": 3},
    ]


def test_context_cluster_findings_are_not_campaigns():
    """H057/H060/H061 are weight-0 corpus context, not G-series campaigns:
    counting them made a centrality pass read as hundreds of campaigns.  G006
    is bounded neighbourhood context, and a one-member "cluster" is a
    single-package signal, so neither is a campaign either."""
    cycle = _cycle(cluster_findings=[
        {"rule_id": "H061", "params": {"members": ["sdl2"]}},
        {"rule_id": "H060", "params": {"members": ["x"]}},
        {"rule_id": "G006", "params": {"members": ["a", "b"]}},
        {"rule_id": "G001", "params": {"members": ["solo"]}},
        {"rule_id": "G002", "params": {"members": ["a", "b"]}},
    ])
    payload = alert_payload(cycle)
    assert payload["campaign_cluster"] == [
        {"rule_id": "G002", "members": ["a", "b"], "count": 2},
    ]
    assert "campaign across 2 packages (G002)" in payload["title"]


def test_burst_clusters_are_not_campaigns():
    """H055 (attribute burst) and H052 (shared source repo) fire on a
    maintainer's own variant family.  Even with several members they are not
    campaigns: a past build listed 226 H061 hubs and a burst family in the
    feed's campaign_cluster, which is what this pins shut."""
    cycle = _cycle(cluster_findings=[
        {"rule_id": "H055",
         "params": {"members": ["bnb-shell", "bnb-extra"], "impersonated": False}},
        {"rule_id": "H052",
         "params": {"members": ["fam-a", "fam-b"], "impersonated": True}},
        {"rule_id": "G002", "params": {"members": ["a", "b"]}},
    ])
    payload = alert_payload(cycle)
    assert [c["rule_id"] for c in payload["campaign_cluster"]] == ["G002"]
    assert "H055" not in payload["title"]
    assert "H052" not in payload["title"]


def test_payload_leads_with_an_impersonation_campaign():
    cycle = _cycle(
        cluster_findings=[{
            "rule_id": "G005",
            "params": {"members": ["yyay", "parru", "yau"],
                       "maintainer": "marchos1as",
                       "targets": ["yay", "paru"], "count": 3},
        }],
        new_alerts=[("yyay", "G005")],
    )
    payload = alert_payload(cycle)
    assert payload["impersonation"] == [{
        "maintainer": "marchos1as", "members": ["yyay", "parru", "yau"],
        "targets": ["yay", "paru"], "count": 3,
    }]
    assert payload["title"].startswith(
        "TrustSight: impersonation campaign by marchos1as")


# --- the signed feed sink ---------------------------------------------------


def _ed25519_keypair() -> tuple[str, object]:
    """A fresh Ed25519 key: (base64 PKCS#8 private, private key object)."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat,
    )

    priv = Ed25519PrivateKey.generate()
    der = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    return base64.b64encode(der).decode(), priv


def test_the_feed_signature_verifies_against_the_public_key(monkeypatch):
    import base64

    from trustsight.notify import _sign_feed

    key_b64, priv = _ed25519_keypair()
    body = json.dumps({"event": "trustsight.alerts", "tool": "trustsight"}).encode()
    headers = _sign_feed(key_b64, "k1", body)

    material = (f"{headers['webhook-id']}.{headers['webhook-timestamp']}."
                .encode() + body)
    signature = base64.b64decode(headers["webhook-signature"].removeprefix("v1="))
    # raises InvalidSignature if the material or key is wrong
    priv.public_key().verify(signature, material)
    assert headers["webhook-key-id"] == "k1"


def test_the_feed_sink_posts_the_same_document_signed(monkeypatch):
    key_b64, _priv = _ed25519_keypair()
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY", key_b64)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")

    ntfy = _Receiver()
    feed = _Receiver()
    try:
        monkeypatch.setattr("trustsight.notify.feed_url", lambda *a, **k: feed.url)
        cycle = CycleResult(over_threshold=[("hot-pkg", 45)],
                            new_alerts=[("hot-pkg", "H001")])
        assert maybe_notify(cycle, ntfy.url) is True

        assert len(ntfy.requests) == 1
        assert len(feed.requests) == 1
        # The feed gets the same document the human channel gets.
        assert feed.requests[0][1] == ntfy.requests[0][1]
        headers = feed.headers_seen[0]
        assert headers["webhook-id"]
        assert headers["webhook-timestamp"].isdigit()
        assert headers["webhook-key-id"] == "k1"
        assert headers["webhook-signature"].startswith("v1=")
    finally:
        ntfy.stop()
        feed.stop()


def test_the_feed_sink_is_skipped_without_a_key(monkeypatch):
    monkeypatch.delenv("TRUSTSIGHT_FEED_KEY", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_FEED_KEY_ID", raising=False)

    ntfy = _Receiver()
    feed = _Receiver()
    try:
        monkeypatch.setattr("trustsight.notify.feed_url", lambda *a, **k: feed.url)
        cycle = CycleResult(over_threshold=[("hot-pkg", 45)],
                            new_alerts=[("hot-pkg", "H001")])
        assert maybe_notify(cycle, ntfy.url) is True
        assert len(ntfy.requests) == 1
        assert feed.requests == []
    finally:
        ntfy.stop()
        feed.stop()
