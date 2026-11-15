"""The feed signer owns the key and returns only signature headers."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading

import pytest

from trustsight import feed_signer_service as service
from trustsight.cli.app import app
from trustsight.feed_signer_client import sign_via_socket


def _keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat,
    )

    priv = Ed25519PrivateKey.generate()
    der = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    return base64.b64encode(der).decode(), priv


def test_signer_returns_a_valid_signature(monkeypatch):
    key_b64, priv = _keypair()
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY", key_b64)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")
    body = b'{"event":"trustsight.alerts","alerts":[]}'
    result = service.handle_request({
        "body": base64.b64encode(body).decode(),
    })
    assert result["ok"] is True
    headers = result["headers"]
    material = (f"{headers['webhook-id']}."
                f"{headers['webhook-timestamp']}.").encode() + body
    signature = base64.b64decode(headers["webhook-signature"].removeprefix("v1="))
    priv.public_key().verify(signature, material)
    assert headers["webhook-key-id"] == "k1"


def test_signer_without_a_key_refuses(monkeypatch):
    monkeypatch.delenv("TRUSTSIGHT_FEED_KEY", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_FEED_KEY_FILE", raising=False)
    result = service.handle_request({
        "body": base64.b64encode(b'{"event":"trustsight.alerts","alerts":[]}').decode(),
    })
    assert result["ok"] is False


def test_signer_records_a_bounded_audit_line(monkeypatch, tmp_path):
    key_b64, _priv = _keypair()
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY", key_b64)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")
    audit = tmp_path / "signatures.jsonl"
    body = b'{"event":"trustsight.alerts","alerts":[]}'
    result = service.handle_request(
        {"body": base64.b64encode(body).decode()}, audit_log=str(audit))
    assert result["ok"] is True
    record = json.loads(audit.read_text().strip())
    assert record["event"] == "trustsight.alerts"
    assert record["key_id"] == "k1"
    assert record["bytes"] == len(body)
    assert record["body_sha256"] == hashlib.sha256(body).hexdigest()


def test_signer_audit_records_are_chained(monkeypatch, tmp_path):
    key_b64, _priv = _keypair()
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY", key_b64)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")
    audit = tmp_path / "signatures.jsonl"
    body = base64.b64encode(
        b'{"event":"trustsight.alerts","alerts":[]}').decode()
    for _ in range(2):
        assert service.handle_request(
            {"body": body}, audit_log=str(audit))["ok"] is True
    first, second = [
        json.loads(line) for line in audit.read_text().splitlines()
    ]
    assert first["prev"] == ""
    assert second["prev"] == first["chain_sha256"]
    unsigned = {k: v for k, v in first.items() if k != "chain_sha256"}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    assert first["chain_sha256"] == hashlib.sha256(payload.encode()).hexdigest()


def test_signer_publishes_the_chain_head(monkeypatch, tmp_path):
    key_b64, _priv = _keypair()
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY", key_b64)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")
    audit = tmp_path / "signatures.jsonl"
    head = tmp_path / "head.json"
    body = base64.b64encode(
        b'{"event":"trustsight.alerts","alerts":[]}').decode()
    assert service.handle_request(
        {"body": body}, audit_log=str(audit), audit_head=str(head))["ok"] is True
    last = json.loads(audit.read_text().splitlines()[-1])
    published = json.loads(head.read_text())
    assert published["chain_sha256"] == last["chain_sha256"]


def test_startup_refuses_a_head_that_does_not_match_the_log(monkeypatch, tmp_path):
    key_b64, _priv = _keypair()
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY", key_b64)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")
    audit = tmp_path / "signatures.jsonl"
    head = tmp_path / "head.json"
    body = base64.b64encode(
        b'{"event":"trustsight.alerts","alerts":[]}').decode()
    assert service.handle_request(
        {"body": body}, audit_log=str(audit), audit_head=str(head))["ok"] is True
    service._verify_head(str(audit), str(head))
    head.write_text('{"chain_sha256": "' + "0" * 64 + '"}\n')
    with pytest.raises(RuntimeError):
        service._verify_head(str(audit), str(head))


def test_signer_refuses_the_wrong_shape_for_an_event():
    result = service.handle_request({
        "body": base64.b64encode(b'{"event":"trustsight.alerts"}').decode(),
    })
    assert result["ok"] is False
    assert "wrong shape" in result["error"]


def test_signer_rate_limits_an_abused_socket(monkeypatch):
    key_b64, _priv = _keypair()
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY", key_b64)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")
    limiter = service.SignerLimiter(max_events=1, window_seconds=60.0)
    body = {"body": base64.b64encode(
        b'{"event":"trustsight.alerts","alerts":[]}').decode()}
    assert service.handle_request(body, limiter=limiter)["ok"] is True
    assert service.handle_request(body, limiter=limiter)["ok"] is False
    assert "rate limit" in service.handle_request(body, limiter=limiter)["error"]


def test_signer_refuses_an_unknown_event():
    result = service.handle_request({
        "body": base64.b64encode(b'{"event":"other"}').decode(),
    })
    assert result["ok"] is False
    assert "known feed event" in result["error"]


def test_client_reads_headers_from_the_socket(monkeypatch, tmp_path):
    key_b64, _priv = _keypair()
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY", key_b64)
    monkeypatch.setenv("TRUSTSIGHT_FEED_KEY_ID", "k1")
    path = str(tmp_path / "feed-signer.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def reply():
        conn, _ = server.accept()
        with conn:
            conn.recv(65536)
            response = service.handle_request({
                "body": base64.b64encode(
                    b'{"event":"trustsight.alerts","alerts":[]}').decode(),
            })
            conn.sendall(json.dumps(response).encode() + b"\n")
        server.close()

    threading.Thread(target=reply, daemon=True).start()
    headers = sign_via_socket(path, b'{"event":"trustsight.alerts","alerts":[]}')
    assert headers["webhook-signature"].startswith("v1=")


def test_the_watcher_uses_the_signer_and_has_no_feed_key():
    import yaml
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    compose = yaml.safe_load((root / "docker-compose.watcher.yml").read_text())
    watcher = compose["services"]["trustsight-watch"]
    signer = compose["services"]["feed-signer"]
    assert watcher["environment"][
        "TRUSTSIGHT_FEED_SIGNER_SOCKET"] == "/run/trustsight/feed-signer.sock"
    assert "TRUSTSIGHT_FEED_KEY" not in watcher["environment"]
    assert "TRUSTSIGHT_FEED_KEY_FILE" not in watcher["environment"]
    assert signer["network_mode"] == "none"


def test_the_feed_signer_command_is_registered():
    from typer.main import get_command

    params = get_command(app).commands["feed-signer"].params
    assert "--socket" in {opt for param in params for opt in param.opts}
