"""The separate upstream fetcher owns the token and verifies bytes."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading


from trustsight import upstream_fetcher_service as service
from trustsight.cli.app import app
from trustsight.upstream_fetcher_client import fetch_from_socket

DATA = b"verified archive"
SHA256 = hashlib.sha256(DATA).hexdigest()


def _config(enabled=True):
    return {"upstream_scan": {
        "enabled": enabled,
        "allowed_hosts": ["github.com"],
    }}


def test_handle_request_returns_verified_bytes(monkeypatch):
    monkeypatch.setattr(service, "load_config", lambda: _config())
    monkeypatch.setattr(service, "resolve_token", lambda provider: None)
    monkeypatch.setattr(service, "fetch_bytes", lambda *a, **k: DATA)

    result = service.handle_request({
        "url": "https://github.com/o/r/archive/v1.tar.gz",
        "expected": SHA256,
        "algorithm": "sha256",
    })
    assert result["ok"] is True
    assert base64.b64decode(result["data"]) == DATA


def test_handle_request_refuses_a_disabled_lane(monkeypatch):
    monkeypatch.setattr(service, "load_config", lambda: _config(enabled=False))
    result = service.handle_request({
        "url": "https://github.com/o/r/archive/v1.tar.gz",
        "expected": SHA256,
        "algorithm": "sha256",
    })
    assert result["ok"] is False
    assert "disabled" in result["error"]


def test_handle_request_refuses_a_checksum_mismatch(monkeypatch):
    monkeypatch.setattr(service, "load_config", lambda: _config())
    monkeypatch.setattr(service, "resolve_token", lambda provider: None)
    monkeypatch.setattr(service, "fetch_bytes", lambda *a, **k: b"other")
    result = service.handle_request({
        "url": "https://github.com/o/r/archive/v1.tar.gz",
        "expected": SHA256,
        "algorithm": "sha256",
    })
    assert result["ok"] is False
    assert "checksum" in result["error"]


def test_client_reads_a_socket_response(tmp_path):
    path = str(tmp_path / "fetch.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def reply():
        conn, _ = server.accept()
        with conn:
            conn.recv(4096)
            body = json.dumps({
                "ok": True,
                "data": base64.b64encode(DATA).decode("ascii"),
            }).encode()
            conn.sendall(body + b"\n")
        server.close()

    thread = threading.Thread(target=reply, daemon=True)
    thread.start()
    data = fetch_from_socket(
        path, url="https://github.com/o/r/archive/v1.tar.gz",
        expected=SHA256, algorithm="sha256", min_bits=256,
        max_bytes=1024, deadline_seconds=5,
    )
    assert data == DATA
    thread.join(timeout=5)


def test_the_fetcher_command_is_registered():
    from typer.main import get_command

    params = get_command(app).commands["upstream-fetcher"].params
    assert "--socket" in {opt for param in params for opt in param.opts}
