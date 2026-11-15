"""Credentials: resolution order, fail-closed keyring, and no-leak redaction."""

from __future__ import annotations

import io
import os
import stat

import pytest

from trustsight import credentials
from trustsight.credentials import (
    CredentialError,
    Secret,
    delete_token,
    normalize_provider,
    read_token_file,
    resolve_token,
    store_token,
    token_from_stdin,
    token_source,
)


class _FakeKeyring:
    def __init__(self, values=None, *, raise_on_get=False):
        self.values = dict(values or {})
        self.raise_on_get = raise_on_get
        self.deleted = []

    def get_password(self, service, name):
        if self.raise_on_get:
            raise RuntimeError("locked")
        return self.values.get((service, name))

    def set_password(self, service, name, value):
        self.values[(service, name)] = value

    def delete_password(self, service, name):
        self.deleted.append((service, name))
        self.values.pop((service, name), None)


def test_normalize_provider_accepts_the_four_and_rejects_others():
    for provider in credentials.PROVIDERS:
        assert normalize_provider(provider.upper()) == provider
    with pytest.raises(CredentialError):
        normalize_provider("sourceforge")


def test_secret_redacts_itself():
    secret = Secret("github", "ghp_supersecretvalue")
    assert "ghp_supersecretvalue" not in str(secret)
    assert "ghp_supersecretvalue" not in repr(secret)
    assert secret.reveal() == "ghp_supersecretvalue"
    assert secret.label == "...alue"


def test_resolution_prefers_systemd_then_keyring_then_file_then_env(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("from-file")
    os.chmod(token_file, 0o600)
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "github-token").write_text("from-systemd")
    os.chmod(creds / "github-token", 0o600)

    environ = {
        "CREDENTIALS_DIRECTORY": str(creds),
        "TRUSTSIGHT_GITHUB_TOKEN": "from-env",
        "TRUSTSIGHT_GITHUB_TOKEN_FILE": str(token_file),
    }
    keyring = _FakeKeyring({("trustsight", "github"): "from-keyring"})

    secret, source = token_source("github", environ=environ, keyring_backend=keyring)
    assert secret.reveal() == "from-systemd"
    assert source == "systemd credential"

    (creds / "github-token").unlink()
    secret, source = token_source("github", environ=environ, keyring_backend=keyring)
    assert secret.reveal() == "from-keyring"
    assert source == "OS keyring"

    keyring.values.clear()
    secret, source = token_source("github", environ=environ, keyring_backend=keyring)
    assert secret.reveal() == "from-file"
    assert source == "0600 token file"

    environ.pop("TRUSTSIGHT_GITHUB_TOKEN_FILE")
    secret, source = token_source("github", environ=environ, keyring_backend=keyring)
    assert secret.reveal() == "from-env"
    assert source == "environment"


def test_no_source_returns_none():
    assert resolve_token("github", environ={}, keyring_backend=_FakeKeyring()) is None


def _broker(tmp_path, payload):
    import json
    import socket
    import threading

    path = str(tmp_path / "token.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(json.dumps(payload).encode() + b"\n")
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return path


def test_the_canary_is_never_used_as_a_live_token(caplog):
    environ = {
        "TRUSTSIGHT_GITHUB_TOKEN": "canary-value",
        "TRUSTSIGHT_CANARY_TOKEN": "canary-value",
    }
    with caplog.at_level("CRITICAL"), pytest.raises(CredentialError):
        resolve_token("github", environ=environ, keyring_backend=_FakeKeyring())
    assert "canary" in caplog.text
    assert "canary-value" not in caplog.text


def test_a_real_token_still_works_with_a_canary_configured():
    environ = {
        "TRUSTSIGHT_GITHUB_TOKEN": "real-value",
        "TRUSTSIGHT_CANARY_TOKEN": "canary-value",
    }
    secret = resolve_token(
        "github", environ=environ, keyring_backend=_FakeKeyring())
    assert secret.reveal() == "real-value"


def test_a_broker_token_is_used(tmp_path):
    path = _broker(tmp_path, {"token": "broker-value", "expires_at": 9999999999})
    secret = resolve_token(
        "github",
        environ={"TRUSTSIGHT_GITHUB_TOKEN_SOCKET": path},
        keyring_backend=_FakeKeyring(),
    )
    assert secret.reveal() == "broker-value"


def test_an_expired_broker_token_is_refused(tmp_path):
    path = _broker(tmp_path, {"token": "broker-value", "expires_at": 1})
    with pytest.raises(CredentialError):
        resolve_token(
            "github",
            environ={"TRUSTSIGHT_GITHUB_TOKEN_SOCKET": path},
            keyring_backend=_FakeKeyring(),
        )


def test_a_missing_broker_fails_closed(tmp_path):
    with pytest.raises(CredentialError):
        resolve_token(
            "github",
            environ={"TRUSTSIGHT_GITHUB_TOKEN_SOCKET": str(tmp_path / "none.sock")},
            keyring_backend=_FakeKeyring(),
        )


def test_an_expired_token_is_refused_without_fallback():
    environ = {
        "TRUSTSIGHT_GITHUB_TOKEN": "env-value",
        "TRUSTSIGHT_GITHUB_TOKEN_EXPIRES_AT": "1",
    }
    with pytest.raises(CredentialError):
        resolve_token("github", environ=environ, keyring_backend=_FakeKeyring())


def test_a_future_expiry_is_accepted():
    import time

    environ = {
        "TRUSTSIGHT_GITHUB_TOKEN": "env-value",
        "TRUSTSIGHT_GITHUB_TOKEN_EXPIRES_AT": str(int(time.time()) + 3600),
    }
    secret = resolve_token(
        "github", environ=environ, keyring_backend=_FakeKeyring())
    assert secret.reveal() == "env-value"


def test_a_malformed_expiry_fails_closed():
    environ = {
        "TRUSTSIGHT_GITHUB_TOKEN": "env-value",
        "TRUSTSIGHT_GITHUB_TOKEN_EXPIRES_AT": "tomorrow",
    }
    with pytest.raises(CredentialError):
        resolve_token("github", environ=environ, keyring_backend=_FakeKeyring())


def test_a_locked_keyring_fails_closed():
    with pytest.raises(CredentialError):
        resolve_token(
            "github",
            environ={"TRUSTSIGHT_GITHUB_TOKEN": "env-value"},
            keyring_backend=_FakeKeyring(raise_on_get=True),
        )


def test_open_permissions_are_warned_but_still_used(tmp_path, caplog):
    token_file = tmp_path / "token"
    token_file.write_text("world-readable")
    os.chmod(token_file, stat.S_IRUSR | stat.S_IROTH)
    with caplog.at_level("WARNING"):
        secret = resolve_token(
            "github",
            environ={"TRUSTSIGHT_GITHUB_TOKEN_FILE": str(token_file)},
            keyring_backend=_FakeKeyring(),
        )
    assert secret.reveal() == "world-readable"
    assert any("0600" in record.getMessage() for record in caplog.records)


def test_store_and_delete_go_through_the_keyring():
    keyring = _FakeKeyring()
    store_token("gitlab", "glpat-value", keyring_backend=keyring)
    assert keyring.values[("trustsight", "gitlab")] == "glpat-value"
    assert delete_token("gitlab", keyring_backend=keyring) is True
    assert ("trustsight", "gitlab") not in keyring.values


def test_store_refuses_an_empty_token():
    with pytest.raises(CredentialError):
        store_token("github", "   ", keyring_backend=_FakeKeyring())


def test_token_from_stdin_is_bounded_and_stripped():
    assert token_from_stdin(io.StringIO("  abc  \n")) == "abc"
    with pytest.raises(CredentialError):
        token_from_stdin(io.StringIO("x" * 5000))


def test_read_token_file_refuses_group_or_other_readable_files(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("secret-value")
    os.chmod(token_file, 0o644)
    with pytest.raises(CredentialError):
        read_token_file(token_file)

    os.chmod(token_file, 0o600)
    assert read_token_file(token_file) == "secret-value"


def test_read_token_file_is_bounded(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("x" * 5000)
    os.chmod(token_file, 0o600)
    with pytest.raises(CredentialError):
        read_token_file(token_file)


def test_the_canary_can_send_an_alert_without_leaking_it(monkeypatch):
    calls = []

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, size): return b""

    def fake(request, timeout):
        calls.append((request.full_url, request.data))
        return Response()

    import trustsight.alerts as alerts
    monkeypatch.setattr(alerts.urllib.request, "urlopen", fake)
    environ = {
        "TRUSTSIGHT_GITHUB_TOKEN": "canary-value",
        "TRUSTSIGHT_CANARY_TOKEN": "canary-value",
        "TRUSTSIGHT_CANARY_ALERT_URL": "https://alerts.example/canary",
    }
    with pytest.raises(CredentialError):
        resolve_token("github", environ=environ, keyring_backend=_FakeKeyring())
    assert calls[0][0] == "https://alerts.example/canary"
    assert b"canary-value" not in calls[0][1]
