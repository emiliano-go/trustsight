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
