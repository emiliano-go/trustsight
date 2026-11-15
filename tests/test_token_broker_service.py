"""The local broker re-reads token files and fails closed."""

from __future__ import annotations

from typer.testing import CliRunner

from trustsight import token_broker_service as service
from trustsight.cli.app import app


def _write(tmp_path, provider="github", token="value", expires=None):
    (tmp_path / f"{provider}.token").write_text(token)
    if expires is not None:
        (tmp_path / f"{provider}.expires").write_text(str(expires))


def test_a_valid_token_is_served(tmp_path):
    _write(tmp_path, expires=9999999999)
    result = service.handle_request({"provider": "github"}, str(tmp_path))
    assert result == {
        "ok": True, "token": "value", "expires_at": 9999999999.0}


def test_a_missing_token_is_an_error(tmp_path):
    result = service.handle_request({"provider": "github"}, str(tmp_path))
    assert result["ok"] is False


def test_an_expired_token_is_refused(tmp_path):
    _write(tmp_path, expires=1)
    result = service.handle_request({"provider": "github"}, str(tmp_path))
    assert result["ok"] is False
    assert "expired" in result["error"]


def test_a_malformed_expiry_is_refused(tmp_path):
    _write(tmp_path, expires="tomorrow")
    result = service.handle_request({"provider": "github"}, str(tmp_path))
    assert result["ok"] is False


def test_path_like_provider_names_are_refused(tmp_path):
    result = service.handle_request({"provider": "../github"}, str(tmp_path))
    assert result["ok"] is False
    assert "provider" in result["error"]


def test_the_broker_command_is_registered():
    result = CliRunner().invoke(app, ["token-broker", "--help"], terminal_width=200)
    assert result.exit_code == 0
    assert "--token-dir" in result.stdout
