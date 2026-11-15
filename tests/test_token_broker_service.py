"""The local broker re-reads token files and fails closed."""

from __future__ import annotations

import json
import sys

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
    from typer.main import get_command

    params = get_command(app).commands["token-broker"].params
    assert "--token-dir" in {opt for param in params for opt in param.opts}


def _command(tmp_path, output, *, exit_code=0):
    script = tmp_path / "credential"
    script.write_text(
        f"#!{sys.executable}\n"
        f"import sys\n"
        f"if {exit_code}: sys.exit({exit_code})\n"
        f"sys.stdout.write({output!r})\n")
    script.chmod(0o755)
    return str(script) + " {provider}"


def test_a_credential_command_can_issue_a_token(tmp_path):
    result = service.handle_request(
        {"provider": "github"}, str(tmp_path),
        _command(tmp_path, json.dumps({"token": "short", "expires_at": 9999999999})))
    assert result == {"ok": True, "token": "short", "expires_at": 9999999999.0}


def test_a_credential_command_can_print_a_plain_token(tmp_path):
    result = service.handle_request(
        {"provider": "github"}, str(tmp_path), _command(tmp_path, "plain"))
    assert result["ok"] is True
    assert result["token"] == "plain"


def test_a_failing_credential_command_is_refused(tmp_path):
    result = service.handle_request(
        {"provider": "github"}, str(tmp_path),
        _command(tmp_path, "nope", exit_code=3))
    assert result["ok"] is False


def test_an_expired_credential_command_token_is_refused(tmp_path):
    result = service.handle_request(
        {"provider": "github"}, str(tmp_path),
        _command(tmp_path, json.dumps({"token": "old", "expires_at": 1})))
    assert result["ok"] is False
    assert "expired" in result["error"]
