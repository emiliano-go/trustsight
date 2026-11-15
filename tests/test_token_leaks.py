"""A provider token must not appear in renderings, errors or request logs."""

from __future__ import annotations

import pytest

from trustsight.credentials import Secret
from trustsight.upstream_fetch import UpstreamFetchError, fetch_bytes


def test_a_secret_never_renders_its_value():
    secret = Secret("github", "ghp_canary_value")
    rendered = f"{secret} {secret!r} {secret.label}"
    assert "ghp_canary_value" not in rendered
    assert secret.reveal() == "ghp_canary_value"


def test_a_fetch_error_does_not_echo_the_token():
    secret = Secret("github", "ghp_canary_value")
    with pytest.raises(UpstreamFetchError) as caught:
        fetch_bytes(
            "https://github.com/owner/repo", token=secret,
            allowed_hosts={"github.com"},
            resolver=lambda host, port: [
                (2, 1, 6, "", ("127.0.0.1", port))])
    assert "ghp_canary_value" not in str(caught.value)


def test_a_token_is_not_logged_when_a_request_fails(caplog):
    secret = Secret("github", "ghp_canary_value")

    class _Failing:
        def connect(self):
            raise OSError("dial failed")

        def close(self):
            pass

    with caplog.at_level("DEBUG"), pytest.raises(UpstreamFetchError):
        fetch_bytes(
            "https://github.com/owner/repo", token=secret,
            allowed_hosts={"github.com"},
            resolver=lambda host, port: [
                (2, 1, 6, "", ("93.184.216.34", port))],
            connection_factory=lambda *a: _Failing())
    assert "ghp_canary_value" not in caplog.text
