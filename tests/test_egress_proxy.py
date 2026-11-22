"""The egress proxy accepts only the exact forge/CDN allowlist on 443."""

from __future__ import annotations

import json
import socket
import threading

import pytest

from trustsight import egress_proxy


def _request(authority: str) -> bytes:
    return f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()


@pytest.mark.parametrize("host", [
    "github.com", "gitlab.com", "codeberg.org", "bitbucket.org",
    "codeload.github.com", "objects.githubusercontent.com",
    "raw.githubusercontent.com", "aur.archlinux.org", "api.github.com",
    "watcher.trustsight.org", "ntfy.sh",
])
def test_allowlisted_hosts_parse(host):
    assert egress_proxy._parse_connect(_request(f"{host}:443")) == (host, 443)


@pytest.mark.parametrize("authority", [
    "evil.example:443",
    "github.com:80",
    "github.com",
    "user@github.com:443",
    "github.com:443/path",
    "169.254.169.254:443",
])
def test_off_allowlist_or_non_443_is_refused(authority):
    with pytest.raises(egress_proxy.ProxyError):
        egress_proxy._parse_connect(_request(authority))


def test_handle_client_refuses_before_dialing():
    client, server = socket.socketpair()
    called = []

    def connector(*args, **kwargs):
        called.append(args)
        raise AssertionError("must not dial")

    try:
        client.sendall(_request("evil.example:443"))
        egress_proxy.handle_client(
            server, resolver=lambda *a, **k: [], connector=connector)
        response = client.recv(4096)
    finally:
        client.close()
    assert b"403" in response
    assert called == []


@pytest.mark.parametrize("authority, expected", [
    ("GITHUB.COM:443", ("github.com", 443)),
    ("github.com.:443", ("github.com", 443)),
])
def test_allowed_hosts_are_normalised(authority, expected):
    assert egress_proxy._parse_connect(_request(authority)) == expected


@pytest.mark.parametrize("authority", [
    "[::1]:443",
    "github.com.evil.example:443",
    "aur.archlinux.org.evil:443",
    "github.com:4430",
])
def test_lookalike_and_unusual_authorities_are_refused(authority):
    with pytest.raises(egress_proxy.ProxyError):
        egress_proxy._parse_connect(_request(authority))


def test_an_unavailable_audit_log_denies_egress(tmp_path):
    client, server = socket.socketpair()
    called = []
    try:
        client.sendall(_request("github.com:443"))
        egress_proxy.handle_client(
            server,
            resolver=lambda *a, **k: [
                (None, None, None, None, ("1.1.1.1", 443))],
            connector=lambda *a, **k: called.append(a),
            audit_log=str(tmp_path / "missing" / "audit.jsonl"))
        response = client.recv(4096)
    finally:
        client.close()
    assert b"403" in response
    assert called == []


def test_the_extra_allowlist_rejects_ip_wildcard_and_port(monkeypatch):
    monkeypatch.setenv(
        "TRUSTSIGHT_EGRESS_ALLOW",
        "ntfy.example.org,*.evil.example,127.0.0.1,host:443,/path",
    )
    assert egress_proxy._env_extra_hosts() == frozenset({"ntfy.example.org"})


def test_a_private_resolution_is_refused_before_connecting():
    client, server = socket.socketpair()
    called = []
    try:
        client.sendall(_request("github.com:443"))
        egress_proxy.handle_client(
            server,
            resolver=lambda *a, **k: [
                (None, None, None, None, ("127.0.0.1", 443))],
            connector=lambda *a, **k: called.append(a))
        response = client.recv(4096)
    finally:
        client.close()
    assert b"403" in response
    assert called == []


def test_handle_client_tunnels_an_allowlisted_connect(tmp_path):
    client, server = socket.socketpair()
    upstream, upstream_peer = socket.socketpair()
    resolver_calls = []

    def resolver(host, port, **kwargs):
        resolver_calls.append((host, port))
        return [(None, None, None, None, ("1.1.1.1", port))]

    def connector(address, timeout):
        return upstream

    audit = tmp_path / "proxy.jsonl"
    thread = threading.Thread(
        target=egress_proxy.handle_client,
        kwargs={"resolver": resolver, "connector": connector,
                "audit_log": str(audit)},
        args=(server,), daemon=True)
    thread.start()
    try:
        client.sendall(_request("github.com:443"))
        response = client.recv(4096)
        assert b"200 Connection Established" in response
        client.sendall(b"client-to-upstream")
        assert upstream_peer.recv(4096) == b"client-to-upstream"
        upstream_peer.sendall(b"upstream-to-client")
        assert client.recv(4096) == b"upstream-to-client"
    finally:
        client.close()
        upstream_peer.close()
    thread.join(timeout=5)
    assert resolver_calls == [("github.com", 443)]
    record = json.loads(audit.read_text().strip())
    assert record["allowed"] is True
    assert record["host"] == "github.com"


def _basic(token: str) -> bytes:
    import base64
    return b"Proxy-Authorization: Basic " + base64.b64encode(
        f"trustsight:{token}".encode()) + b"\r\n"


def test_proxy_auth_requires_a_matching_password():
    request = (_request("github.com:443").replace(
        b"\r\n\r\n", b"\r\n") + _basic("secret") + b"\r\n")
    assert egress_proxy._authorised(request, "secret") is True
    assert egress_proxy._authorised(request, "other") is False
    assert egress_proxy._authorised(_request("github.com:443"), "secret") is False
    assert egress_proxy._authorised(_request("github.com:443"), None) is True


def test_a_refused_connect_can_alert(monkeypatch):
    import trustsight.alerts as alerts

    calls = []
    monkeypatch.setattr(alerts, "send",
                        lambda url, payload: calls.append((url, payload)) or True)
    client, server = socket.socketpair()
    try:
        client.sendall(_request("evil.example:443"))
        egress_proxy.handle_client(
            server, resolver=lambda *a, **k: [],
            alert_url="https://alerts.example/proxy")
        client.recv(4096)
    finally:
        client.close()
    assert calls[0][0] == "https://alerts.example/proxy"
    assert calls[0][1]["event"] == "trustsight.proxy_denied"


def test_default_listen_is_loopback():
    from trustsight.egress_proxy import DEFAULT_LISTEN, _listen_parts

    assert DEFAULT_LISTEN == "127.0.0.1:3128"
    assert _listen_parts(DEFAULT_LISTEN) == ("127.0.0.1", 3128)
    assert _listen_parts(":3128") == ("127.0.0.1", 3128)
