"""The upstream transport: pinning, redirects, caps, and auth scope."""

from __future__ import annotations

import pytest

from trustsight.credentials import Secret
from trustsight.upstream_fetch import UpstreamFetchError, fetch_bytes
from trustsight.upstream_scan import DEFAULT_ALLOWED_HOSTS

ALLOWED = frozenset(DEFAULT_ALLOWED_HOSTS)
URL = "https://github.com/owner/repo/releases/download/v1/a.tar.gz"
CDN = "https://codeload.github.com/owner/repo/tar.gz/refs/tags/v1"


def _resolver(*addresses):
    def resolve(host, port):
        return [(2, 1, 6, "", (address, port)) for address in addresses]
    return resolve


class _Response:
    def __init__(self, status=200, chunks=(b"body",), location=None):
        self.status = status
        self._chunks = list(chunks)
        self._location = location

    def read(self, _size):
        return self._chunks.pop(0) if self._chunks else b""

    def getheader(self, name, default=None):
        return self._location if name.lower() == "location" else default


class _PeerSocket:
    def __init__(self, address):
        self.address = address
        self.timeout = None

    def getpeername(self):
        return (self.address, 443)

    def settimeout(self, timeout):
        self.timeout = timeout


class _Connection:
    def __init__(self, host, address, response, sink):
        self.host = host
        self.response = response
        self.sink = sink
        self.sock = _PeerSocket(address)

    def connect(self):
        self.sink["connected"] = True

    def request(self, method, path, headers=None):
        self.sink.setdefault("calls", []).append(
            {"host": self.host, "path": path, "headers": dict(headers or {})})

    def getresponse(self):
        return self.response

    def close(self):
        self.sink["closed"] = True


def _factory(responses, sink):
    queue = list(responses)

    def build(host, address, timeout):
        sink["address"] = address
        return _Connection(host, address, queue.pop(0), sink)
    return build


def test_fetch_returns_the_body_and_sends_no_token_by_default():
    sink = {}
    body = fetch_bytes(
        URL, allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
        connection_factory=_factory([_Response(chunks=[b"abc", b"def"])], sink))
    assert body == b"abcdef"
    assert sink["address"] == "93.184.216.34"
    assert "Authorization" not in sink["calls"][0]["headers"]
    assert sink["closed"] is True
    assert sink["calls"][0]["path"].startswith("/owner/repo/releases/")


def test_fetch_sends_the_token_only_when_given():
    sink = {}
    fetch_bytes(
        URL, allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
        token=Secret("github", "ghp_secret"),
        connection_factory=_factory([_Response()], sink))
    assert sink["calls"][0]["headers"]["Authorization"] == "Bearer ghp_secret"


def test_fetch_follows_a_redirect_to_a_forge_cdn_without_the_token():
    sink = {}
    body = fetch_bytes(
        URL, allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
        token=Secret("github", "ghp_secret"),
        connection_factory=_factory([
            _Response(status=302, location=CDN),
            _Response(chunks=[b"archive"]),
        ], sink))
    assert body == b"archive"
    assert [call["host"] for call in sink["calls"]] == [
        "github.com", "codeload.github.com"]
    assert "Authorization" not in sink["calls"][1]["headers"]


def test_fetch_refuses_a_redirect_to_an_off_allowlist_host():
    sink = {}
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            URL, allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
            connection_factory=_factory([
                _Response(status=302, location="https://evil.example/x"),
                _Response(),
            ], sink))


def test_fetch_refuses_a_non_200():
    sink = {}
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            URL, allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
            connection_factory=_factory([_Response(status=500)], sink))


def test_fetch_refuses_a_body_past_the_cap():
    sink = {}
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            URL, allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
            max_bytes=3,
            connection_factory=_factory([_Response(chunks=[b"toolarge"])], sink))


def test_fetch_refuses_a_path_outside_the_validated_repo():
    sink = {}
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            "https://github.com/owner/repo/../other/x",
            allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
            connection_factory=_factory([_Response()], sink))
    assert "calls" not in sink


def test_fetch_refuses_an_off_allowlist_host_before_dialing():
    sink = {}
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            "https://evil.example/owner/repo/a.tar.gz",
            allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
            connection_factory=_factory([_Response()], sink))
    assert "calls" not in sink


def test_fetch_refuses_a_private_resolution():
    sink = {}
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            URL, allowed_hosts=ALLOWED, resolver=_resolver("10.0.0.1"),
            connection_factory=_factory([_Response()], sink))
    assert "calls" not in sink


def test_fetch_refuses_a_redirect_to_another_allowlisted_forge():
    sink = {}
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            URL, allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
            connection_factory=_factory([
                _Response(status=302,
                          location="https://gitlab.com/owner/repo/x"),
                _Response(),
            ], sink))


def test_fetch_refuses_a_peer_that_differs_from_the_pinned_address():
    sink = {}
    def build(host, address, timeout):
        connection = _Connection(host, "10.0.0.1", _Response(), sink)
        return connection
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            URL, allowed_hosts=ALLOWED, resolver=_resolver("93.184.216.34"),
            connection_factory=build)
