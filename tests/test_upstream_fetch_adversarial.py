"""URL/redirect edge cases the fetch boundary must refuse."""

from __future__ import annotations

import pytest

from trustsight.upstream_fetch import UpstreamFetchError, fetch_bytes

ALLOWED = frozenset({"github.com", "codeload.github.com"})


def _resolver(*addresses):
    def resolve(host, port):
        return [(2, 1, 6, "", (address, port)) for address in addresses]
    return resolve


class _Response:
    def __init__(self, status=200, body=b"body", location=None):
        self.status = status
        self.body = body
        self.location = location

    def read(self, _size):
        body, self.body = self.body, b""
        return body

    def getheader(self, name, default=None):
        return self.location if name.lower() == "location" else default


class _Connection:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def connect(self):
        pass

    def request(self, method, path, headers=None):
        self.calls.append((method, path, dict(headers or {})))

    def getresponse(self):
        return self.response

    def close(self):
        pass


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://github.com/owner/repo",
    "https://user@github.com/owner/repo",
    "https://github.com:444/owner/repo",
    "https://127.0.0.1/owner/repo",
    "https://[::1]/owner/repo",
    "https://169.254.169.254/owner/repo",
    "https://2130706433/owner/repo",
    "https://github.com@evil.example/owner/repo",
])
def test_disallowed_url_forms_are_refused_before_dialing(url):
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(url, allowed_hosts=ALLOWED,
                    resolver=_resolver("93.184.216.34"))


def test_a_redirect_to_plain_http_is_refused():
    connection = _Connection(_Response(302, location="http://github.com/x"))
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            "https://github.com/owner/repo", allowed_hosts=ALLOWED,
            resolver=_resolver("93.184.216.34"),
            connection_factory=lambda *a: connection)


def test_a_redirect_without_a_location_is_refused():
    connection = _Connection(_Response(302, location=None))
    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            "https://github.com/owner/repo", allowed_hosts=ALLOWED,
            resolver=_resolver("93.184.216.34"),
            connection_factory=lambda *a: connection)


def test_a_redirect_loop_hits_the_redirect_cap():
    class Looping(_Connection):
        def getresponse(self):
            return _Response(
                302, location="https://github.com/owner/repo")

    with pytest.raises(UpstreamFetchError):
        fetch_bytes(
            "https://github.com/owner/repo", allowed_hosts=ALLOWED,
            resolver=_resolver("93.184.216.34"),
            connection_factory=lambda *a: Looping(_Response()),
            max_redirects=2)
