"""Bounded, pinned HTTPS transport for the upstream-scan lane (A2/A3/A18).

This is the only module that opens a connection for the upstream lane.  It is
deliberately small and has no policy of its own beyond what
:mod:`trustsight.upstream_scan` already validated:

* the first target is re-parsed against the exact allowlist, and the request
  path must stay under the validated ``owner/repo``;
* the DNS answer is pinned, and a private/loopback/metadata answer was already
  refused by ``pin_target``;
* TLS is verified against the system store, with SNI for the hostname while the
  socket goes to the pinned address;
* a redirect is followed only to a fixed forge-CDN host, re-validated and
  re-pinned at each hop, and the body is read under a byte cap and deadline;
* the optional token is sent only on the first hop, so a redirect to a CDN
  never receives it.

The one redirect allowance is what makes a source archive reachable: GitHub
answers ``/archive/...`` and ``/releases/download/...`` with a 302 to
``codeload.github.com`` / ``objects.githubusercontent.com``.  Those hosts are
literal constants here, not package-named.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .upstream_scan import (
    ForgeTarget,
    UpstreamScanError,
    is_routable_address,
    parse_forge_target,
    pin_target,
)

__all__ = ["UpstreamFetchError", "fetch_bytes"]

_DEFAULT_TIMEOUT = 30.0
_MAX_BYTES = 67_108_864
_DEADLINE_SECONDS = 120.0
_CHUNK = 65_536
_MAX_REDIRECTS = 3
#: Hard ceilings: a caller or config value can lower these, never raise them.
_HARD_MAX_BYTES = 64 * 1024 * 1024
_HARD_DEADLINE_SECONDS = 300.0
_HARD_MAX_REDIRECTS = 5
_USER_AGENT = "trustsight-upstream/1 (+https://docs.trustsight.org)"

#: Fixed forge CDNs a GitHub/GitLab archive redirect may reach.  Literal
#: constants: a package cannot add a host here.
REDIRECT_HOSTS = frozenset({
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
})


class UpstreamFetchError(UpstreamScanError):
    """The bounded fetch failed or was refused."""


@dataclass(frozen=True)
class _Hop:
    host: str
    path: str
    send_token: bool


def _pinned_connection(pinned_address: str, port: int):
    """A ``socket.create_connection`` replacement that dials the pinned IP."""

    def create(_address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
               source_address=None):
        return socket.create_connection(
            (pinned_address, port), timeout, source_address)

    return create


def _open(host: str, address: str, timeout: float):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    connection = http.client.HTTPSConnection(
        host, 443, timeout=timeout, context=context)
    # SNI still names the hostname; only the dialed address is pinned.
    connection._create_connection = _pinned_connection(address, 443)  # type: ignore[attr-defined]
    return connection


def _request_path(url: str, target: ForgeTarget) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    prefix = f"/{target.owner}/{target.repo}"
    if not (path == prefix or path.startswith(prefix + "/")
            or path.startswith(prefix + ".git")):
        raise UpstreamFetchError(
            "request path is outside the validated owner/repo")
    if ".." in path.split("/"):
        raise UpstreamFetchError("request path carries a traversal segment")
    return path + (f"?{parts.query}" if parts.query else "")


def _first_hop(url: str, allowed_hosts) -> tuple[ForgeTarget, _Hop]:
    target = parse_forge_target(url, allowed_hosts=allowed_hosts)
    return target, _Hop(target.host, _request_path(url, target), True)


def _redirect_hop(url: str, allowed_hosts) -> _Hop:
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise UpstreamFetchError("redirect is not https")
    if parts.username or parts.password:
        raise UpstreamFetchError("redirect carries userinfo")
    try:
        port = parts.port
    except ValueError as exc:
        raise UpstreamFetchError("redirect has an invalid port") from exc
    if port not in (None, 443):
        raise UpstreamFetchError("redirect uses a non-default port")
    host = (parts.hostname or "").lower().rstrip(".")
    # A redirect may only land on a fixed forge CDN, never on another
    # allowlisted forge: the original request already chose its provider.
    if host not in REDIRECT_HOSTS:
        raise UpstreamFetchError(f"redirect host is not allowed: {host or '?'}")
    path = parts.path or "/"
    if ".." in path.split("/"):
        raise UpstreamFetchError("redirect path carries a traversal segment")
    return _Hop(host, path + (f"?{parts.query}" if parts.query else ""), False)


def _read_body(response, deadline: float, max_bytes: int, sock,
               timeout: float) -> bytes:
    body = bytearray()
    while True:
        now = time.monotonic()
        if now > deadline:
            raise UpstreamFetchError("fetch exceeded its deadline")
        if sock is not None:
            sock.settimeout(max(0.1, min(timeout, deadline - now)))
        chunk = response.read(_CHUNK)
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > max_bytes:
            raise UpstreamFetchError(f"body exceeded the {max_bytes}-byte cap")
    return bytes(body)


def fetch_bytes(
    url: str,
    *,
    allowed_hosts=None,
    token=None,
    resolver=socket.getaddrinfo,
    connection_factory=None,
    max_bytes: int = _MAX_BYTES,
    deadline_seconds: float = _DEADLINE_SECONDS,
    timeout: float = _DEFAULT_TIMEOUT,
    max_redirects: int = _MAX_REDIRECTS,
) -> bytes:
    """GET *url* and return the body, or raise :class:`UpstreamFetchError`.

    *connection_factory* is injectable for tests; it has ``_open``'s shape
    ``factory(host, address, timeout)`` and returns an object with
    ``request(method, path, headers=...)``, ``getresponse()`` and ``close()``.
    """
    if max_bytes <= 0 or deadline_seconds <= 0:
        raise UpstreamFetchError("fetch bounds must be positive")
    max_bytes = min(int(max_bytes), _HARD_MAX_BYTES)
    deadline_seconds = min(float(deadline_seconds), _HARD_DEADLINE_SECONDS)
    max_redirects = max(0, min(int(max_redirects), _HARD_MAX_REDIRECTS))
    deadline = time.monotonic() + deadline_seconds
    factory = connection_factory or _open
    try:
        target, hop = _first_hop(url, allowed_hosts)
    except UpstreamFetchError:
        raise
    except UpstreamScanError as exc:
        raise UpstreamFetchError(str(exc)) from exc
    current = url
    for attempt in range(max_redirects + 1):
        if time.monotonic() > deadline:
            raise UpstreamFetchError("fetch exceeded its deadline")
        try:
            addresses = pin_target(
                ForgeTarget(hop.host, "", ""), resolver)
        except UpstreamFetchError:
            raise
        except UpstreamScanError as exc:
            raise UpstreamFetchError(str(exc)) from exc
        connection = factory(
            hop.host, addresses[0], min(timeout, deadline_seconds))
        headers = {
            "User-Agent": _USER_AGENT,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        }
        if hop.send_token and token is not None:
            headers["Authorization"] = f"Bearer {token.reveal()}"
        try:
            # Connect before sending so the actual socket peer can be checked
            # against the address pin_target validated (DNS-rebinding close).
            connection.connect()
            peer_socket = getattr(connection, "sock", None)
            if peer_socket is None:
                raise UpstreamFetchError("connection has no socket")
            peer = peer_socket.getpeername()[0]
            try:
                same = (ipaddress.ip_address(peer)
                        == ipaddress.ip_address(addresses[0]))
            except ValueError as exc:
                raise UpstreamFetchError(
                    "socket peer is not an IP address") from exc
            if not same:
                raise UpstreamFetchError(
                    "socket peer changed after address validation")
            if not is_routable_address(peer):
                raise UpstreamFetchError(
                    "socket peer is not a globally routable address")
            connection.request("GET", hop.path, headers=headers)
            response = connection.getresponse()
            status = int(getattr(response, "status", 0))
            if status in (301, 302, 303, 307, 308):
                if attempt >= max_redirects:
                    raise UpstreamFetchError("too many redirects")
                location = response.getheader("location") if hasattr(
                    response, "getheader") else None
                if not location:
                    raise UpstreamFetchError("redirect without a location")
                current = urljoin(current, location)
                hop = _redirect_hop(current, allowed_hosts)
                continue
            if status != 200:
                raise UpstreamFetchError(f"upstream returned HTTP {status}")
            return _read_body(
                response, deadline, max_bytes,
                getattr(connection, "sock", None), timeout)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise UpstreamFetchError(
                f"fetch failed: {type(exc).__name__}") from exc
        finally:
            try:
                connection.close()
            except Exception:  # noqa: BLE001 - close must never mask the result
                pass
    raise UpstreamFetchError("too many redirects")
