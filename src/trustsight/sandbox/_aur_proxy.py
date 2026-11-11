"""The only egress the sandboxed git worker gets (A16).

The worker runs in a network namespace with no route off the machine.  For a
fetch it reaches a loopback listener in that namespace, which forwards bytes
to this proxy over one of a small pool of inherited Unix socketpairs.  The
worker speaks plain HTTP to that listener; it never originates TLS, and it
never chooses a host.

This parent-side proxy accepts exactly two Git smart-HTTP requests for the one
package the session serves:

* ``GET /<pkg>.git/info/refs?service=git-upload-pack``
* ``POST /<pkg>.git/git-upload-pack``

It ignores the worker's headers, parses the AUR refs advertisement, and
synthesises a deterministic upload-pack request from the advertised refs.
Once that request is forwarded it stops reading from the worker and relays the
upstream response until EOF.  A defect in libgit2 during response parsing
therefore has no forwardable outbound path: it can write into its own socket
buffer, but those bytes never reach the AUR.
"""

from __future__ import annotations

import os
import select
import socket
import ssl
import threading
import time

from .git_bounds import (
    GIT_PROXY_ADVERT_BYTES,
    GIT_PROXY_BODY_SECONDS,
    GIT_PROXY_DEADLINE_SECONDS,
    GIT_PROXY_HEADER_BYTES,
    GIT_PROXY_HEADER_SECONDS,
    GIT_PROXY_MAX_REFS,
    GIT_PROXY_MAX_REQUESTS,
    GIT_PROXY_MAX_WANTS,
    GIT_PROXY_REQUEST_BODY_BYTES,
    GIT_PROXY_RESPONSE_BYTES,
    GIT_PROXY_RESPONSE_HEADER_BYTES,
    GIT_PROXY_TOTAL_REQUEST_BYTES,
)

__all__ = ["AurFetchProxy"]

_AUR_HOST = "aur.archlinux.org"
_AUR_PORT = 443
_MAX_CONNECTIONS = 16
_RELAY_CHUNK = 65536
_MAX_HEADERS = 64
_MAX_GETS = 1
_MAX_POSTS = 1
_HEX = frozenset("0123456789abcdefABCDEF")
_HEADER_NAME_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_CAPABILITIES = "multi_ack_detailed side-band-64k ofs-delta thin-pack no-progress"
_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

_PKG_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._+-")
_RESERVED_PKG_NAMES = frozenset({".", ".."})

_BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_UNAVAILABLE = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_CONTINUE = b"HTTP/1.1 100 Continue\r\n\r\n"


class _BadRequest(Exception):
    """The worker sent something the proxy will not forward."""


class _UpstreamError(Exception):
    """The AUR sent an unusable status or response header."""


def _valid_pkg(name: object) -> bool:
    return (
        isinstance(name, str)
        and bool(name)
        and name not in _RESERVED_PKG_NAMES
        and all(character in _PKG_CHARS for character in name)
    )


def _is_oid(value: str) -> bool:
    return len(value) in (40, 64) and all(character in _HEX for character in value)


def _pkt_line(payload: bytes) -> bytes:
    return f"{len(payload) + 4:04x}".encode("ascii") + payload


def _pkt_line_length(header: bytes) -> int:
    if len(header) != 4 or any(chr(value) not in _HEX for value in header):
        raise _BadRequest("invalid pkt-line length")
    return int(header, 16)


def _decode_chunked(data: bytes) -> bytes:
    output = bytearray()
    offset = 0
    while offset < len(data):
        line_end = data.find(b"\r\n", offset)
        if line_end < 0:
            raise _BadRequest("truncated chunk header")
        size_text = data[offset:line_end].split(b";", 1)[0].strip()
        if not size_text or any(chr(value) not in _HEX for value in size_text):
            raise _BadRequest("invalid chunk size")
        size = int(size_text, 16)
        offset = line_end + 2
        if size == 0:
            return bytes(output)
        if size > GIT_PROXY_ADVERT_BYTES or offset + size > len(data):
            raise _BadRequest("chunk exceeds advertisement budget")
        output.extend(data[offset:offset + size])
        offset += size
        if data[offset:offset + 2] != b"\r\n":
            raise _BadRequest("chunk is not terminated")
        offset += 2
    raise _BadRequest("truncated chunked body")


def _parse_advertisement(data: bytes):
    """``(head_oid, advertised_oids)`` from a protocol-v0 ref advertisement."""
    refs: dict[str, str] = {}
    symref_head = ""
    offset = 0
    lines = 0
    while offset < len(data):
        length = _pkt_line_length(data[offset:offset + 4])
        offset += 4
        if length == 0:
            continue
        if length < 4 or offset + length - 4 > len(data):
            raise _BadRequest("advertisement pkt-line out of range")
        payload = data[offset:offset + length - 4]
        offset += length - 4
        lines += 1
        if lines > GIT_PROXY_MAX_REFS + 2:
            raise _BadRequest("advertisement has too many pkt-lines")
        if not payload.endswith(b"\n"):
            raise _BadRequest("advertisement pkt-line is not terminated")
        payload = payload[:-1]
        if payload.startswith(b"#"):
            continue
        ref_part, separator, capabilities = payload.partition(b"\0")
        try:
            text = ref_part.decode("ascii")
        except UnicodeDecodeError as exc:
            raise _BadRequest("non-ascii ref advertisement") from exc
        fields = text.split(" ")
        if len(fields) != 2:
            raise _BadRequest("malformed ref advertisement")
        oid, name = fields
        if not _is_oid(oid) or not (
                name == "HEAD" or name.startswith("refs/")):
            raise _BadRequest("malformed ref advertisement")
        refs[name] = oid
        if len(refs) > GIT_PROXY_MAX_REFS:
            raise _BadRequest("advertisement has too many refs")
        if separator:
            cap_text = capabilities.decode("ascii", "replace")
            for token in cap_text.split(" "):
                if token.startswith("symref=HEAD:"):
                    symref_head = token.split(":", 1)[1]
    if not refs:
        return None
    head = refs.get(symref_head) or refs.get("refs/heads/master") \
        or refs.get("refs/heads/main") or refs.get("HEAD")
    if not head:
        return None
    return head, frozenset(refs.values())


class AurFetchProxy:
    """A validating Git reverse proxy for one package's fetch session."""

    def __init__(self, package: str,
                 timeout: int = GIT_PROXY_DEADLINE_SECONDS) -> None:
        if not _valid_pkg(package):
            raise ValueError(f"invalid proxy package name: {package!r}")
        self.package = package
        self._timeout = timeout
        self._parent_sockets: list[socket.socket] = []
        self._child_sockets: list[socket.socket] = []
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._lock = threading.Lock()
        self._requests = 0
        self._request_bytes = 0
        self._received_bytes = 0
        self._upstreams: set[socket.socket] = set()
        self._gets = 0
        self._posts = 0
        self._advertised_head: str | None = None
        self._advertised_oids: frozenset[str] = frozenset()
        try:
            for _ in range(_MAX_CONNECTIONS):
                parent, child = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_STREAM)
                self._parent_sockets.append(parent)
                self._child_sockets.append(child)
            self._thread = threading.Thread(target=self._dispatch, daemon=True)
            self._thread.start()
        except Exception:
            self.close()
            raise

    @property
    def advertised_head(self) -> str | None:
        with self._lock:
            return self._advertised_head

    @property
    def received_bytes(self) -> int:
        with self._lock:
            return self._received_bytes

    @property
    def child_fds(self) -> list[int]:
        return [child.fileno() for child in self._child_sockets]

    def release_child_fds(self) -> None:
        """Close the parent's copies after the worker inherited them."""
        for child in self._child_sockets:
            try:
                child.close()
            except OSError:
                pass
        self._child_sockets = []

    def close(self) -> None:
        self._stopping.set()
        self.release_child_fds()
        with self._lock:
            parents = list(self._parent_sockets)
            self._parent_sockets = []
        for parent in parents:
            try:
                parent.close()
            except OSError:
                pass
        with self._lock:
            upstreams = list(self._upstreams)
            self._upstreams.clear()
        for upstream in upstreams:
            try:
                upstream.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)
        self._thread = None

    def _dispatch(self) -> None:
        """Handle one worker request at a time.

        The worker cannot use sixteen simultaneous slow connections to hold
        sixteen parent threads: a single dispatcher services one socket until
        that request/response is complete.  The bounded header/body timeouts
        are what stop a slow client.
        """
        while not self._stopping.is_set():
            with self._lock:
                sockets = list(self._parent_sockets)
            if not sockets:
                return
            try:
                readable, _, _ = select.select(sockets, [], [], 0.2)
            except (OSError, ValueError):
                return
            for connection in readable:
                self._handle(connection)
                with self._lock:
                    if connection in self._parent_sockets:
                        self._parent_sockets.remove(connection)
                try:
                    connection.close()
                except OSError:
                    pass

    def _handle(self, connection: socket.socket) -> None:
        response_started = [False]
        try:
            connection.settimeout(GIT_PROXY_HEADER_SECONDS)
            method, target = self._read_request(connection)
            upstream_request = self._build_upstream(method, target)
            self._charge(method, upstream_request)
            self._forward(connection, upstream_request, response_started, method)
        except _BadRequest:
            if not response_started[0]:
                self._send(connection, _BAD_REQUEST)
        except _UpstreamError:
            if not response_started[0]:
                self._send(connection, _UNAVAILABLE)
        except (OSError, ssl.SSLError):
            if not response_started[0]:
                self._send(connection, _UNAVAILABLE)
        except Exception:
            if not response_started[0]:
                self._send(connection, _BAD_REQUEST)
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def _charge(self, method: str, request: bytes) -> None:
        with self._lock:
            if self._requests >= GIT_PROXY_MAX_REQUESTS:
                raise _BadRequest("too many requests in one fetch session")
            if method == "GET":
                self._gets += 1
                if self._gets > _MAX_GETS:
                    raise _BadRequest("too many info/refs requests")
            else:
                if self._gets == 0:
                    raise _BadRequest("upload-pack request before info/refs")
                self._posts += 1
                if self._posts > _MAX_POSTS:
                    raise _BadRequest("too many upload-pack requests")
            if self._request_bytes + len(request) > GIT_PROXY_TOTAL_REQUEST_BYTES:
                raise _BadRequest("upload-pack request budget exhausted")
            self._requests += 1
            self._request_bytes += len(request)

    @staticmethod
    def _send(connection: socket.socket, response: bytes) -> None:
        try:
            connection.sendall(response)
        except OSError:
            pass

    def _read_request(self, connection: socket.socket):
        connection.settimeout(GIT_PROXY_HEADER_SECONDS)
        data = bytearray()
        while b"\r\n\r\n" not in data:
            if len(data) >= GIT_PROXY_HEADER_BYTES:
                raise _BadRequest("request headers too large")
            chunk = connection.recv(4096)
            if not chunk:
                raise _BadRequest("worker closed before sending a request")
            data.extend(chunk)
        header_block, body_start = bytes(data).split(b"\r\n\r\n", 1)
        lines = header_block.split(b"\r\n")
        try:
            request_line = lines[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise _BadRequest("non-ascii request line") from exc
        parts = request_line.split(" ")
        if any(ord(character) < 0x20 or ord(character) == 0x7f
               for character in request_line):
            raise _BadRequest("control character in request line")
        if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
            raise _BadRequest("malformed request line")
        method, target = parts[0], parts[1]
        if method not in ("GET", "POST"):
            raise _BadRequest("unsupported method")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if line.startswith((b" ", b"\t")):
                raise _BadRequest("folded headers are not supported")
            if b":" not in line:
                raise _BadRequest("malformed header")
            name, value = line.split(b":", 1)
            try:
                key = name.decode("ascii").strip().lower()
                text = value.decode("ascii").strip()
            except UnicodeDecodeError as exc:
                raise _BadRequest("non-ascii header") from exc
            if not key or any(character not in _HEADER_NAME_CHARS
                              for character in key):
                raise _BadRequest("malformed header name")
            if any(ord(character) < 0x20 or ord(character) == 0x7f
                   for character in text):
                raise _BadRequest("control character in header")
            if len(headers) >= _MAX_HEADERS:
                raise _BadRequest("too many headers")
            if key in headers and key == "content-length" \
                    and headers[key] != text:
                raise _BadRequest("conflicting content-length")
            headers.setdefault(key, text)
        if "transfer-encoding" in headers:
            raise _BadRequest("transfer-encoding is not supported")
        expect = headers.get("expect", "").lower()
        raw_length = headers.get("content-length")
        if raw_length is not None:
            if not raw_length.isdigit() or len(raw_length) > 9:
                raise _BadRequest("unbounded content-length")
            length = int(raw_length)
        else:
            length = None
        if method == "POST":
            if length is None:
                raise _BadRequest("POST without a content-length")
            if length > GIT_PROXY_REQUEST_BODY_BYTES:
                raise _BadRequest("request body too large")
            if "100-continue" in expect:
                self._send(connection, _CONTINUE)
            connection.settimeout(GIT_PROXY_BODY_SECONDS)
            body = bytearray(body_start)
            while len(body) < length:
                chunk = connection.recv(min(65536, length - len(body)))
                if not chunk:
                    raise _BadRequest("truncated request body")
                body.extend(chunk)
            return method, target
        if length not in (None, 0):
            raise _BadRequest("GET carried a body")
        if body_start:
            raise _BadRequest("GET carried a body")
        return method, target

    def _build_upstream(self, method: str, target: str) -> bytes:
        info_target = (f"/{self.package}.git/info/refs"
                       "?service=git-upload-pack")
        post_target = f"/{self.package}.git/git-upload-pack"
        if "%" in target or "#" in target or not target.startswith("/"):
            raise _BadRequest("unsupported request target")
        if method == "GET":
            if target != info_target:
                raise _BadRequest("unsupported GET target")
            body = b""
        else:
            if target != post_target:
                raise _BadRequest("unsupported POST target")
            with self._lock:
                wants = sorted(self._advertised_oids)
            if not wants or len(wants) > GIT_PROXY_MAX_WANTS:
                raise _BadRequest("no usable refs advertisement")
            body = bytearray()
            for index, oid in enumerate(wants):
                suffix = (" " + _CAPABILITIES) if index == 0 else ""
                body.extend(_pkt_line(f"want {oid}{suffix}\n".encode("ascii")))
            body.extend(b"0000")
            body.extend(_pkt_line(b"done\n"))
            body = bytes(body)

        lines = [
            f"{method} {target} HTTP/1.1",
            f"Host: {_AUR_HOST}",
            "User-Agent: trustsight/1.0",
            "Accept-Encoding: identity",
            "Connection: close",
        ]
        if method == "POST":
            lines.extend([
                "Accept: application/x-git-upload-pack-result",
                "Content-Type: application/x-git-upload-pack-request",
                f"Content-Length: {len(body)}",
            ])
        else:
            lines.append("Accept: */*")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body

    def _open_upstream(self):
        if not os.path.exists(_CA_BUNDLE):
            raise _UpstreamError("explicit CA bundle is unavailable")
        context = ssl.create_default_context(cafile=_CA_BUNDLE)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection(
            (_AUR_HOST, _AUR_PORT), timeout=self._timeout)
        try:
            return context.wrap_socket(raw, server_hostname=_AUR_HOST)
        except Exception:
            raw.close()
            raise

    @staticmethod
    def _read_response_head(upstream: socket.socket):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            if len(data) >= GIT_PROXY_RESPONSE_HEADER_BYTES:
                raise _UpstreamError("response headers too large")
            chunk = upstream.recv(4096)
            if not chunk:
                raise _UpstreamError("upstream closed before response headers")
            data.extend(chunk)
        head, body = bytes(data).split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        status = lines[0].split(b" ")
        if len(status) < 2 or not status[1].isdigit() \
                or int(status[1]) != 200:
            raise _UpstreamError("upstream did not answer 200")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if b":" not in line:
                continue
            name, value = line.split(b":", 1)
            headers[name.decode("ascii", "replace").strip().lower()] = \
                value.decode("ascii", "replace").strip()
        if "location" in headers:
            raise _UpstreamError("upstream redirects are not accepted")
        encoding = headers.get("transfer-encoding", "").lower()
        if encoding and encoding != "chunked":
            raise _UpstreamError("unsupported upstream transfer-encoding")
        content_encoding = headers.get("content-encoding", "").lower()
        if content_encoding and content_encoding != "identity":
            raise _UpstreamError("unsupported upstream content-encoding")
        return head + b"\r\n\r\n", body, headers

    def _forward(self, connection: socket.socket, request: bytes,
                 response_started: list, method: str) -> None:
        deadline = time.monotonic() + self._timeout
        connection.settimeout(self._timeout)
        upstream = self._open_upstream()
        with self._lock:
            self._upstreams.add(upstream)
        try:
            upstream.settimeout(GIT_PROXY_HEADER_SECONDS)
            upstream.sendall(request)
            header_block, body_prefix, headers = self._read_response_head(
                upstream)
            expected_type = (
                "application/x-git-upload-pack-advertisement"
                if method == "GET"
                else "application/x-git-upload-pack-result")
            content_type = headers.get("content-type", "")
            if content_type and not content_type.startswith(expected_type):
                raise _UpstreamError("unexpected upstream content-type")

            if method == "GET":
                wire_body = bytearray(body_prefix)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise _UpstreamError("advertisement deadline exceeded")
                    upstream.settimeout(min(remaining, self._timeout))
                    try:
                        chunk = upstream.recv(_RELAY_CHUNK)
                    except socket.timeout as exc:
                        raise _UpstreamError("advertisement timed out") from exc
                    if not chunk:
                        break
                    if len(wire_body) + len(chunk) > GIT_PROXY_ADVERT_BYTES:
                        raise _UpstreamError("advertisement exceeds its budget")
                    wire_body.extend(chunk)
                body = bytes(wire_body)
                try:
                    if headers.get("transfer-encoding", "").lower() == "chunked":
                        body = _decode_chunked(body)
                    parsed = _parse_advertisement(body)
                except _BadRequest as exc:
                    raise _UpstreamError(str(exc)) from exc
                if parsed is None:
                    raise _UpstreamError("invalid refs advertisement")
                with self._lock:
                    self._advertised_head, self._advertised_oids = parsed
                response_started[0] = True
                connection.sendall(header_block)
                connection.sendall(bytes(wire_body))
                return

            response_started[0] = True
            connection.sendall(header_block)
            chunk = body_prefix
            total = 0
            while True:
                if not chunk:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    upstream.settimeout(min(remaining, self._timeout))
                    try:
                        chunk = upstream.recv(_RELAY_CHUNK)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                total += len(chunk)
                if total > GIT_PROXY_RESPONSE_BYTES:
                    raise _UpstreamError("response budget exhausted")
                with self._lock:
                    self._received_bytes += len(chunk)
                connection.sendall(chunk)
                chunk = b""
        finally:
            with self._lock:
                self._upstreams.discard(upstream)
            try:
                upstream.close()
            except OSError:
                pass
