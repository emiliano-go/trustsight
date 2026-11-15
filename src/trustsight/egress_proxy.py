"""Small CONNECT-only egress proxy for the upstream fetcher.

The fetcher has no direct internet route.  It sends CONNECT to this proxy,
which accepts only HTTPS to the exact forge/CDN allowlist and refuses
loopback, private, link-local, reserved and metadata addresses before it
dials.  TLS stays end-to-end; the proxy only sees the hostname in CONNECT.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import base64
import hmac
import select
import socket
import sys
import threading
import time

from .upstream_fetch import REDIRECT_HOSTS
from .upstream_scan import DEFAULT_ALLOWED_HOSTS, is_routable_address

__all__ = ["ALLOWED_HOSTS", "handle_client", "serve"]

log = logging.getLogger(__name__)

WATCHER_HOSTS = frozenset({
    "aur.archlinux.org", "api.github.com", "watcher.trustsight.org",
    "ntfy.sh",
})
ALLOWED_HOSTS = (
    frozenset(DEFAULT_ALLOWED_HOSTS) | frozenset(REDIRECT_HOSTS) | WATCHER_HOSTS
)
MAX_HEADER_BYTES = 8 * 1024
MAX_AUDIT_BYTES = 64 * 1024 * 1024
CONNECT_TIMEOUT = 15.0
IDLE_TIMEOUT = 300.0
MAX_CONNECTIONS = 64


class ProxyError(Exception):
    pass


def _audit(path: str | None, record: dict) -> None:
    """Append a CONNECT record; fail closed if the audit cannot be kept."""
    if not path:
        return
    try:
        if os.path.getsize(path) > MAX_AUDIT_BYTES:
            os.replace(path, path + ".1")
    except FileNotFoundError:
        pass
    except OSError:
        pass
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    except OSError as exc:
        raise ProxyError(
            f"CONNECT audit is unavailable: {type(exc).__name__}") from exc


def _read_headers(conn: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_HEADER_BYTES:
            raise ProxyError("request headers are over their cap")
    return bytes(data)


def _env_extra_hosts() -> frozenset[str]:
    raw = os.environ.get("TRUSTSIGHT_EGRESS_ALLOW", "")
    values = set()
    for value in raw.split(","):
        host = value.strip().lower().rstrip(".")
        if (not host or "." not in host or "/" in host or ":" in host
                or "*" in host or ".." in host or host.startswith(".")
                or not all(c.isalnum() or c in ".-" for c in host)):
            continue
        try:
            import ipaddress

            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        values.add(host)
    return frozenset(values)


def _authorised(data: bytes, token: str | None) -> bool:
    if not token:
        return True
    for line in data.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if not sep or name.strip().lower() != b"proxy-authorization":
            continue
        scheme, _, credential = value.strip().partition(b" ")
        if scheme.lower() != b"basic":
            continue
        try:
            decoded = base64.b64decode(credential.strip(), validate=True)
        except Exception:
            return False
        _user, _, password = decoded.partition(b":")
        return hmac.compare_digest(password, token.encode())
    return False


def _parse_connect(data: bytes, allowed=None) -> tuple[str, int]:
    first = data.split(b"\r\n", 1)[0].decode("latin-1")
    parts = first.split()
    if len(parts) != 3 or parts[0].upper() != "CONNECT":
        raise ProxyError("only CONNECT is allowed")
    authority = parts[1]
    if "@" in authority or "/" in authority:
        raise ProxyError("invalid CONNECT authority")
    host, sep, port_text = authority.rpartition(":")
    if not sep:
        raise ProxyError("CONNECT authority has no port")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ProxyError("invalid CONNECT port") from exc
    host = host.lower().rstrip(".")
    if port != 443:
        raise ProxyError("only 443 is allowed")
    if host not in (allowed or ALLOWED_HOSTS):
        raise ProxyError(f"host is not allowlisted: {host or '?'}")
    return host, port


def _tunnel(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, IDLE_TIMEOUT)
            if errored or not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                target = right if source is left else left
                target.sendall(data)
    except OSError:
        return


def handle_client(conn: socket.socket, *, resolver=socket.getaddrinfo,
                  connector=socket.create_connection, allowed=None,
                  audit_log: str | None = None,
                  auth_token: str | None = None) -> None:
    conn.settimeout(CONNECT_TIMEOUT)
    upstream = None
    data = b""
    try:
        data = _read_headers(conn)
        if not _authorised(data, auth_token):
            raise ProxyError("proxy authentication required")
        host, port = _parse_connect(data, allowed)
        infos = resolver(host, port, type=socket.SOCK_STREAM)
        address = None
        for info in infos or ():
            candidate = info[4][0]
            if is_routable_address(candidate):
                address = candidate
                break
        if address is None:
            raise ProxyError(f"{host} has no routable address")
        _audit(audit_log, {
            "ts": int(time.time()), "host": host, "address": address,
            "allowed": True,
        })
        upstream = connector((address, port), CONNECT_TIMEOUT)
        upstream.settimeout(None)
        conn.settimeout(None)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        log.info("CONNECT %s:443 -> %s", host, address)
        _tunnel(conn, upstream)
    except ProxyError as exc:
        try:
            _audit(audit_log, {
                "ts": int(time.time()), "host": data.split(b" ")[1].decode(
                    "latin-1") if b" " in data else "", "allowed": False,
                "reason": str(exc),
            })
        except ProxyError as audit_exc:
            log.warning("CONNECT denial audit failed: %s", audit_exc)
        try:
            conn.sendall(
                f"HTTP/1.1 403 Forbidden\r\nContent-Length: {len(str(exc))}\r\n"
                f"\r\n{exc}".encode()
            )
        except OSError:
            pass
        log.warning("refused CONNECT: %s", exc)
    except OSError:
        pass
    finally:
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass
        try:
            conn.close()
        except OSError:
            pass


def serve(listen: str = "0.0.0.0:3128", audit_log: str | None = None,
          auth_token: str | None = None) -> None:
    host, _, port_text = listen.rpartition(":")
    if not host:
        host = "0.0.0.0"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, int(port_text)))
    server.listen(16)
    allowed = ALLOWED_HOSTS | _env_extra_hosts()
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
    try:
        while True:
            conn, _ = server.accept()
            if not slots.acquire(blocking=False):
                conn.close()
                continue

            def run(client=conn):
                try:
                    handle_client(
                        client, allowed=allowed, audit_log=audit_log,
                        auth_token=auth_token)
                finally:
                    slots.release()

            threading.Thread(target=run, daemon=True).start()
    finally:
        server.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0:3128")
    parser.add_argument("--audit-log", default=None)
    args = parser.parse_args(argv)
    try:
        serve(args.listen, args.audit_log)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"egress-proxy: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
