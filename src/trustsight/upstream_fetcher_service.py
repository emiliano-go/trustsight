"""Separate-process upstream archive fetcher.

The watcher asks this service to fetch and verify an archive; the provider
token never enters the watcher process.  The service has no database, config
write path, feed key, or parser worker.  It validates the same allowlist and
checksum rules as the in-process transport.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import stat
import sys
from pathlib import Path

from .config import load_config
from .credentials import CredentialError, resolve_token
from .upstream_fetch import UpstreamFetchError, fetch_bytes
from .upstream_scan import (
    UpstreamScanError,
    configured_hosts,
    parse_forge_target,
    verify_archive_checksum,
)

__all__ = ["MAX_REQUEST_BYTES", "handle_request", "serve"]

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 24 * 1024 * 1024
DEFAULT_SOCKET = "/run/trustsight/upstream.sock"

_PROVIDER_BY_HOST = {
    "github.com": "github",
    "gitlab.com": "gitlab",
    "codeberg.org": "codeberg",
    "bitbucket.org": "bitbucket",
}


def _token_for(host: str):
    provider = _PROVIDER_BY_HOST.get(host)
    if not provider:
        return None
    return resolve_token(provider)


def _error(message: str) -> dict:
    return {"ok": False, "error": message}


def handle_request(request: object) -> dict:
    """Handle one JSON request; never raise a caller-controlled exception."""
    try:
        if not isinstance(request, dict):
            return _error("invalid request")
        url = request.get("url")
        expected = request.get("expected")
        algorithm = request.get("algorithm")
        if not all(isinstance(v, str) and v for v in
                   (url, expected, algorithm)):
            return _error("missing url, expected or algorithm")
        try:
            min_bits = int(request.get("min_bits", 256))
            max_bytes = int(request.get("max_bytes", 16 * 1024 * 1024))
            deadline = float(request.get("deadline_seconds", 120))
        except (TypeError, ValueError):
            return _error("invalid bounds")
        if min_bits < 256 or max_bytes <= 0 or deadline <= 0:
            return _error("refused bounds")

        config = load_config()
        section = (config or {}).get("upstream_scan")
        if not isinstance(section, dict) or not section.get("enabled", False):
            return _error("upstream scan is disabled")
        allowed = configured_hosts(config)
        target = parse_forge_target(url, allowed_hosts=allowed)
        token = _token_for(target.host)
        proxy = (
            os.environ.get("TRUSTSIGHT_UPSTREAM_PROXY", "").strip()
            or str(section.get("proxy", "") or "").strip()
            or None
        )
        data = fetch_bytes(
            url, allowed_hosts=allowed, token=token, proxy=proxy,
            max_bytes=min(max_bytes, 16 * 1024 * 1024),
            deadline_seconds=min(deadline, 120.0),
        )
        if not verify_archive_checksum(
                data, expected, algorithm=algorithm, min_bits=min_bits):
            return _error("archive does not match its checksum")
        encoded = base64.b64encode(data).decode("ascii")
        if len(encoded) > MAX_RESPONSE_BYTES:
            return _error("response is over its cap")
        return {"ok": True, "data": encoded}
    except CredentialError as exc:
        return _error(f"credential failure: {exc}")
    except UpstreamFetchError as exc:
        response = _error(str(exc))
        response["status"] = exc.status
        return response
    except UpstreamScanError as exc:
        return _error(str(exc))
    except Exception as exc:  # noqa: BLE001 - one bad request is not a crash
        return _error(f"{type(exc).__name__}: request failed")


def _read_line(conn: socket.socket) -> bytes:
    chunks = bytearray()
    while len(chunks) <= MAX_REQUEST_BYTES:
        chunk = conn.recv(4096)
        if not chunk:
            break
        chunks.extend(chunk)
        if b"\n" in chunk:
            break
    if len(chunks) > MAX_REQUEST_BYTES:
        raise ValueError("request is over its cap")
    line, _, _ = bytes(chunks).partition(b"\n")
    return line


def _serve_connection(conn: socket.socket) -> None:
    conn.settimeout(130.0)
    try:
        line = _read_line(conn)
        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            response = _error("invalid JSON")
        else:
            response = handle_request(request)
    except Exception as exc:  # noqa: BLE001
        response = _error(f"channel failure: {type(exc).__name__}")
    payload = json.dumps(response, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_RESPONSE_BYTES:
        payload = json.dumps(_error("response is over its cap")).encode()
    try:
        conn.sendall(payload + b"\n")
    except OSError:
        pass


def serve(path: str = DEFAULT_SOCKET) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        info = target.lstat()
    except FileNotFoundError:
        info = None
    if info is not None:
        if not stat.S_ISSOCK(info.st_mode):
            raise RuntimeError(f"{target} exists and is not a socket")
        target.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(target))
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        server.listen(8)
        while True:
            conn, _ = server.accept()
            with conn:
                _serve_connection(conn)
    finally:
        server.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    args = parser.parse_args(argv)
    try:
        serve(args.socket)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"upstream-fetcher: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
