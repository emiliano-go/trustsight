"""A local Unix-socket token broker.

The fetcher asks for a provider token and receives the token plus its expiry.
Files are re-read per request, so an external agent can rotate them without a
restart.  The broker has no network, no database, and only the token
directory it is given.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import stat
import sys
import time
from pathlib import Path

__all__ = ["MAX_REQUEST_BYTES", "DEFAULT_SOCKET", "handle_request", "serve"]

MAX_REQUEST_BYTES = 4096
MAX_TOKEN_BYTES = 8192
DEFAULT_SOCKET = "/run/trustsight/token-broker.sock"
DEFAULT_TOKEN_DIR = "/run/trustsight/tokens"  # noqa: S105
_PROVIDER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _read_bounded(path: Path, cap: int) -> str:
    with path.open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise ValueError("file is over its cap")
    return data.decode("utf-8", errors="replace").strip()


def handle_request(request: object, token_dir: str) -> dict:
    if not isinstance(request, dict):
        return {"ok": False, "error": "invalid request"}
    provider = request.get("provider")
    if not isinstance(provider, str) or not _PROVIDER_RE.fullmatch(provider):
        return {"ok": False, "error": "invalid provider"}
    base = Path(token_dir)
    try:
        token = _read_bounded(base / f"{provider}.token", MAX_TOKEN_BYTES)
    except FileNotFoundError:
        return {"ok": False, "error": "token is not configured"}
    except (OSError, ValueError):
        return {"ok": False, "error": "token cannot be read"}
    if not token:
        return {"ok": False, "error": "token is empty"}
    expires_at = None
    try:
        raw = _read_bounded(base / f"{provider}.expires", 64)
    except FileNotFoundError:
        raw = ""
    except (OSError, ValueError):
        return {"ok": False, "error": "expiry cannot be read"}
    if raw:
        try:
            expires_at = float(raw)
        except ValueError:
            return {"ok": False, "error": "expiry is not a timestamp"}
        if time.time() >= expires_at:
            return {"ok": False, "error": "token is expired"}
    return {"ok": True, "token": token, "expires_at": expires_at}


def _read_line(conn: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("request is over its cap")
    return bytes(data).split(b"\n", 1)[0]


def _serve_connection(conn: socket.socket, token_dir: str) -> None:
    conn.settimeout(10.0)
    try:
        line = _read_line(conn)
        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            response = {"ok": False, "error": "invalid JSON"}
        else:
            response = handle_request(request, token_dir)
    except Exception as exc:  # noqa: BLE001
        response = {"ok": False, "error": f"channel failure: {type(exc).__name__}"}
    try:
        conn.sendall(json.dumps(response).encode() + b"\n")
    except OSError:
        pass


def serve(path: str = DEFAULT_SOCKET, token_dir: str = DEFAULT_TOKEN_DIR) -> None:
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
        server.listen(4)
        while True:
            conn, _ = server.accept()
            with conn:
                _serve_connection(conn, token_dir)
    finally:
        server.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("--token-dir", default=DEFAULT_TOKEN_DIR)
    args = parser.parse_args(argv)
    try:
        serve(args.socket, args.token_dir)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"token-broker: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
