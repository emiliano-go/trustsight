"""Separate process that owns the feed signing key.

The watcher sends a body to this service and receives signature headers.  The
private key never enters the watcher process.  The signer has no network and
no database; it signs bounded bodies and returns the headers.
"""

from __future__ import annotations

import argparse
import base64
from collections import deque
import hashlib
import json
import os
import socket
import stat
import sys
import time
from pathlib import Path

from .notify import _feed_key, _sign_feed_local

__all__ = ["MAX_BODY_BYTES", "DEFAULT_SOCKET", "handle_request", "serve"]

MAX_BODY_BYTES = 1_200_000
MAX_AUDIT_BYTES = 64 * 1024 * 1024
DEFAULT_SOCKET = "/run/trustsight/feed-signer.sock"
ALLOWED_EVENTS = frozenset({
    "trustsight.alerts", "trustsight.scans", "trustsight.heartbeat",
})


class SignerLimiter:
    """A small sliding-window limiter for an abused signing socket."""

    def __init__(self, max_events: int = 120, window_seconds: float = 60.0):
        self.max_events = max_events
        self.window = window_seconds
        self._times: deque[float] = deque()

    def allow(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        while self._times and now - self._times[0] >= self.window:
            self._times.popleft()
        if len(self._times) >= self.max_events:
            return False
        self._times.append(now)
        return True


_LIMITER = SignerLimiter()


def _audit(path: str | None, document: dict, headers: dict, body: bytes,
           head_path: str | None = None) -> None:
    """Append one signed-body record, or refuse to sign if it cannot be kept."""
    if not path:
        return
    target = Path(path)
    try:
        if target.stat().st_size > MAX_AUDIT_BYTES:
            raise RuntimeError("audit log is over its cap")
    except FileNotFoundError:
        pass
    previous = _last_chain(target)
    record = {
        "ts": int(time.time()),
        "event": document.get("event", ""),
        "webhook_id": headers.get("webhook-id", ""),
        "key_id": headers.get("webhook-key-id", ""),
        "bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "signature_sha256": hashlib.sha256(
            headers.get("webhook-signature", "").encode()).hexdigest(),
        "prev": previous,
    }
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
    record["chain_sha256"] = hashlib.sha256(
        (previous + payload).encode()).hexdigest()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    if head_path:
        _write_head(Path(head_path), record["chain_sha256"])


def _write_head(target: Path, chain: str) -> None:
    """Atomically publish the current head so an external anchor can read it."""
    temporary = target.with_name(f"{target.name}.tmp.{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (json.dumps({
            "chain_sha256": chain, "ts": int(time.time()),
        }, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, target)


def _verify_head(log_path: str | None, head_path: str | None) -> None:
    """Refuse to start when the published head disagrees with the log tail."""
    if not log_path or not head_path:
        return
    head = Path(head_path)
    if not head.exists():
        return
    log = Path(log_path)
    if not log.exists():
        raise RuntimeError("signer audit head exists without an audit log")
    try:
        published = json.loads(head.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("signer audit head is unreadable") from exc
    chain = published.get("chain_sha256") if isinstance(published, dict) else None
    if not isinstance(chain, str) or chain != _last_chain(log):
        raise RuntimeError("signer audit head does not match the log tail")


def _last_chain(target: Path) -> str:
    """Read the previous chain value; refuse to append to a corrupt log."""
    try:
        with target.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 4096))
            tail = handle.read(4096)
    except FileNotFoundError:
        return ""
    line = b""
    for part in reversed(tail.split(b"\n")):
        if part:
            line = part
            break
    if not line:
        return ""
    try:
        record = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("signer audit log is corrupt") from exc
    chain = record.get("chain_sha256") if isinstance(record, dict) else None
    if not isinstance(chain, str) or len(chain) != 64:
        raise RuntimeError("signer audit log has no chain value")
    return chain


def _document_shape(document: dict) -> bool:
    event = document.get("event")
    if event == "trustsight.alerts":
        return isinstance(document.get("alerts"), list)
    if event == "trustsight.scans":
        return isinstance(document.get("scans"), list)
    return event == "trustsight.heartbeat"


def handle_request(request: object, *, audit_log: str | None = None,
                   audit_head: str | None = None,
                   limiter: SignerLimiter | None = None) -> dict:
    limiter = _LIMITER if limiter is None else limiter
    if not limiter.allow():
        return {"ok": False, "error": "signer rate limit exceeded"}
    if not isinstance(request, dict):
        return {"ok": False, "error": "invalid request"}
    encoded = request.get("body")
    if not isinstance(encoded, str):
        return {"ok": False, "error": "missing body"}
    try:
        body = base64.b64decode(encoded, validate=True)
    except Exception:
        return {"ok": False, "error": "invalid body encoding"}
    if not body or len(body) > MAX_BODY_BYTES:
        return {"ok": False, "error": "body is empty or over its cap"}
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": False, "error": "body is not JSON"}
    if not isinstance(document, dict) or document.get("event") not in ALLOWED_EVENTS:
        return {"ok": False, "error": "body is not a known feed event"}
    if not _document_shape(document):
        return {"ok": False, "error": "body has the wrong shape for its event"}
    timestamp = request.get("timestamp")
    webhook_id = request.get("webhook_id")
    if timestamp is not None and not isinstance(timestamp, int):
        return {"ok": False, "error": "invalid timestamp"}
    if webhook_id is not None and not isinstance(webhook_id, str):
        return {"ok": False, "error": "invalid webhook id"}
    key_id, key = _feed_key()
    if not key:
        return {"ok": False, "error": "feed key is not configured"}
    try:
        headers = _sign_feed_local(
            key, key_id, body, timestamp=timestamp, webhook_id=webhook_id)
        _audit(audit_log, document, headers, body, audit_head)
    except Exception as exc:  # noqa: BLE001 - one bad request is not a crash
        return {"ok": False, "error": f"{type(exc).__name__}: signing failed"}
    return {"ok": True, "headers": headers}


def _read_line(conn: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= 2_000_000:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > 2_000_000:
        raise ValueError("request is over its cap")
    return bytes(data).split(b"\n", 1)[0]


def _serve_connection(conn: socket.socket, audit_log: str | None = None,
                      audit_head: str | None = None) -> None:
    conn.settimeout(15.0)
    try:
        line = _read_line(conn)
        try:
            request = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            response = {"ok": False, "error": "invalid JSON"}
        else:
            response = handle_request(
                request, audit_log=audit_log, audit_head=audit_head)
    except Exception as exc:  # noqa: BLE001
        response = {"ok": False, "error": f"channel failure: {type(exc).__name__}"}
    try:
        conn.sendall(json.dumps(response).encode() + b"\n")
    except OSError:
        pass


def serve(path: str = DEFAULT_SOCKET, audit_log: str | None = None,
          audit_head: str | None = None) -> None:
    _verify_head(audit_log, audit_head)
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
                _serve_connection(conn, audit_log, audit_head)
    finally:
        server.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("--audit-log", default=None)
    parser.add_argument("--audit-head", default=None)
    args = parser.parse_args(argv)
    try:
        serve(args.socket, args.audit_log, args.audit_head)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"feed-signer: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
