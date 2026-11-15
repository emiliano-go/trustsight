"""Watcher-side client for the separate feed signer."""

from __future__ import annotations

import base64
import json
import socket
from pathlib import Path

__all__ = ["sign_via_socket"]


class FeedSignerError(RuntimeError):
    """The signer is unavailable or refused the request."""


def sign_via_socket(path: str, body: bytes, *,
                    timestamp: int | None = None,
                    webhook_id: str | None = None) -> dict:
    request = {
        "body": base64.b64encode(body).decode("ascii"),
        "timestamp": timestamp,
        "webhook_id": webhook_id,
    }
    payload = json.dumps(request, separators=(",", ":")).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(10.0)
        try:
            conn.connect(str(Path(path)))
        except OSError as exc:
            raise FeedSignerError(
                f"feed signer is unavailable: {type(exc).__name__}") from exc
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        chunks = bytearray()
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > 64 * 1024:
                raise FeedSignerError("feed signer response is over its cap")
    try:
        response = json.loads(bytes(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FeedSignerError("feed signer returned invalid JSON") from exc
    if not isinstance(response, dict) or not response.get("ok"):
        raise FeedSignerError(
            str(response.get("error", "feed signer refused"))
            if isinstance(response, dict) else "feed signer refused")
    headers = response.get("headers")
    if not isinstance(headers, dict) or not headers.get("webhook-signature"):
        raise FeedSignerError("feed signer returned no signature")
    return headers
