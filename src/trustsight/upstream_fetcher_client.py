"""Watcher-side client for the separate upstream fetcher."""

from __future__ import annotations

import base64
import json
import socket
from pathlib import Path

from .upstream_fetch import UpstreamFetchError
from .upstream_scan import verify_archive_checksum

__all__ = ["fetch_from_socket"]


def fetch_from_socket(
    path: str,
    *,
    url: str,
    expected: str,
    algorithm: str,
    min_bits: int,
    max_bytes: int,
    deadline_seconds: float,
) -> bytes:
    request = {
        "url": url,
        "expected": expected,
        "algorithm": algorithm,
        "min_bits": min_bits,
        "max_bytes": max_bytes,
        "deadline_seconds": deadline_seconds,
    }
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(max(1.0, deadline_seconds + 5.0))
        try:
            conn.connect(str(Path(path)))
        except OSError as exc:
            raise UpstreamFetchError(
                f"upstream fetcher is unavailable: {type(exc).__name__}") from exc
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        chunks = bytearray()
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > 25 * 1024 * 1024:
                raise UpstreamFetchError("upstream fetcher response is over its cap")
    try:
        response = json.loads(bytes(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpstreamFetchError("upstream fetcher returned invalid JSON") from exc
    if not isinstance(response, dict) or not response.get("ok"):
        status = response.get("status") if isinstance(response, dict) else None
        raise UpstreamFetchError(
            str(response.get("error", "upstream fetcher refused"))
            if isinstance(response, dict) else "upstream fetcher refused",
            status=status if isinstance(status, int) else None,
        )
    try:
        data = base64.b64decode(str(response["data"]), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise UpstreamFetchError("upstream fetcher returned invalid data") from exc
    if not verify_archive_checksum(
            data, expected, algorithm=algorithm, min_bits=min_bits):
        raise UpstreamFetchError("upstream fetcher body failed its checksum")
    return data
