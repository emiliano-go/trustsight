"""Client for the narrow database writer."""

from __future__ import annotations

import base64
import json
import socket
import sqlite3

__all__ = ["WriterClient", "WriterUnavailable", "decode_value"]

MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class WriterUnavailable(sqlite3.OperationalError):
    pass


def _encode(value):
    if isinstance(value, bytes):
        return {"$b": base64.b64encode(value).decode()}
    return value


def decode_value(value):
    if isinstance(value, dict) and set(value) == {"$b"}:
        return base64.b64decode(value["$b"])
    return value


class WriterClient:
    def __init__(self, path: str, *, timeout: float = 30.0):
        self.path = path
        self.timeout = timeout

    def _request(self, request: dict) -> dict:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self.timeout)
                conn.connect(self.path)
                conn.sendall(json.dumps(request).encode() + b"\n")
                data = bytearray()
                while b"\n" not in data and len(data) <= MAX_RESPONSE_BYTES:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
        except OSError as exc:
            raise WriterUnavailable(
                f"database writer is unavailable: {type(exc).__name__}") from exc
        if len(data) > MAX_RESPONSE_BYTES:
            raise WriterUnavailable("database writer response is oversized")
        try:
            response = json.loads(bytes(data).split(b"\n", 1)[0])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WriterUnavailable("database writer returned an invalid response") from exc
        if not response.get("ok"):
            raise sqlite3.OperationalError(
                str(response.get("error") or "database writer refused"))
        return response

    def execute(self, sql: str, params=()) -> dict:
        return self._request({
            "op": "execute", "sql": sql,
            "params": [_encode(value) for value in params],
        })

    def executemany(self, sql: str, rows) -> dict:
        return self._request({
            "op": "executemany", "sql": sql,
            "rows": [[_encode(value) for value in row] for row in rows],
        })

    def begin(self) -> None:
        self._request({"op": "begin"})

    def commit(self) -> None:
        self._request({"op": "commit"})

    def rollback(self) -> None:
        self._request({"op": "rollback"})
