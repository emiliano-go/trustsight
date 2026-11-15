"""A narrow SQLite writer for the watcher.

The watcher keeps a read-only handle to the database and sends every write to
this process over a Unix socket.  The writer owns the only writable handle.
It refuses schema changes, PRAGMA, ATTACH and DELETE, enforces a table
allowlist through SQLite's authorizer, and appends a hash-chained audit record
before each statement is accepted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import sqlite3
import stat
import sys
import time
from pathlib import Path

__all__ = ["MAX_REQUEST_BYTES", "DEFAULT_SOCKET", "handle", "serve"]

MAX_REQUEST_BYTES = 8 * 1024 * 1024
DEFAULT_SOCKET = "/run/trustsight-db/db-writer.sock"
_ALLOWED_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_INSERT,
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_FUNCTION,
    sqlite3.SQLITE_TRANSACTION,
    sqlite3.SQLITE_SAVEPOINT,
    sqlite3.SQLITE_RECURSIVE,
}


def _digest(value) -> str:
    encoded = json.dumps(value, sort_keys=True, default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _decode(value):
    if isinstance(value, dict) and set(value) == {"$b"}:
        return base64.b64decode(value["$b"])
    return value


def _encode(value):
    if isinstance(value, bytes):
        return {"$b": base64.b64encode(value).decode()}
    return value


class _Audit:
    def __init__(self, path: str | None):
        self.path = path
        self.prev = "0" * 64 if path else ""
        if path:
            self._recover()

    def _recover(self) -> None:
        prev = "0" * 64
        try:
            with open(self.path, encoding="utf-8") as handle:
                for line in handle:
                    record = json.loads(line)
                    claimed = str(record.get("chain_sha256", ""))
                    body = {key: value for key, value in record.items()
                            if key != "chain_sha256"}
                    expected = hashlib.sha256(
                        (prev + json.dumps(body, sort_keys=True)).encode()
                    ).hexdigest()
                    if body.get("prev") != prev or claimed != expected:
                        raise RuntimeError("audit chain mismatch")
                    prev = claimed
        except FileNotFoundError:
            return
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("database writer audit is corrupt") from exc
        self.prev = prev

    def append(self, record: dict) -> None:
        if not self.path:
            return
        body = {**record, "prev": self.prev, "ts": int(time.time())}
        body["chain_sha256"] = hashlib.sha256(
            (self.prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                         0o600)
            try:
                os.write(fd, (json.dumps(body, sort_keys=True) + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise RuntimeError("database writer audit is unavailable") from exc
        self.prev = body["chain_sha256"]


_SCHEMA_DENY = {
    sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_CREATE_INDEX,
    sqlite3.SQLITE_CREATE_TABLE,
    sqlite3.SQLITE_CREATE_TRIGGER,
    sqlite3.SQLITE_CREATE_VIEW,
    sqlite3.SQLITE_DROP_INDEX,
    sqlite3.SQLITE_DROP_TABLE,
    sqlite3.SQLITE_DROP_TRIGGER,
    sqlite3.SQLITE_DROP_VIEW,
    sqlite3.SQLITE_ALTER_TABLE,
    sqlite3.SQLITE_REINDEX,
    sqlite3.SQLITE_ANALYZE,
    sqlite3.SQLITE_ATTACH,
    sqlite3.SQLITE_DETACH,
    sqlite3.SQLITE_PRAGMA,
}


def _authorizer(action, arg1, arg2, dbname, trigger):
    if action in _SCHEMA_DENY:
        return sqlite3.SQLITE_DENY
    if action in _ALLOWED_ACTIONS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=FULL")
    from .db._connection import _harden_connection

    _harden_connection(conn, read_only=False)
    conn.set_authorizer(_authorizer)
    return conn


def _first_word(sql: str) -> str:
    stripped = sql.lstrip()
    while stripped.startswith("--"):
        stripped = stripped.split("\n", 1)[1] if "\n" in stripped else ""
        stripped = stripped.lstrip()
    return stripped.split(None, 1)[0].upper() if stripped else ""


def handle(request: object, conn: sqlite3.Connection, audit: _Audit,
           state: dict) -> dict:
    if not isinstance(request, dict):
        return {"ok": False, "error": "invalid request"}
    session = request.get("session")
    if state.get("in_tx") and session != state.get("session"):
        # Requests arrive on separate sockets, so a client that dies mid-batch
        # cannot close its transaction itself.  A new session rolls the stale
        # one back instead of leaving the writer permanently locked.
        try:
            conn.rollback()
        except sqlite3.Error:
            return {"ok": False, "error": "stale transaction could not be closed"}
        state["in_tx"] = False
        state["session"] = None
    if isinstance(session, str):
        state["session"] = session
    op = request.get("op")
    if op in ("begin", "commit", "rollback"):
        if op == "begin":
            if state["in_tx"]:
                return {"ok": False, "error": "transaction already open"}
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error:
                return {"ok": False, "error": "transaction failed"}
            state["in_tx"] = True
            return {"ok": True}
        if not state["in_tx"]:
            return {"ok": True}
        try:
            conn.execute(op.upper())
        except sqlite3.Error:
            return {"ok": False, "error": "transaction failed"}
        state["in_tx"] = False
        return {"ok": True}
    if op not in ("execute", "executemany"):
        return {"ok": False, "error": "unknown operation"}
    sql = request.get("sql")
    params = request.get("params") or []
    if not isinstance(sql, str) or not sql.strip():
        return {"ok": False, "error": "missing SQL"}
    if len(sql) > 65536:
        return {"ok": False, "error": "SQL is over its cap"}
    if _first_word(sql) == "DELETE":
        return {"ok": False, "error": "DELETE is not available to the watcher"}
    if op == "executemany":
        rows = request.get("rows")
        if not isinstance(rows, list) or len(rows) > 5000:
            return {"ok": False, "error": "executemany rows are over their cap"}
        decoded = [[_decode(value) for value in row] for row in rows]
    else:
        decoded = [_decode(value) for value in params]
    audit.append({"sql_sha256": _digest(sql),
                  "params_sha256": _digest(decoded)})
    try:
        cursor = conn.cursor()
        if op == "executemany":
            cursor.executemany(sql, decoded)
        else:
            cursor.execute(sql, decoded)
        rows_out = cursor.fetchall() if cursor.description else []
        columns = [column[0] for column in cursor.description or ()]
        result = {
            "ok": True,
            "columns": columns,
            "rows": [[_encode(value) for value in row] for row in rows_out],
            "lastrowid": cursor.lastrowid,
            "rowcount": cursor.rowcount,
        }
        return result
    except sqlite3.Error as exc:
        return {"ok": False, "error": f"database refused: {exc}"}


def _read_line(conn: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("request is over its cap")
    return bytes(data).split(b"\n", 1)[0]


def serve(path: str = DEFAULT_SOCKET, db_path: str | None = None,
          audit_log: str | None = None) -> None:
    db_path = db_path or os.environ.get("TRUSTSIGHT_DB_PATH")
    if not db_path:
        raise RuntimeError("database path is required")
    # Initialise and migrate before installing the write firewall.  This is
    # the only DDL the writer ever runs.
    os.environ["TRUSTSIGHT_DB_PATH"] = db_path
    os.environ.pop("TRUSTSIGHT_DB_WRITER_SOCKET", None)
    from .db._connection import close_connections
    from .db._schema import init_db

    init_db()
    close_connections()
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass
    conn = _connect(db_path)
    audit = _Audit(audit_log)
    state = {"in_tx": False}
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        target.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(target))
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        server.listen(4)
        while True:
            client, _ = server.accept()
            with client:
                try:
                    line = _read_line(client)
                    request = json.loads(line.decode("utf-8"))
                    response = handle(request, conn, audit, state)
                except Exception as exc:  # noqa: BLE001
                    response = {"ok": False,
                                "error": f"channel failure: {type(exc).__name__}"}
                try:
                    client.sendall(json.dumps(response).encode() + b"\n")
                except OSError:
                    pass
    finally:
        server.close()
        conn.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("--db", required=True)
    parser.add_argument("--audit-log", default=None)
    args = parser.parse_args()
    try:
        serve(args.socket, args.db, args.audit_log)
    except KeyboardInterrupt:
        raise SystemExit(0)
    except Exception as exc:  # noqa: BLE001
        print(f"db-writer: {exc}", file=sys.stderr)
        raise SystemExit(2)
