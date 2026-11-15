"""The writer accepts narrow writes and refuses history-destroying SQL."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from trustsight.db_writer_service import _Audit, _connect, handle


def _db(tmp_path):
    path = tmp_path / "db.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO items (name) VALUES ('one')")
    conn.commit()
    return path, _connect(str(path))


def test_writer_allows_insert_and_update_but_refuses_delete(tmp_path):
    path, conn = _db(tmp_path)
    audit = _Audit(None)
    state = {"in_tx": False}
    inserted = handle({"op": "execute", "sql": "INSERT INTO items (name) VALUES (?)",
                       "params": ["two"]}, conn, audit, state)
    assert inserted["ok"] and inserted["lastrowid"] == 2
    updated = handle({"op": "execute", "sql": "UPDATE items SET name=? WHERE id=?",
                      "params": ["changed", 2]}, conn, audit, state)
    assert updated["ok"] and updated["rowcount"] == 1
    refused = handle({"op": "execute", "sql": "DELETE FROM items", "params": []},
                     conn, audit, state)
    assert refused["ok"] is False
    assert "DELETE" in refused["error"]
    assert conn.execute("SELECT count(*) FROM items").fetchone()[0] == 2


def test_writer_refuses_schema_and_pragma(tmp_path):
    path, conn = _db(tmp_path)
    audit = _Audit(None)
    state = {"in_tx": False}
    for sql in ("DROP TABLE items", "PRAGMA writable_schema=ON",
                "ALTER TABLE items ADD COLUMN x TEXT"):
        result = handle({"op": "execute", "sql": sql, "params": []},
                        conn, audit, state)
        assert result["ok"] is False, sql


def test_writer_audit_is_hash_chained(tmp_path):
    path, conn = _db(tmp_path)
    log = tmp_path / "audit.jsonl"
    audit = _Audit(str(log))
    state = {"in_tx": False}
    assert handle({"op": "execute", "sql": "INSERT INTO items (name) VALUES (?)",
                   "params": ["a"]}, conn, audit, state)["ok"]
    assert handle({"op": "execute", "sql": "INSERT INTO items (name) VALUES (?)",
                   "params": ["b"]}, conn, audit, state)["ok"]
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records[1]["prev"] == records[0]["chain_sha256"]


def test_the_watcher_proxy_reads_locally_and_writes_through_the_service(tmp_path):
    db = tmp_path / "trustsight.db"
    sock = tmp_path / "writer.sock"
    audit = tmp_path / "audit.jsonl"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
    proc = subprocess.Popen(
        [sys.executable, "-m", "trustsight.db_writer_service",
         "--socket", str(sock), "--db", str(db), "--audit-log", str(audit)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if sock.exists():
                break
            if proc.poll() is not None:
                raise AssertionError(proc.stderr.read())
            time.sleep(0.05)
        assert sock.exists()
        os.environ["TRUSTSIGHT_DB_PATH"] = str(db)
        os.environ["TRUSTSIGHT_DB_WRITER_SOCKET"] = str(sock)
        from trustsight.db import close_connections, get_package, upsert_package
        close_connections()
        assert upsert_package("pkg", "1") > 0
        assert get_package("pkg")["current_version"] == "1"
        with pytest.raises(sqlite3.OperationalError):
            from trustsight.db import get_connection
            with get_connection() as conn:
                conn.execute("DELETE FROM packages")
        assert get_package("pkg") is not None
        from trustsight.db import (get_metadata, get_pkgbuild_snapshot,
                                   save_pkgbuild_snapshot, set_metadata,
                                   write_batch)
        with write_batch():
            set_metadata("writer-test", "yes")
            save_pkgbuild_snapshot("pkg", "pkgname=pkg\npkgver=1\n", "1")
        assert get_metadata("writer-test") == "yes"
        assert get_pkgbuild_snapshot("pkg")["pkgbuild_text"].startswith("pkgname=pkg")
    finally:
        os.environ.pop("TRUSTSIGHT_DB_WRITER_SOCKET", None)
        os.environ.pop("TRUSTSIGHT_DB_PATH", None)
        proc.terminate()
        proc.wait(timeout=10)


def test_a_tampered_writer_audit_refuses_to_start(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text('{"chain_sha256":"' + "0" * 64 + '","prev":"' + "0" * 64 + '"}\n')
    with pytest.raises(RuntimeError):
        _Audit(str(log))


def test_a_new_session_rolls_back_a_stale_transaction(tmp_path):
    path, conn = _db(tmp_path)
    audit = _Audit(None)
    state = {"in_tx": False}
    assert handle({"op": "begin", "session": "old"}, conn, audit, state)["ok"]
    assert handle({"op": "execute", "session": "old",
                   "sql": "INSERT INTO items (name) VALUES (?)",
                   "params": ["stale"]}, conn, audit, state)["ok"]
    assert state["in_tx"] is True
    result = handle({"op": "execute", "session": "new",
                     "sql": "INSERT INTO items (name) VALUES (?)",
                     "params": ["fresh"]}, conn, audit, state)
    assert result["ok"]
    rows = [row[0] for row in conn.execute("SELECT name FROM items")]
    assert "stale" not in rows
    assert "fresh" in rows
