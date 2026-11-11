"""SQLite is opened defensively, not with default permissive settings."""

from __future__ import annotations

import sqlite3

import pytest

from trustsight.db._connection import _new_connection


def _conn(tmp_path):
    return _new_connection(tmp_path / "hardening.db")


def test_trusted_schema_and_writable_schema_are_off(tmp_path):
    conn = _conn(tmp_path)
    try:
        assert conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        assert conn.execute("PRAGMA writable_schema").fetchone()[0] == 0
    finally:
        conn.close()


def test_defensive_and_extension_loading_config(tmp_path):
    conn = _conn(tmp_path)
    try:
        if hasattr(conn, "getconfig"):
            assert conn.getconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE) is True
            assert conn.getconfig(
                sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA) is False
            assert conn.getconfig(
                sqlite3.SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION) is False
    finally:
        conn.close()


def test_attach_is_denied(tmp_path):
    conn = _conn(tmp_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("ATTACH DATABASE ':memory:' AS side")
    finally:
        conn.close()


def test_writable_schema_pragma_is_denied(tmp_path):
    conn = _conn(tmp_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("PRAGMA writable_schema=ON")
    finally:
        conn.close()


def test_attach_limit_is_zero(tmp_path):
    conn = _conn(tmp_path)
    try:
        if hasattr(conn, "getlimit"):
            assert conn.getlimit(sqlite3.SQLITE_LIMIT_ATTACHED) == 0
    finally:
        conn.close()
