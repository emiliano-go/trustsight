"""Analysis store reads run in a read-only worker, not the analysis process."""

from __future__ import annotations

import inspect
import os
import signal
import time

import pytest

from trustsight.sandbox import store_client, store_worker


def _temp_db(tmp_path, monkeypatch):
    import trustsight.db as db

    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    db.init_db()
    return db


def test_reads_are_served_by_the_store_worker(tmp_path, monkeypatch):
    db = _temp_db(tmp_path, monkeypatch)
    package_id = db.upsert_package("demo", "1.0")
    assert store_client.get_package_id("demo") == package_id
    assert store_client.get_package("demo")["name"] == "demo"
    assert store_client.get_last_analysis(package_id) is None
    assert store_client.effective_observation_count() >= 0


def test_worker_has_the_store_sandbox(tmp_path, monkeypatch):
    _temp_db(tmp_path, monkeypatch)
    source = inspect.getsource(store_worker.main)
    assert '"store"' in source
    assert "apply_limits(" in source


def test_unknown_operation_is_refused(tmp_path, monkeypatch):
    _temp_db(tmp_path, monkeypatch)
    with pytest.raises(store_client.StoreUnavailable, match="unknown store op"):
        store_client._call("drop_everything")


def test_dead_worker_restarts(tmp_path, monkeypatch):
    _temp_db(tmp_path, monkeypatch)
    assert store_client.get_package("demo") is None
    worker = store_client._get_worker()
    os.killpg(os.getpgid(worker.proc.pid), signal.SIGKILL)
    time.sleep(0.2)
    assert store_client.get_package("demo") is None


def test_worker_restarts_when_the_database_path_changes(tmp_path, monkeypatch):
    db = _temp_db(tmp_path / "one", monkeypatch)
    db.init_db()
    assert store_client.get_package("demo") is None
    first = store_client._worker.proc.pid
    monkeypatch.setattr(db, "DATA_DIR", tmp_path / "two")
    db.init_db()
    assert store_client.get_package("demo") is None
    assert store_client._worker.proc.pid != first


def test_read_and_write_operation_sets_are_disjoint():
    live = set(store_worker._OPS)
    assert store_worker._READ_OPS.isdisjoint(store_worker._WRITE_OPS)
    assert live == store_worker._READ_OPS | store_worker._WRITE_OPS


def test_missing_database_defaults_only_apply_to_reads(tmp_path, monkeypatch):
    from trustsight.sandbox import store_worker

    monkeypatch.setenv("TRUSTSIGHT_DB_PATH", str(tmp_path / "missing.db"))
    read = store_worker._handle(
        b'{"op": "get_package", "args": ["demo"]}')["result"]
    assert read is None
    write = store_worker._handle(
        b'{"op": "upsert_package", "args": ["demo", "1.0"]}')
    assert "error" in write


def test_store_request_cap_refuses_before_spawning(monkeypatch):
    with pytest.raises(store_client.StoreUnavailable, match="request exceeds"):
        store_client.set_metadata("key", "x" * (store_client.MAX_REQUEST_BYTES + 1))


def test_worker_has_a_bounded_store_sandbox():
    source = inspect.getsource(store_worker.main)
    assert '"store"' in source
    assert "apply_limits(" in source
    assert "fsize=512 * 1024 * 1024" in source


def test_malformed_frames_are_refusals():
    for body in (b"not json", b"{}", b'{"op":"get_package","args":"x"}',
                 b'{"op":"get_package","kwargs":[]}'):
        response = store_worker._handle(body)
        assert isinstance(response, dict) and "error" in response


def test_read_and_write_modes_switch_the_connection():
    from trustsight.sandbox import store_worker

    store_worker._handle(b'{"op":"get_package","args":["x"]}')
    assert __import__("os").environ.get("TRUSTSIGHT_STORE_READ_ONLY") == "1"
    store_worker._handle(b'{"op":"set_metadata","args":["k","v"]}')
    assert __import__("os").environ.get("TRUSTSIGHT_STORE_READ_ONLY") is None


def test_store_worker_pins_a_private_home_and_allows_a_large_write():
    """The worker's root is a private tmpfs; a parent HOME path does not exist.

    A real corpus write can also take longer than ten seconds, which used to be
    reported as a dead worker.
    """
    source = inspect.getsource(store_client._Worker.start)
    assert '"HOME": "/"' in source
    assert store_client.REQUEST_TIMEOUT_SECONDS >= 60
