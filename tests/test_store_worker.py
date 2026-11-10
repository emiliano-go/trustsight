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


def test_worker_is_read_only_and_has_the_os_sandbox(tmp_path, monkeypatch):
    _temp_db(tmp_path, monkeypatch)
    source = inspect.getsource(store_worker.main)
    assert '_linux_sandbox.apply("read"' in source
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
