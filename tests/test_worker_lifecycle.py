"""The staged worker teardown and restart budget."""

import io
import json
import threading
from types import SimpleNamespace

from trustsight.sandbox import client, expand_worker, worker_lifecycle


def _fake_proc():
    return SimpleNamespace(
        pid=4321,
        stdin=io.BytesIO(),
        stdout=io.BytesIO(),
        stderr=None,
        poll=lambda: 0,
        kill=lambda: None,
        wait=lambda timeout=None: 0,
    )


def test_stop_writes_one_bounded_corpse(tmp_path, monkeypatch):
    monkeypatch.setattr(worker_lifecycle, "CORPSE_DIR", tmp_path)
    worker = client._Worker()
    worker.proc = _fake_proc()
    worker.requests = 7
    worker.degraded = ["RLIMIT_FSIZE not applied: OSError"]

    worker.stop("request_error")
    worker.stop("request_error")

    files = list(tmp_path.glob("worker-*.json"))
    assert len(files) == 1
    body = json.loads(files[0].read_text())
    assert body["reason"] == "request_error"
    assert body["requests"] == 7
    assert body["degraded"] == ["RLIMIT_FSIZE not applied: OSError"]


def test_restart_budget_shuts_the_pool_down(monkeypatch):
    monkeypatch.setattr(client, "WORKER_RESTART_LIMIT", 3)
    monkeypatch.setattr(client, "WORKER_RESTART_WINDOW_SECONDS", 60.0)
    monkeypatch.setattr(client, "_shutdown", threading.Event())
    with client._restart_lock:
        client._restart_times.clear()

    assert client._restart_budget_exhausted() is False
    assert client._restart_budget_exhausted() is False
    assert client._restart_budget_exhausted() is True
    assert client._shutdown.is_set()


def test_anchorage_loss_is_reported_by_the_child_view(monkeypatch):
    monkeypatch.setattr(expand_worker, "_ANCHOR", {
        "uid": 1000, "cwd": "/", "net_inode": None, "no_new_privs": False,
        "root_read_only": False,
    })
    monkeypatch.setattr(expand_worker.os, "geteuid", lambda: 0)
    assert expand_worker._anchorage_lost() == "effective uid changed"


def test_lost_read_only_root_is_anchorage_loss(monkeypatch):
    monkeypatch.setattr(expand_worker, "_ANCHOR", {
        "uid": expand_worker.os.geteuid(), "cwd": expand_worker.os.getcwd(),
        "net_inode": None, "no_new_privs": False, "root_read_only": True,
    })
    monkeypatch.setattr(expand_worker, "_root_read_only", lambda: False)
    monkeypatch.setattr(expand_worker, "_has_no_new_privs", lambda: False)
    assert expand_worker._anchorage_lost() == "root mount became writable"


def test_analysed_content_has_no_teardown_operation():
    """The worker protocol exposes only pure tokenizer operations."""
    from trustsight.sandbox import tokenizer_ops

    for op in ("kill", "stop", "shutdown", "teardown", "signal"):
        try:
            tokenizer_ops.dispatch(op, "x")
        except tokenizer_ops.UnknownOp:
            continue
        raise AssertionError(f"teardown-shaped operation is reachable: {op}")
