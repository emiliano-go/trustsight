"""Fetcher: the git-sandbox seam and the network-timeout configuration.

The clone/fetch *behaviour* now lives in the isolated worker and is tested in
``test_git_worker.py``; the subprocess transport is in ``test_git_client.py``;
freshness is parent-owned in ``sandbox/fetch_state.py``.  What remains here is
the parent seam: ``clone_or_fetch`` returns a bound handle, and the configured
timeouts reach the worker.
"""

import pytest

from trustsight import fetcher
from trustsight.fetcher import clone_or_fetch


@pytest.fixture(autouse=True)
def _online(monkeypatch):
    """These tests exercise the fetch path, which TRUSTSIGHT_OFFLINE forbids."""
    monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)


# --- the git-sandbox seam ---------------------------------------------------


class _FakeSession:
    instances: list["_FakeSession"] = []

    def __init__(self):
        self.calls: list[dict] = []
        self.closed = False
        _FakeSession.instances.append(self)

    advertised = "a" * 40

    def open_fetch(self, pkg, cache_dir, upstream_mtime, offline,
                   connect, transfer, force=False, previous_head=""):
        self.calls.append({
            "pkg": pkg, "cache_dir": cache_dir,
            "upstream_mtime": upstream_mtime, "offline": offline,
            "connect": connect, "transfer": transfer, "force": force,
            "previous_head": previous_head,
        })
        return {"path": str(cache_dir), "head": self.advertised,
                "fetched": True, "marker_time": None, "received_bytes": 0}

    def advertised_head(self):
        return self.advertised

    def received_bytes(self):
        return 0

    def head(self, pkg, cache_dir):
        return self.advertised

    def close(self):
        self.closed = True


def test_clone_or_fetch_delegates_to_the_isolated_worker(tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    _FakeSession.instances = []
    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _FakeSession)

    project = clone_or_fetch("demo", 1234)

    session = _FakeSession.instances[-1]
    assert session.calls == [{
        "pkg": "demo", "cache_dir": str(cache),
        "upstream_mtime": 1234, "offline": False,
        "connect": fetcher.DEFAULT_CONNECT_TIMEOUT,
        "transfer": fetcher.DEFAULT_TRANSFER_TIMEOUT,
        "force": True, "previous_head": "",
    }]
    project.close()
    assert session.closed, "the worker session was not closed"


def test_clone_or_fetch_reports_a_dead_worker_as_a_fetch_failure(tmp_path, monkeypatch):
    from trustsight.sandbox.git_client import GitSandboxUnavailable

    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)

    class _Dead:
        def __init__(self):
            pass

        def open_fetch(self, *a, **k):
            raise GitSandboxUnavailable("worker died")

        def close(self):
            pass

    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _Dead)
    with pytest.raises(fetcher._TimeoutError, match="git sandbox unavailable"):
        clone_or_fetch("demo")


# --- network timeout configuration ------------------------------------------


def test_network_timeouts_reach_the_worker(monkeypatch):
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"limits": {"network_connect_timeout": 4, "network_transfer_timeout": 9}},
    )
    assert fetcher._network_timeout_values() == (4, 9)


def test_network_timeouts_fall_back_when_unconfigured(monkeypatch):
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"limits": {"network_connect_timeout": 0}},
    )
    assert fetcher._network_timeout_values() == (
        fetcher.DEFAULT_CONNECT_TIMEOUT, fetcher.DEFAULT_TRANSFER_TIMEOUT,
    )


def test_clone_or_fetch_rejects_a_head_that_differs_from_the_advertisement(
        tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)

    class _Mismatch(_FakeSession):
        advertised = "a" * 40

        def head(self, pkg, cache_dir):
            return "b" * 40

    _FakeSession.instances = []
    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _Mismatch)
    with pytest.raises(fetcher._TimeoutError, match="does not match"):
        clone_or_fetch("demo", 1234)
    assert _FakeSession.instances[-1].closed


def test_offline_without_parent_state_refuses_before_spawning(
        tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    monkeypatch.setenv("TRUSTSIGHT_OFFLINE", "1")

    class _Explode:
        def __init__(self):
            raise AssertionError("a session was spawned for an unverified cache")

    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _Explode)
    with pytest.raises(fetcher._TimeoutError, match="no verified fetch state"):
        clone_or_fetch("demo")


def test_a_no_op_fetch_is_accepted_only_when_the_parent_state_matches(
        tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    from trustsight.sandbox import fetch_state

    head = "a" * 40
    fetch_state.store(cache, "demo", fetch_state.FetchState(
        head=head, advertised_head=head, fetched_at=10,
        upstream_mtime=10, verified=True))

    class _Noop(_FakeSession):
        def open_fetch(self, *args, **kwargs):
            return {"path": str(args[1]), "head": head,
                    "fetched": False, "marker_time": None,
                    "received_bytes": 0}

        def head(self, pkg, cache_dir):
            return head

    _Noop.advertised = head
    _FakeSession.instances = []
    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _Noop)
    project = clone_or_fetch("demo", 10)
    assert project.last_fetch_time() == 10
    project.close()


def test_a_no_op_mismatch_discards_the_repository(tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    repo = cache / "demo"
    repo.mkdir()
    (repo / "marker").write_text("x")
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    from trustsight.sandbox import fetch_state

    fetch_state.store(cache, "demo", fetch_state.FetchState(
        head="a" * 40, advertised_head="a" * 40, fetched_at=10,
        upstream_mtime=10, verified=True))

    class _Noop(_FakeSession):
        advertised = "a" * 40

        def open_fetch(self, *args, **kwargs):
            return {"path": str(args[1]), "head": self.advertised,
                    "fetched": False, "marker_time": None,
                    "received_bytes": 0}

        def head(self, pkg, cache_dir):
            return "b" * 40

    _FakeSession.instances = []
    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _Noop)
    with pytest.raises(fetcher._TimeoutError, match="not the verified HEAD"):
        clone_or_fetch("demo", 10)
    assert not repo.exists()


def test_prefetch_reports_a_state_backed_hint(tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    _FakeSession.instances = []
    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _FakeSession)

    from trustsight.review import prefetch

    hints = prefetch([{"name": "demo"}])

    assert isinstance(hints["demo"], int)
    assert hints["demo"] > 0


def test_a_worker_cannot_ignore_a_required_fetch(tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    from trustsight.sandbox import fetch_state

    head = "a" * 40
    fetch_state.store(cache, "demo", fetch_state.FetchState(
        head=head, advertised_head=head, fetched_at=10,
        upstream_mtime=10, verified=True))

    class _Stale(_FakeSession):
        def open_fetch(self, *args, **kwargs):
            return {"path": str(args[1]), "head": head,
                    "fetched": False, "marker_time": None,
                    "received_bytes": 0}

        def head(self, pkg, cache_dir):
            return head

    _FakeSession.instances = []
    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _Stale)
    with pytest.raises(fetcher._TimeoutError, match="did not perform"):
        clone_or_fetch("demo", 11)


def test_a_changed_upstream_mtime_forces_a_fetch(tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    from trustsight.sandbox import fetch_state

    head = "a" * 40
    fetch_state.store(cache, "demo", fetch_state.FetchState(
        head=head, advertised_head=head, fetched_at=10,
        upstream_mtime=10, verified=True))
    _FakeSession.instances = []
    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _FakeSession)

    project = clone_or_fetch("demo", 11)
    assert _FakeSession.instances[-1].calls[-1]["force"] is True
    project.close()
