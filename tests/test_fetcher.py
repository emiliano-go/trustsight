"""clone_or_fetch's cache-freshness short circuit.

Fetching is the slowest step of an analysis, so a clone that already
carries the upstream's newest commit must not pay for a network round
trip.  Equally, a stale clone must still fetch: skipping when the cache
is behind would silently analyse the wrong diff.
"""

import shutil
import time

import pygit2
import pytest

from trustsight import fetcher
from trustsight.fetcher import (
    _apply_network_timeouts,
    _is_current,
    _record_fetch,
    clone_or_fetch,
    get_head_commit,
    last_fetch_time,
)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A real git repository standing in for a cached AUR clone."""
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    path = cache / "demo"
    created = pygit2.init_repository(str(path))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = created.create_blob(b"pkgver=1.0\n")
    builder = created.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    created.create_commit(
        "HEAD", author, author, "initial", builder.write(), []
    )
    # clone_or_fetch reaches for remotes["origin"]; the URL is never
    # contacted because the tests that get that far stub out fetch.
    created.remotes.create("origin", "https://aur.archlinux.org/demo.git")
    return created


def _head_time(repo) -> int:
    return int(repo[get_head_commit(repo)].commit_time)


def test_is_current_when_fetched_at_or_after_upstream(repo):
    fetched = _record_fetch(repo)
    assert _is_current(repo, fetched) is True
    assert _is_current(repo, fetched - 60) is True


def test_is_not_current_when_upstream_is_newer_than_our_fetch(repo):
    fetched = _record_fetch(repo)
    assert _is_current(repo, fetched + 60) is False


def test_is_not_current_without_a_marker(repo):
    """A clone from an older version has no marker and must be fetched."""
    assert last_fetch_time(repo) is None
    assert _is_current(repo, int(time.time())) is False


def test_a_future_dated_commit_cannot_suppress_fetches(repo, monkeypatch):
    """Freshness must not be decided by an upstream-controlled timestamp.

    A maintainer sets a commit's date freely.  When freshness was read
    from HEAD's commit time, dating a commit in the future made the clone
    look permanently current, so trustsight never fetched that package
    again and went blind to every subsequent update.
    """
    author = pygit2.Signature(
        "Tester", "tester@example.com", int(time.time()) + 10 * 365 * 86400, 0
    )
    blob = repo.create_blob(b"pkgver=2.0\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    repo.create_commit(
        "HEAD", author, author, "future", builder.write(),
        [repo.head.peel().id],
    )
    assert _head_time(repo) > time.time(), "fixture should be future-dated"

    _record_fetch(repo)
    calls = []
    monkeypatch.setattr(
        pygit2.Remote, "fetch", lambda self, *a, **k: calls.append(1)
    )
    # The AUR reports an update after our last fetch: it must be fetched,
    # however far ahead the local commit claims to be.
    clone_or_fetch("demo", int(time.time()) + 5)
    assert calls, "future-dated commit suppressed a needed fetch"


def test_clone_or_fetch_skips_the_network_when_current(repo, monkeypatch):
    """A current clone is returned without touching the remote."""
    fetched = _record_fetch(repo)

    def explode(*args, **kwargs):
        raise AssertionError("fetch attempted despite an up-to-date clone")

    monkeypatch.setattr(pygit2.Remote, "fetch", explode)
    result = clone_or_fetch("demo", fetched)
    assert get_head_commit(result) == get_head_commit(repo)


def test_clone_or_fetch_still_fetches_when_upstream_is_newer(repo, monkeypatch):
    """A stale clone must not be short-circuited."""
    fetched = _record_fetch(repo)
    calls = []
    monkeypatch.setattr(
        pygit2.Remote, "fetch", lambda self, *a, **k: calls.append(1)
    )
    clone_or_fetch("demo", fetched + 3600)
    assert calls, "expected a fetch for a clone behind upstream"


def test_a_successful_fetch_records_the_marker(repo, monkeypatch):
    """Without recording, the skip could never trigger on a later run."""
    monkeypatch.setattr(pygit2.Remote, "fetch", lambda self, *a, **k: None)
    clone_or_fetch("demo")
    assert last_fetch_time(repo) is not None


def test_clone_or_fetch_fetches_when_no_hint_is_given(repo, monkeypatch):
    """Without a hint the behaviour is unchanged: always fetch."""
    calls = []
    monkeypatch.setattr(
        pygit2.Remote, "fetch", lambda self, *a, **k: calls.append(1)
    )
    clone_or_fetch("demo")
    assert calls, "expected a fetch when the caller supplied no hint"


def test_a_failed_fetch_keeps_the_cached_clone(repo, monkeypatch):
    """A network failure must not cost us the clone.

    Deleting the cache on a failed fetch means the next attempt pays for a
    full clone over the same connection that just failed - and when the
    stall is on the AUR's side, that clone fails too and the cache is gone
    for every later run as well.
    """
    path = fetcher.repo_path("demo")

    def explode(self, *args, **kwargs):
        raise pygit2.GitError("connection reset")

    monkeypatch.setattr(pygit2.Remote, "fetch", explode)
    with pytest.raises(pygit2.GitError):
        clone_or_fetch("demo")
    assert path.exists(), "a failed fetch deleted a usable clone"
    assert get_head_commit(pygit2.Repository(str(path)))


def test_an_unreadable_clone_is_rebuilt(repo, monkeypatch):
    """Corruption, unlike a failed fetch, is grounds for a re-clone."""
    path = fetcher.repo_path("demo")
    cloned = []

    def fake_clone(url, dest, **kwargs):
        cloned.append(url)
        return pygit2.init_repository(dest)

    shutil.rmtree(path / ".git")  # a directory that is no longer a repository
    monkeypatch.setattr(pygit2, "clone_repository", fake_clone)
    clone_or_fetch("demo")
    assert cloned == ["https://aur.archlinux.org/demo.git"]
    assert path.exists()


@pytest.fixture
def unapplied_timeouts(monkeypatch):
    """Reset the once-per-process guard and restore libgit2's settings."""
    before = (
        pygit2.settings.server_connect_timeout,
        pygit2.settings.server_timeout,
    )
    monkeypatch.setattr(fetcher, "_NETWORK_TIMEOUTS_APPLIED", False)
    yield
    pygit2.settings.server_connect_timeout = before[0]
    pygit2.settings.server_timeout = before[1]
    fetcher._NETWORK_TIMEOUTS_APPLIED = False


def test_network_timeouts_reach_libgit2(unapplied_timeouts, monkeypatch):
    """The deadline callbacks cannot see a socket that never delivers.

    A connection that stalls before the first byte never invokes
    transfer_progress, so only libgit2's own timeouts can end it.
    """
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"limits": {"network_connect_timeout": 4, "network_transfer_timeout": 9}},
    )
    _apply_network_timeouts()
    assert pygit2.settings.server_connect_timeout == 4000
    assert pygit2.settings.server_timeout == 9000


def test_network_timeouts_fall_back_when_unconfigured(unapplied_timeouts, monkeypatch):
    """An absent or nonsensical value must still leave a finite deadline."""
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"limits": {"network_connect_timeout": 0}},
    )
    _apply_network_timeouts()
    assert pygit2.settings.server_connect_timeout == fetcher.DEFAULT_CONNECT_TIMEOUT * 1000
    assert pygit2.settings.server_timeout == fetcher.DEFAULT_TRANSFER_TIMEOUT * 1000


def test_clone_or_fetch_applies_the_timeouts_before_the_network(
    repo, unapplied_timeouts, monkeypatch
):
    """The settings are worthless if a fetch can start before they are set."""
    monkeypatch.setattr(pygit2.Remote, "fetch", lambda self, *a, **k: None)
    clone_or_fetch("demo")
    assert fetcher._NETWORK_TIMEOUTS_APPLIED is True
