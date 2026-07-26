"""clone_or_fetch's cache-freshness short circuit.

Fetching is the slowest step of an analysis, so a clone that already
carries the upstream's newest commit must not pay for a network round
trip.  Equally, a stale clone must still fetch: skipping when the cache
is behind would silently analyse the wrong diff.
"""

import time

import pygit2
import pytest

from trustsight.fetcher import (
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
