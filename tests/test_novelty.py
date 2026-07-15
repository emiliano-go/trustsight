import pytest

from trustsight.db import get_connection, get_package_id, init_db, upsert_package
from trustsight.novelty import (
    build_novelty_context,
    check_maintainer_novelty,
    check_url_novelty,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    upsert_package("testpkg", "1.0")
    yield


def test_url_first_seen_globally(db):
    first_pkg, first_global = check_url_novelty("https://brandnew.com/pkg.tar.gz", 1)
    assert first_global is True
    assert first_pkg is True


def test_url_seen_again_same_package(db):
    check_url_novelty("https://example.com/pkg.tar.gz", 1)
    first_pkg, first_global = check_url_novelty("https://example.com/pkg.tar.gz", 1)
    assert first_global is False
    assert first_pkg is False  # first_seen_package_id=1 matches current package=1


def test_url_seen_different_package(db):
    check_url_novelty("https://example.com/pkg.tar.gz", 1)
    first_pkg, first_global = check_url_novelty("https://example.com/pkg.tar.gz", 2)
    assert first_global is False
    assert first_pkg is True


def test_maintainer_first_seen(db):
    result = check_maintainer_novelty("newdev", 1)
    assert result is True


def test_maintainer_already_seen(db):
    check_maintainer_novelty("knowndev", 1)
    result = check_maintainer_novelty("knowndev", 1)
    assert result is False


def test_maintainer_seen_different_package(db):
    upsert_package("otherpkg", "1.0")
    pid2 = get_package_id("otherpkg")
    check_maintainer_novelty("shareddev", 1)
    result = check_maintainer_novelty("shareddev", pid2)
    assert result is True


def test_build_novelty_context_url_added(db):
    ctx = build_novelty_context(["https://brandnew.com/pkg.tar.gz"], 1)
    assert ctx.url_first_seen_globally is True
    assert ctx.url_first_seen_in_this_package is True


def test_build_novelty_context_maintainer(db):
    ctx = build_novelty_context([], 1, maintainer="freshmaintainer")
    assert ctx.maintainer_first_seen_for_this_package is True


def test_build_novelty_context_no_changes(db):
    ctx = build_novelty_context([], 1)
    assert ctx.url_first_seen_globally is False
    assert ctx.url_first_seen_in_this_package is False
    assert ctx.maintainer_first_seen_for_this_package is False


def test_build_novelty_context_multiple_urls(db):
    urls = ["https://first.com/a.tar.gz", "https://second.com/b.tar.gz"]
    ctx = build_novelty_context(urls, 1)
    assert ctx.url_first_seen_globally is True
    assert ctx.url_first_seen_in_this_package is True


def test_build_novelty_context_some_already_seen(db):
    check_url_novelty("https://existing.com/pkg.tar.gz", 1)
    urls = ["https://existing.com/pkg.tar.gz", "https://brandnew.com/new.tar.gz"]
    ctx = build_novelty_context(urls, 1)
    assert ctx.url_first_seen_globally is True
    assert ctx.url_first_seen_in_this_package is True


def test_url_tracking_increments_counter(db):
    check_url_novelty("https://example.com/pkg.tar.gz", 1)
    check_url_novelty("https://example.com/pkg.tar.gz", 2)
    check_url_novelty("https://example.com/pkg.tar.gz", 3)
    conn = get_connection()
    row = conn.execute("SELECT total_uses FROM source_urls WHERE url = ?", ("https://example.com/pkg.tar.gz",)).fetchone()
    conn.close()
    assert row["total_uses"] == 3
