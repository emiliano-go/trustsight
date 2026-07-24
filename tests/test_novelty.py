import pytest

from trustsight.db import get_connection, get_package_id, init_db, upsert_package
from trustsight.novelty import (
    build_novelty_context,
    check_maintainer_novelty,
    check_url_novelty,
    normalize_url,
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
    url = "https://example.com/pkg.tar.gz"
    nurl = normalize_url(url)
    check_url_novelty(url, 1)
    check_url_novelty(url, 2)
    check_url_novelty(url, 3)
    with get_connection() as conn:
        row = conn.execute("SELECT total_uses FROM source_urls WHERE url = ?", (nurl,)).fetchone()
    assert row["total_uses"] == 3


# --- URL normalization ---

def test_normalize_strips_version():
    n = normalize_url("https://github.com/user/pro/archive/v2.0.0.tar.gz")
    assert "2.0.0" not in n


def test_normalize_strips_two_part_version():
    n = normalize_url("https://example.com/releases/1.2/file.tar.gz")
    assert "1.2" not in n


def test_normalize_deduplicates_version_templates():
    a = normalize_url("https://example.com/pkg/v2.0.0.tar.gz")
    b = normalize_url("https://example.com/pkg/v2.0.1.tar.gz")
    assert a == b


def test_normalize_strips_hash():
    n = normalize_url("https://example.com/pkg/abc123def456abc789abc123def456abc123def4.tar.gz")
    assert "HASH" in n


def test_normalize_strips_date():
    n = normalize_url("https://example.com/snapshots/2024-03-15/file.tar.gz")
    assert "2024" not in n


def test_normalize_unchanged_simple_url():
    n = normalize_url("https://github.com/user/project.git")
    assert n == "https://github.com/user/project.git"


def test_normalize_version_bump_same_template():
    v1 = normalize_url("https://github.com/rust-lang/cargo/archive/0.80.0.tar.gz")
    v2 = normalize_url("https://github.com/rust-lang/cargo/archive/0.81.0.tar.gz")
    assert v1 == v2


def test_novelty_not_fired_on_version_bump(db):
    url_old = "https://github.com/user/proj/archive/v1.0.0.tar.gz"
    url_new = "https://github.com/user/proj/archive/v2.0.0.tar.gz"
    check_url_novelty(url_old, 1)
    first_pkg, first_global = check_url_novelty(url_new, 1)
    assert first_global is False
    assert first_pkg is False


# --- Database maturity (tier C gating) ---

def test_observation_count_starts_at_zero(db):
    from trustsight.db import count_observations

    assert count_observations() == 0


def test_observation_count_tracks_recorded_analyses(db):
    from trustsight.db import count_observations, insert_analysis

    pkg_id = get_package_id("testpkg")
    for i in range(3):
        insert_analysis(
            package_id=pkg_id, old_version="1.0", new_version=f"1.{i}",
            old_commit="a" * 40, new_commit="b" * 40, final_score=0,
            raw_diff="", fact_json="{}", triggered_rules=[],
        )
    assert count_observations() == 3


def test_build_novelty_context_populates_observation_count(db):
    """Regression: observation_count was never assigned, so maturity()
    always saw 0 and every tier C novelty weight scored zero."""
    from trustsight.db import insert_analysis

    pkg_id = get_package_id("testpkg")
    for i in range(5):
        insert_analysis(
            package_id=pkg_id, old_version="1.0", new_version=f"1.{i}",
            old_commit="a" * 40, new_commit="b" * 40, final_score=0,
            raw_diff="", fact_json="{}", triggered_rules=[],
        )

    ctx = build_novelty_context(["https://new.example.com/x.tar.gz"], pkg_id)
    assert ctx.observation_count == 5


def test_novelty_scores_zero_on_a_cold_database(db):
    """The cold-start guarantee: novelty must contribute nothing until
    the database has observations."""
    from trustsight.scoring import calculate_score

    pkg_id = get_package_id("testpkg")
    ctx = build_novelty_context(["https://brand-new.example.com/x.tar.gz"], pkg_id)
    assert ctx.url_first_seen_globally is True
    assert ctx.observation_count == 0

    config = {
        "severity_weights": {},
        "novelty_weights": {"url_first_globally": 15, "url_first_in_package": 10},
    }
    score, breakdown, _ = calculate_score([], {}, ctx, config)
    assert score == 0
    assert not [e for e in breakdown if e.rule_id == "NOVELTY"]


def test_novelty_contributes_once_database_is_warm(db):
    """The counterpart: with observations recorded, tier C is live."""
    from trustsight.db import insert_analysis
    from trustsight.scoring import calculate_score

    pkg_id = get_package_id("testpkg")
    for i in range(50):
        insert_analysis(
            package_id=pkg_id, old_version="1.0", new_version=f"1.{i}",
            old_commit="a" * 40, new_commit="b" * 40, final_score=0,
            raw_diff="", fact_json="{}", triggered_rules=[],
        )

    ctx = build_novelty_context(["https://brand-new.example.com/x.tar.gz"], pkg_id)
    assert ctx.observation_count == 50

    config = {
        "severity_weights": {},
        "novelty_weights": {"url_first_globally": 15, "url_first_in_package": 10},
    }
    score, breakdown, _ = calculate_score([], {}, ctx, config)
    assert score == 25
    assert [e for e in breakdown if e.rule_id == "NOVELTY"]


def test_observation_count_excludes_the_current_analysis(db):
    """Maturity is read before the current run is recorded, so a package
    is never counted as an observation of itself."""
    pkg_id = get_package_id("testpkg")
    ctx = build_novelty_context(["https://x.example.com/a.tar.gz"], pkg_id)
    assert ctx.observation_count == 0
