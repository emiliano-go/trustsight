import pytest

from trustsight.db import (
    get_all_packages,
    get_connection,
    get_history,
    get_last_analysis,
    get_package,
    get_package_id,
    get_triggered_rules,
    init_db,
    insert_analysis,
    update_package_version,
    upsert_package,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


def test_init_db_creates_tables(db):
    with get_connection() as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
        table_names = [r["name"] for r in tables]
    assert "packages" in table_names
    assert "source_urls" in table_names
    assert "maintainers" in table_names
    assert "analysis_history" in table_names
    assert "triggered_rules" in table_names


def test_upsert_package_new(db):
    pid = upsert_package("testpkg", "1.0.0")
    assert isinstance(pid, int)
    assert pid > 0


def test_upsert_package_existing(db):
    pid1 = upsert_package("testpkg", "1.0.0")
    pid2 = upsert_package("testpkg", "2.0.0")
    assert pid1 == pid2


def test_get_package_id_found(db):
    upsert_package("myapp", "1.0")
    pid = get_package_id("myapp")
    assert pid is not None
    assert isinstance(pid, int)


def test_get_package_id_not_found(db):
    pid = get_package_id("nonexistent")
    assert pid is None


def test_get_package_found(db):
    upsert_package("myapp", "1.0")
    pkg = get_package("myapp")
    assert pkg is not None
    assert pkg["name"] == "myapp"
    assert pkg["current_version"] == "1.0"


def test_get_package_not_found(db):
    pkg = get_package("nonexistent")
    assert pkg is None


def test_update_package_version(db):
    upsert_package("myapp", "1.0")
    update_package_version("myapp", "2.0")
    pkg = get_package("myapp")
    assert pkg["current_version"] == "2.0"


def test_insert_analysis(db):
    pid = upsert_package("myapp", "1.0")
    triggered = [{"rule_id": "R001", "severity": "CRITICAL"}]
    hid = insert_analysis(
        package_id=pid,
        old_version="1.0",
        new_version="2.0",
        old_commit="abc123",
        new_commit="def456",
        final_score=85,
        raw_diff="+echo hello",
        fact_json='{"package_name": "myapp"}',
        triggered_rules=triggered,
    )
    assert isinstance(hid, int)
    assert hid > 0


def test_get_last_analysis_none(db):
    pid = upsert_package("myapp", "1.0")
    last = get_last_analysis(pid)
    assert last is None


def test_get_last_analysis_found(db):
    pid = upsert_package("myapp", "1.0")
    insert_analysis(pid, "1.0", "2.0", "abc", "def", 50, "+diff", "{}", [])
    insert_analysis(pid, "2.0", "3.0", "def", "ghi", 85, "+diff2", "{}", [])
    last = get_last_analysis(pid)
    assert last is not None
    assert last["final_score"] == 85
    assert last["new_commit"] == "ghi"


def test_get_triggered_rules(db):
    pid = upsert_package("myapp", "1.0")
    rules = [{"rule_id": "R001", "severity": "CRITICAL"}, {"rule_id": "R004", "severity": "HIGH"}]
    hid = insert_analysis(pid, "1.0", "2.0", "a", "b", 65, "+d", "{}", rules)
    stored = get_triggered_rules(hid)
    assert len(stored) == 2
    assert stored[0]["rule_id"] in ("R001", "R004")


def test_get_history(db):
    pid = upsert_package("myapp", "1.0")
    for i in range(5):
        insert_analysis(pid, f"{i}.0", f"{i+1}.0", "a", "b", i * 10, "+d", "{}", [])
    history = get_history(pid, limit=3)
    assert len(history) == 3
    assert history[0]["final_score"] == 40


def test_get_all_packages(db):
    upsert_package("alpha", "1.0")
    upsert_package("beta", "2.0")
    pkgs = get_all_packages()
    names = [p["name"] for p in pkgs]
    assert "alpha" in names
    assert "beta" in names


def test_source_url_unique_constraint(db):
    upsert_package("testpkg", "1.0")
    pid = get_package_id("testpkg")
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO source_urls (url, first_seen_package_id, first_seen_globally_timestamp) VALUES (?, ?, datetime('now'))",
            ("https://unique-url.com/pkg.tar.gz", pid),
        )
        conn.commit()
        with pytest.raises(Exception):
            conn.execute(
                "INSERT INTO source_urls (url, first_seen_package_id) VALUES (?, ?)",
                ("https://unique-url.com/pkg.tar.gz", pid),
            )
            conn.commit()


def test_foreign_key_enforced(db):
    with pytest.raises(Exception):
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO analysis_history (package_id, old_version, new_version) VALUES (99999, '1.0', '2.0')",
            )
            conn.commit()


def test_analysis_stores_diff_blob(db):
    pid = upsert_package("myapp", "1.0")
    diff = "+source=('https://evil.com/payload.tar.gz')\n+sha256sums=('SKIP')"
    hid = insert_analysis(pid, "1.0", "2.0", "a", "b", 85, diff, "{}", [])
    with get_connection() as conn:
        row = conn.execute("SELECT raw_diff_blob FROM analysis_history WHERE id = ?", (hid,)).fetchone()
    assert row is not None
    assert "evil.com" in row["raw_diff_blob"]


def test_init_db_idempotent(db):
    init_db()
    init_db()
    init_db()
    with get_connection() as conn:
        tables = conn.execute("SELECT count(*) as cnt FROM sqlite_master WHERE type='table'").fetchone()
    assert tables["cnt"] >= 5


# --- Seed import and maturity bootstrap ---

def _make_seed(path, urls=("https://github.com/a/v0.tar.gz",), observations=279):
    import sqlite3

    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT UNIQUE,
                               current_version TEXT, last_checked TEXT);
        CREATE TABLE source_urls (id INTEGER PRIMARY KEY, url TEXT UNIQUE,
                                  first_seen_package_id INTEGER,
                                  first_seen_globally_timestamp TEXT,
                                  total_uses INTEGER, last_seen_timestamp TEXT);
        CREATE TABLE maintainer_counts (name TEXT PRIMARY KEY, count INTEGER);
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
    """)
    conn.execute("INSERT INTO packages (id, name) VALUES (0, '__seed__')")
    for u in urls:
        conn.execute(
            """INSERT INTO source_urls (url, first_seen_package_id,
               first_seen_globally_timestamp, total_uses, last_seen_timestamp)
               VALUES (?, 0, '2024-01-01', 500, '2024-01-01')""", (u,))
    conn.execute("INSERT INTO maintainer_counts (name, count) VALUES ('Someone', 12)")
    conn.execute("INSERT INTO metadata (key, value) VALUES ('seed_observation_count', ?)",
                 (str(observations),))
    conn.commit()
    conn.close()


def test_seed_observation_count_defaults_to_zero(db):
    from trustsight.db import seed_observation_count

    assert seed_observation_count() == 0


def test_import_seed_populates_urls_and_bootstrap(db, tmp_path):
    from trustsight.db import (
        effective_observation_count,
        import_seed,
        seed_observation_count,
    )

    seed = tmp_path / "seed.db"
    _make_seed(seed)
    stats = import_seed(seed)

    assert stats["urls_added"] == 1
    assert seed_observation_count() == 279
    assert effective_observation_count() == 279


def test_real_history_overtakes_the_seed(db, tmp_path):
    """Ordinary use eventually replaces the seed, so the tool never
    depends on external data permanently."""
    from trustsight.db import (
        count_observations,
        effective_observation_count,
        import_seed,
        insert_analysis,
        upsert_package,
    )

    seed = tmp_path / "seed.db"
    _make_seed(seed, observations=10)
    import_seed(seed)
    assert effective_observation_count() == 10

    pkg_id = upsert_package("p", "1.0")
    for i in range(15):
        insert_analysis(package_id=pkg_id, old_version="1", new_version=f"1.{i}",
                        old_commit="a" * 40, new_commit="b" * 40, final_score=0,
                        raw_diff="", fact_json="{}", triggered_rules=[])
    assert count_observations() == 15
    assert effective_observation_count() == 15


def test_import_seed_never_overwrites_learned_rows(db, tmp_path):
    """A seed must not clobber something a real analysis recorded."""
    from trustsight.db import get_connection, import_seed

    url = "https://github.com/a/v0.tar.gz"
    with get_connection() as conn:
        conn.execute("INSERT INTO packages (id, name) VALUES (7, 'real')")
        conn.execute(
            """INSERT INTO source_urls (url, first_seen_package_id,
               first_seen_globally_timestamp, total_uses)
               VALUES (?, 7, '2026-01-01', 3)""", (url,))
        conn.commit()

    seed = tmp_path / "seed.db"
    _make_seed(seed, urls=(url,))
    import_seed(seed)

    with get_connection() as conn:
        row = conn.execute(
            "SELECT first_seen_package_id, total_uses FROM source_urls WHERE url = ?",
            (url,)).fetchone()
    assert row["first_seen_package_id"] == 7
    assert row["total_uses"] == 3


def test_import_seed_is_idempotent(db, tmp_path):
    from trustsight.db import import_seed

    seed = tmp_path / "seed.db"
    _make_seed(seed)
    import_seed(seed)
    second = import_seed(seed)
    assert second["urls_added"] == 0


def test_import_seed_accepts_gzip(db, tmp_path):
    import gzip
    import shutil

    from trustsight.db import import_seed

    seed = tmp_path / "seed.db"
    _make_seed(seed)
    gz = tmp_path / "seed.db.gz"
    with open(seed, "rb") as s, gzip.open(gz, "wb") as d:
        shutil.copyfileobj(s, d)
    seed.unlink()

    assert import_seed(gz)["urls_total"] == 1


def test_missing_seed_raises(db, tmp_path):
    from trustsight.db import import_seed

    try:
        import_seed(tmp_path / "nope.db")
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")


def test_auto_import_is_skipped_when_already_seeded(db, tmp_path, monkeypatch):
    import trustsight.db as dbmod

    seed = tmp_path / "seed.db"
    _make_seed(seed)
    monkeypatch.setattr(dbmod, "bundled_seed_path", lambda: seed)
    assert dbmod.maybe_auto_import_seed(quiet=True) is not None
    assert dbmod.maybe_auto_import_seed(quiet=True) is None


def test_auto_import_is_skipped_when_history_exists(db, tmp_path, monkeypatch):
    """A database with real analyses does not need a bootstrap."""
    import trustsight.db as dbmod

    pkg_id = dbmod.upsert_package("p", "1.0")
    dbmod.insert_analysis(package_id=pkg_id, old_version="1", new_version="2",
                          old_commit="a" * 40, new_commit="b" * 40, final_score=0,
                          raw_diff="", fact_json="{}", triggered_rules=[])
    seed = tmp_path / "seed.db"
    _make_seed(seed)
    monkeypatch.setattr(dbmod, "bundled_seed_path", lambda: seed)
    assert dbmod.maybe_auto_import_seed(quiet=True) is None


def test_auto_import_is_a_noop_without_a_bundled_seed(db, tmp_path, monkeypatch):
    import trustsight.db as dbmod

    monkeypatch.setattr(dbmod, "bundled_seed_path", lambda: tmp_path / "absent.db.gz")
    assert dbmod.maybe_auto_import_seed(quiet=True) is None


def test_seeded_url_is_not_novel_after_version_bump(db, tmp_path, monkeypatch):
    """The whole point of the seed: an ordinary AUR source URL, and the
    same URL at a new version, must both be recognised."""
    import trustsight.db as dbmod
    from trustsight.novelty import build_novelty_context, normalize_url

    url = "https://github.com/acme/tool/archive/v1.0.0.tar.gz"
    seed = tmp_path / "seed.db"
    _make_seed(seed, urls=(normalize_url(url),))
    monkeypatch.setattr(dbmod, "bundled_seed_path", lambda: seed)
    dbmod.maybe_auto_import_seed(quiet=True)

    pkg_id = dbmod.upsert_package("demo", "1.0")
    bumped = "https://github.com/acme/tool/archive/v2.5.1.tar.gz"
    ctx = build_novelty_context([bumped], pkg_id)
    assert ctx.url_first_seen_globally is False
    assert ctx.observation_count == 279


def test_unseeded_domain_is_still_novel(db, tmp_path, monkeypatch):
    import trustsight.db as dbmod
    from trustsight.novelty import build_novelty_context

    seed = tmp_path / "seed.db"
    _make_seed(seed)
    monkeypatch.setattr(dbmod, "bundled_seed_path", lambda: seed)
    dbmod.maybe_auto_import_seed(quiet=True)

    pkg_id = dbmod.upsert_package("demo", "1.0")
    ctx = build_novelty_context(["https://unknown-host.invalid/x-1.0.tar.gz"], pkg_id)
    assert ctx.url_first_seen_globally is True
