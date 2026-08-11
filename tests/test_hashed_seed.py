import json
import sqlite3
import tarfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trustsight.cli import app
from trustsight.db import (
    SEED_DIGEST_KEY,
    _get_salt,
    _hash_maintainer_value,
    get_connection,
    get_metadata,
    import_seed,
    init_db,
    is_maintainer_globally_novel,
    lookup_maintainer,
    seed_observation_count,
)
from trustsight.seed_build import build_seed


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield


def _build_v2_seed(tmp_path, maintainers=None, urls=None, deps=None):
    seed_dir = tmp_path / "seed-v2"
    raw = maintainers or [
        {"name": "Alice Example", "email": "alice@example.com",
         "packages": ["pkg-a", "pkg-b"], "source": "aur"},
        {"name": "Bob Builder", "packages": ["pkg-c"], "source": "aur"},
    ]
    build_seed(raw, seed_dir)

    if urls:
        with open(seed_dir / "trustsight-seed-v2" / "source_urls.jsonl", "w") as fh:
            for u in urls:
                fh.write(json.dumps(u) + "\n")

    if deps:
        with open(seed_dir / "trustsight-seed-v2" / "dependency_names.jsonl", "w") as fh:
            for d in deps:
                fh.write(json.dumps(d) + "\n")

    return seed_dir


def test_hashing_is_deterministic_with_salt():
    salt = "a" * 64
    h1 = _hash_maintainer_value("Same Name", salt)
    h2 = _hash_maintainer_value("Same Name", salt)
    h3 = _hash_maintainer_value("Different Name", salt)
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64


def test_build_seed_writes_expected_files(tmp_path):
    raw = [{"name": "Carol Coder", "email": "carol@example.com", "packages": ["pkg-d"]}]
    result = build_seed(raw, tmp_path)
    seed_dir = Path(result["seed_dir"])
    assert seed_dir.exists()
    assert (seed_dir / "seed_meta.json").exists()
    assert (seed_dir / "maintainers.jsonl").exists()

    meta = json.loads((seed_dir / "seed_meta.json").read_text())
    assert meta["format_version"] == "2.0.0"
    assert meta["hash_algorithm"] == "sha256"
    assert meta["count"] == 1
    assert "salt" in meta
    assert "seed_hash" in meta

    lines = (seed_dir / "maintainers.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["name_hash"] == _hash_maintainer_value("Carol Coder", meta["salt"])
    assert row["email_hash"] == _hash_maintainer_value("carol@example.com", meta["salt"])


def test_build_seed_folds_duplicate_names(tmp_path):
    raw = [
        {"name": "Dave Dev", "packages": ["pkg-x"]},
        {"name": "Dave Dev", "packages": ["pkg-y"]},
    ]
    result = build_seed(raw, tmp_path)
    assert result["count"] == 1
    lines = (Path(result["seed_dir"]) / "maintainers.jsonl").read_text().strip().splitlines()
    row = json.loads(lines[0])
    assert set(row["packages"]) == {"pkg-x", "pkg-y"}


def test_import_v2_seed_populates_hashed_maintainers(db, tmp_path):
    seed_dir = _build_v2_seed(tmp_path)
    stats = import_seed(seed_dir)

    assert stats["maintainers"] == 2
    assert seed_observation_count() == 2
    with get_connection() as conn:
        assert _get_salt(conn) is not None

    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM maintainers_hashed").fetchall()
        assert len(rows) == 2
        assert not any("Alice Example" in str(tuple(r)) for r in rows)


def test_import_v2_seed_populates_optional_urls_and_deps(db, tmp_path):
    urls = [
        {"url": "https://github.com/acme/tool/archive/v1.tar.gz",
         "first_seen_globally_timestamp": "2024-01-01", "total_uses": 10},
    ]
    deps = [{"name": "openssl", "observation_count": 100}]
    seed_dir = _build_v2_seed(tmp_path, urls=urls, deps=deps)
    stats = import_seed(seed_dir)

    assert stats["urls_total"] == 1
    assert stats["dependency_names"] == 1


def test_import_v2_seed_records_provenance(db, tmp_path):
    seed_dir = _build_v2_seed(tmp_path)
    import_seed(seed_dir)

    assert get_metadata(SEED_DIGEST_KEY) is not None
    assert get_metadata("seed_origin") == str(seed_dir)


def test_import_v2_from_tar_gz(db, tmp_path):
    seed_dir = _build_v2_seed(tmp_path)
    archive = tmp_path / "seed.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(seed_dir / "trustsight-seed-v2", arcname="trustsight-seed-v2")

    stats = import_seed(archive)
    assert stats["maintainers"] == 2


def test_lookup_maintainer_finds_hashed_identity(db, tmp_path):
    seed_dir = _build_v2_seed(tmp_path)
    import_seed(seed_dir)

    row = lookup_maintainer("Alice Example")
    assert row is not None
    assert row["package_count"] == 2

    row = lookup_maintainer("Alice Example", "alice@example.com")
    assert row is not None

    row = lookup_maintainer("Unknown Person")
    assert row is None


def test_is_maintainer_globally_novel_with_hashed_seed(db, tmp_path):
    seed_dir = _build_v2_seed(tmp_path)
    import_seed(seed_dir)

    assert is_maintainer_globally_novel("Alice Example") is False
    assert is_maintainer_globally_novel("Bob Builder") is False
    assert is_maintainer_globally_novel("Never Seen") is True


def test_maintainer_first_seen_for_package_uses_hashed_table(db, tmp_path):
    from trustsight.db import upsert_package
    from trustsight.novelty import check_maintainer_novelty

    pkg_id = upsert_package("demo", "1.0")

    # Without a salt, the legacy plaintext table is used.
    assert check_maintainer_novelty("Mallory", pkg_id) is True
    assert check_maintainer_novelty("Mallory", pkg_id) is False

    # After seeding, hashed per-package records are used.
    seed_dir = _build_v2_seed(tmp_path)
    import_seed(seed_dir)
    pkg2 = upsert_package("other", "1.0")
    assert check_maintainer_novelty("Alice Example", pkg2) is True
    assert check_maintainer_novelty("Alice Example", pkg2) is False


def test_migration_from_plaintext_maintainers(tmp_path):
    """init_db migrates the old plaintext table to salted hashes."""
    from trustsight.db import close_connections

    close_connections()
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    legacy = sqlite3.connect(str(tmp_path / "trustsight.db"))
    legacy.executescript("""
        CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT UNIQUE);
        CREATE TABLE maintainers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            first_seen_package_id INTEGER
        );
    """)
    legacy.execute("INSERT INTO packages (name) VALUES ('pkg-1')")
    pid = legacy.execute("SELECT id FROM packages WHERE name = 'pkg-1'").fetchone()[0]
    legacy.execute(
        "INSERT INTO maintainers (name, first_seen_package_id) VALUES (?, ?)",
        ("Plaintext Maintainer", pid),
    )
    legacy.commit()
    legacy.close()

    with pytest.warns(UserWarning, match="Plaintext maintainers table detected"):
        init_db()

    with get_connection() as conn:
        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "maintainers" not in tables
        assert "maintainers_deprecated_backup" in tables
        assert "maintainers_hashed" in tables

    assert is_maintainer_globally_novel("Plaintext Maintainer") is False
    with get_connection() as conn:
        assert _get_salt(conn) is not None

    monkeypatch.undo()


def test_seed_cli_info(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()

    result = CliRunner().invoke(app, ["seed", "info"])
    assert result.exit_code == 0
    assert "Seeded" in result.output or "seeded" in result.output


def test_seed_cli_stats(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()

    result = CliRunner().invoke(app, ["seed", "stats"])
    assert result.exit_code == 0
    assert "Total maintainers" in result.output


def test_seed_cli_migrate_from_legacy_table(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()

    with get_connection() as conn:
        # The legacy table may already exist on a fresh database; insert a row.
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )
        conn.execute(
            "INSERT INTO maintainers (name, first_seen_package_id) VALUES (?, 0)",
            ("Legacy Maintainer",),
        )
        conn.commit()

    result = CliRunner().invoke(app, ["seed", "migrate", "--from-backup"])
    assert result.exit_code == 0, result.output
    assert is_maintainer_globally_novel("Legacy Maintainer") is False


# --- normalization edge cases (spec §3.3.1: lowercase().strip()) -----------


def test_hash_is_case_and_whitespace_insensitive():
    """A maintainer whose casing or surrounding whitespace varies must hash
    to one value, or the novelty signal reads every spelling as a new person."""
    salt = "c" * 64
    canonical = _hash_maintainer_value("Alice Example", salt)
    assert _hash_maintainer_value("alice example", salt) == canonical
    assert _hash_maintainer_value("  ALICE EXAMPLE  ", salt) == canonical
    assert _hash_maintainer_value("Bob Builder", salt) != canonical


def test_build_migration_and_lookup_hash_identically():
    """The seed builder and the db lookup are one chokepoint; a value hashed
    on either side must match, or an imported seed never resolves."""
    from trustsight.seed_build import _hash_value

    salt = "d" * 64
    assert _hash_value("Carol Coder", salt) == _hash_maintainer_value("carol coder", salt)


def test_lookup_matches_a_differently_cased_maintainer(db, tmp_path):
    """End to end: a seeded maintainer is found when the PKGBUILD spells the
    name with different case and whitespace."""
    seed_dir = _build_v2_seed(tmp_path)
    import_seed(seed_dir)
    assert lookup_maintainer("  alice EXAMPLE ") is not None
    assert is_maintainer_globally_novel("ALICE EXAMPLE") is False


def test_lookup_without_a_salt_returns_none_not_error(db):
    """A cold database (no seed imported, no salt) must answer, not crash."""
    assert lookup_maintainer("Anyone At All") is None
    assert is_maintainer_globally_novel("Anyone At All") is True
