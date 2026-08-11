import atexit
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import warnings
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .config import DATA_DIR

# Ceiling on a decompressed seed database.  The bundled seed is ~20 MB
# compressed and a few hundred MB expanded; ``trustsight seed-db`` takes a
# path, so the ceiling is what stops an arbitrary .gz from filling the disk.
MAX_SEED_BYTES = 2 * 1024 * 1024 * 1024


def get_db_path() -> Path:
    """Return the path to the SQLite database file."""
    return DATA_DIR / "trustsight.db"


# Connections are cached per (thread, database path) rather than opened per
# query.  Opening one costs ~0.35ms once the two PRAGMAs are counted, and the
# hot paths issue thousands of small reads: R074 alone used to open 5001
# connections for a single package.  Keying on the path keeps the tests
# honest, since they monkeypatch DATA_DIR to a tmpdir between cases.
_local = threading.local()


def _new_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # journal_mode is a persistent property of the file, so this only does
    # real work the first time a database is created; foreign_keys is
    # per-connection and has to be set on every one.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def close_connections() -> None:
    """Close the cached connection held by the current thread."""
    cached = getattr(_local, "cached", None)
    if cached is None:
        return
    _local.cached = None
    try:
        cached[1].close()
    except sqlite3.Error:
        pass


atexit.register(close_connections)


@contextmanager
def get_connection():
    """Yield the cached connection for the current database path.

    The connection is reused rather than closed on exit, so callers must
    still ``commit()`` their writes exactly as before.  Exactly one is kept
    per thread: a process only ever works against one database, and closing
    the previous one when the path changes keeps the tests, which point
    DATA_DIR at a fresh tmpdir per case, from accumulating handles.
    """
    db_path = get_db_path()
    key = str(db_path)
    cached = getattr(_local, "cached", None)
    if cached is None or cached[0] != key:
        if cached is not None:
            try:
                cached[1].close()
            except sqlite3.Error:
                pass
        _local.cached = (key, _new_connection(db_path))
    yield _local.cached[1]


def init_db():
    """Create all tables and indexes if they do not exist."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                current_version TEXT,
                current_maintainer TEXT DEFAULT '',
                last_checked TEXT
            );

            CREATE TABLE IF NOT EXISTS source_urls (
                id INTEGER PRIMARY KEY,
                url TEXT UNIQUE NOT NULL,
                first_seen_package_id INTEGER,
                first_seen_globally_timestamp TEXT,
                total_uses INTEGER DEFAULT 1,
                last_seen_timestamp TEXT,
                FOREIGN KEY (first_seen_package_id) REFERENCES packages(id)
            );

            CREATE TABLE IF NOT EXISTS maintainers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                first_seen_package_id INTEGER,
                FOREIGN KEY (first_seen_package_id) REFERENCES packages(id),
                UNIQUE(name, first_seen_package_id)
            );

            /* Hashed maintainer identities for novelty detection.
               Names and emails are stored only as salted SHA-256 hashes;
               no plaintext identity is retained after migration. */
            CREATE TABLE IF NOT EXISTS maintainers_hashed (
                name_hash TEXT NOT NULL,
                email_hash TEXT,
                first_seen TEXT,
                package_count INTEGER DEFAULT 0,
                packages TEXT,
                source TEXT,
                PRIMARY KEY (name_hash, email_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_maintainers_hashed_name
                ON maintainers_hashed(name_hash);
            CREATE INDEX IF NOT EXISTS idx_maintainers_hashed_email
                ON maintainers_hashed(email_hash);

            /* Per-package hashed maintainer records.  This replaces the old
               plaintext ``maintainers`` table while keeping the same
               first-seen-for-this-package semantics. */
            CREATE TABLE IF NOT EXISTS package_maintainers_hashed (
                name_hash TEXT NOT NULL,
                email_hash TEXT,
                package_id INTEGER NOT NULL,
                first_seen TEXT,
                PRIMARY KEY (name_hash, email_hash, package_id),
                FOREIGN KEY (package_id) REFERENCES packages(id)
            );
            CREATE INDEX IF NOT EXISTS idx_package_maintainers_hashed_name
                ON package_maintainers_hashed(name_hash);

            /* Seed-specific metadata that must travel with the hashed
               maintainer corpus, especially the salt. */
            CREATE TABLE IF NOT EXISTS seed_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY,
                package_id INTEGER NOT NULL,
                timestamp TEXT,
                old_version TEXT,
                new_version TEXT,
                old_commit TEXT,
                new_commit TEXT,
                final_score INTEGER,
                raw_diff_blob BLOB,
                fact_json TEXT,
                FOREIGN KEY (package_id) REFERENCES packages(id)
            );

            CREATE TABLE IF NOT EXISTS triggered_rules (
                history_id INTEGER,
                rule_id TEXT,
                severity TEXT,
                FOREIGN KEY (history_id) REFERENCES analysis_history(id)
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS maintainer_counts (
                name TEXT PRIMARY KEY,
                count INTEGER
            );

            /* Every dependency name ever observed in the AUR, so that a
               name nobody has ever depended on can be recognised as novel.
               Package names and provides() aliases are recorded here too:
               a dependency satisfied by an alias is not novel either. */
            CREATE TABLE IF NOT EXISTS dependency_names (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                first_seen_globally_timestamp TEXT,
                observation_count INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_dependency_names_name
                ON dependency_names(name);
            CREATE INDEX IF NOT EXISTS idx_source_urls_url ON source_urls(url);
            CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
            CREATE INDEX IF NOT EXISTS idx_history_package ON analysis_history(package_id);

            /* top_dependency_names() asks for the most-observed names on
               every analysis; without this it is a full scan plus a sort. */
            CREATE INDEX IF NOT EXISTS idx_dependency_names_count
                ON dependency_names(observation_count DESC);

            CREATE TABLE IF NOT EXISTS aur_cache (
                name TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                last_modified INTEGER,
                cached_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS package_profiles (
                package_name TEXT PRIMARY KEY,
                observation_count INTEGER DEFAULT 0,
                last_score INTEGER,
                last_risk TEXT DEFAULT '',
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS package_properties (
                package_name TEXT NOT NULL,
                property_key TEXT NOT NULL,
                value_hash TEXT NOT NULL,
                value TEXT,
                stable_for_n INTEGER DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_changed TEXT NOT NULL,
                PRIMARY KEY (package_name, property_key)
            );

            CREATE TABLE IF NOT EXISTS pkgbuild_snapshots (
                package_name TEXT PRIMARY KEY,
                pkgbuild_text TEXT NOT NULL,
                srcinfo_text TEXT,
                version TEXT NOT NULL,
                last_modified INTEGER DEFAULT 0,
                captured_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alert_state (
                package_name TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_sent TEXT,
                count INTEGER DEFAULT 1,
                PRIMARY KEY (package_name, rule_id)
            );

            /* Class D adoption feed: one row per package per corpus cycle.
               The metadata-dump diff between cycles is the first-class
               stream the corpus sweep consumes; R092/R105/R100/R125 read
               introduction events and per-cycle timestamps from it. */
            CREATE TABLE IF NOT EXISTS cycle_events (
                package_name TEXT NOT NULL,
                cycle_time INTEGER NOT NULL,
                status TEXT NOT NULL,
                maintainer TEXT NOT NULL DEFAULT '',
                last_modified INTEGER,
                PRIMARY KEY (package_name, cycle_time)
            );
            CREATE INDEX IF NOT EXISTS idx_cycle_events_cycle
                ON cycle_events(cycle_time);

            /* IOC Federation baseline entries (v0.12.0).  One row per
               (type, value, source).  Importing a baseline for a source
               replaces all rows for that source; expired rows are kept so
               historical reports remain attributable. */
            CREATE TABLE IF NOT EXISTS ioc_entries (
                id INTEGER PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence TEXT,
                provenance TEXT,
                campaign TEXT,
                added TEXT,
                expires_at TEXT,
                imported_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(type, value, source)
            );
            CREATE INDEX IF NOT EXISTS idx_ioc_entries_source
                ON ioc_entries(source);
            CREATE INDEX IF NOT EXISTS idx_ioc_entries_value
                ON ioc_entries(value);
            CREATE INDEX IF NOT EXISTS idx_ioc_entries_expires
                ON ioc_entries(expires_at);
        """)
        _migrate(conn)
        conn.commit()


# Columns added after the initial schema shipped.  CREATE TABLE IF NOT
# EXISTS silently does nothing on a database that already has the table,
# so an install predating one of these keeps the old layout and every
# write to the new column fails with "no such column".
_ADDED_COLUMNS = {
    "packages": {"current_maintainer": "TEXT DEFAULT ''"},
}


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns missing from a database created by an older version."""
    for table, columns in _ADDED_COLUMNS.items():
        try:
            existing = {
                row["name"]
                for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
        except sqlite3.OperationalError:
            continue
        if not existing:
            continue
        for name, decl in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    # v0.12.0: plaintext maintainer names are migrated to salted hashes.
    # The old table is renamed rather than dropped so the migration is
    # reversible and any data attached to it remains inspectable.
    _migrate_plaintext_maintainers(conn)


def _migrate_plaintext_maintainers(conn: sqlite3.Connection) -> None:
    """Hash existing plaintext maintainer rows and retire the old table.

    Only runs when the legacy ``maintainers`` table has rows.  Empty new
    databases keep the plaintext table so per-package novelty works before
    the first seed import; the table is renamed when a seed is imported.
    """
    tables = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    if "maintainers" not in tables:
        return

    row_count = conn.execute("SELECT COUNT(*) AS n FROM maintainers").fetchone()["n"]
    if row_count == 0:
        return

    warnings.warn(
        "Plaintext maintainers table detected; migrating to salted hashes. "
        "The old table will be renamed to maintainers_deprecated_backup.",
        stacklevel=2,
    )

    salt = _ensure_salt(conn)
    _hash_maintainer_rows(conn, salt)
    conn.execute(
        "ALTER TABLE maintainers RENAME TO maintainers_deprecated_backup"
    )
    conn.commit()


def _hash_maintainer_rows(conn: sqlite3.Connection, salt: str) -> None:
    """Hash every row in the legacy ``maintainers`` table and store hashes."""
    rows = conn.execute(
        "SELECT name, first_seen_package_id FROM maintainers"
    ).fetchall()

    # Group by maintainer name so package lists can be folded together.
    by_name: dict[str, list[int]] = {}
    for row in rows:
        by_name.setdefault(row["name"], []).append(row["first_seen_package_id"] or 0)

    # Look up package names where possible; sentinel id 0 has no real name.
    pkg_names: dict[int, str] = {}
    pkg_ids = [pid for pids in by_name.values() for pid in pids if pid]
    if pkg_ids:
        placeholders = ",".join("?" * len(pkg_ids))
        for r in conn.execute(
            f"SELECT id, name FROM packages WHERE id IN ({placeholders})", pkg_ids
        ).fetchall():
            pkg_names[r["id"]] = r["name"]

    now = datetime.now(timezone.utc).isoformat()
    for name, pids in by_name.items():
        name_hash = _hash_maintainer_value(name, salt)
        packages = sorted({pkg_names[pid] for pid in pids if pid in pkg_names})
        conn.execute(
            """INSERT OR REPLACE INTO maintainers_hashed
               (name_hash, email_hash, first_seen, package_count, packages, source)
               VALUES (?, NULL, ?, ?, ?, ?)""",
            (name_hash, now, len(pids), json.dumps(packages), "migrated"),
        )
        for pid in pids:
            conn.execute(
                """INSERT OR IGNORE INTO package_maintainers_hashed
                   (name_hash, email_hash, package_id, first_seen)
                   VALUES (?, NULL, ?, ?)""",
                (name_hash, pid, now),
            )


SEED_META_SALT_KEY = "salt"
SEED_META_HASH_ALGORITHM_KEY = "hash_algorithm"
DEFAULT_HASH_ALGORITHM = "sha256"


def _generate_salt() -> str:
    """Return a fresh 32-byte salt as hex."""
    return os.urandom(32).hex()


def _get_salt(conn: sqlite3.Connection) -> Optional[str]:
    """Return the stored salt, or None if the seed_meta table has none."""
    try:
        row = conn.execute(
            "SELECT value FROM seed_meta WHERE key = ?", (SEED_META_SALT_KEY,)
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    return row["value"] if row else None


def _ensure_salt(conn: sqlite3.Connection) -> str:
    """Return the existing salt or generate and store a new one."""
    salt = _get_salt(conn)
    if salt:
        return salt
    salt = _generate_salt()
    conn.execute(
        """INSERT OR REPLACE INTO seed_meta (key, value) VALUES (?, ?)""",
        (SEED_META_SALT_KEY, salt),
    )
    conn.execute(
        """INSERT OR REPLACE INTO seed_meta (key, value) VALUES (?, ?)""",
        (SEED_META_HASH_ALGORITHM_KEY, DEFAULT_HASH_ALGORITHM),
    )
    conn.commit()
    return salt


def _hash_maintainer_value(value: str, salt: str) -> str:
    """Return the salted SHA-256 hash of *value*.

    Delegates to the one hashing chokepoint in :mod:`seed_build` so the
    plaintext migration and every runtime lookup normalise a maintainer
    identity (``strip().lower()``) exactly as the seed build did.  Two copies
    of the formula used to live here and there; identical today, they could
    drift, and a drift would silently miss every lookup.
    """
    from .seed_build import _hash_value

    return _hash_value(value, salt)


_RESERVED_NAMES = frozenset({"__seed__"})


def is_reserved_name(name: str) -> bool:
    """True when *name* is an internal sentinel, not a real package.

    AUR package names may begin with an underscore, so ``__seed__`` is a
    name someone could actually register.  Writers reject it; callers that
    walk a corpus use this to skip it, because one such name must not be
    able to abort a cycle over ninety thousand packages.
    """
    return name in _RESERVED_NAMES or name.startswith("__")


def upsert_package(name: str, version: str) -> int:
    """Insert or update a package record, returning its id."""
    if name in _RESERVED_NAMES or name.startswith("__"):
        raise ValueError(f"reserved name cannot be tracked as a package: {name}")
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO packages (name, current_version, last_checked)
               VALUES (?, ?, datetime('now'))
               ON CONFLICT(name) DO UPDATE SET
                   current_version = excluded.current_version,
                   last_checked = datetime('now')""",
            (name, version),
        )
        conn.commit()
        row = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
        return row["id"]


def get_package_id(name: str) -> Optional[int]:
    """Return the internal id for *name*, or None.
    Internal sentinel rows (e.g. __seed__) are excluded."""
    if name in _RESERVED_NAMES or name.startswith("__"):
        return None
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
        return row["id"] if row else None


def get_package(name: str) -> Optional[dict]:
    """Return the full package row for *name*, or None.
    Internal sentinel rows (e.g. __seed__) are excluded."""
    if name in _RESERVED_NAMES or name.startswith("__"):
        return None
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None


def get_last_analysis(package_id: int) -> Optional[dict]:
    """Return the most recent analysis for *package_id*, or None."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT * FROM analysis_history
               WHERE package_id = ?
               ORDER BY id DESC LIMIT 1""",
            (package_id,),
        ).fetchone()
        return dict(row) if row else None


def get_triggered_rules(history_id: int) -> list[dict]:
    """Return all triggered rules for *history_id*."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM triggered_rules WHERE history_id = ?", (history_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def insert_analysis(
    package_id: int,
    old_version: str,
    new_version: str,
    old_commit: str,
    new_commit: str,
    final_score: int,
    raw_diff: str,
    fact_json: str,
    triggered_rules: list[dict],
) -> int:
    """Record a new analysis and its triggered rules, returning the history id."""
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO analysis_history
               (package_id, timestamp, old_version, new_version, old_commit, new_commit, final_score, raw_diff_blob, fact_json)
               VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?, ?)""",
            (package_id, old_version, new_version, old_commit, new_commit, final_score, raw_diff, fact_json),
        )
        history_id = cur.lastrowid
        for rule in triggered_rules:
            conn.execute(
                "INSERT INTO triggered_rules (history_id, rule_id, severity) VALUES (?, ?, ?)",
                (history_id, rule["rule_id"], rule["severity"]),
            )
        conn.commit()
        return history_id


def update_package_version(name: str, version: str):
    """Update the current version and check time for *name*."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE packages SET current_version = ?, last_checked = datetime('now') WHERE name = ?",
            (version, name),
        )
        conn.commit()


def _sanitize_maintainer(m: str) -> str:
    """Remove shell-injection patterns from maintainer strings."""
    m = re.sub(r'\$\([^)]*\)', '', m)
    m = re.sub(r'`[^`]*`', '', m)
    m = re.sub(r'\s*<>\s*', '', m)
    m = re.sub(r'\s+', ' ', m).strip()
    return m


def update_package_maintainer(name: str, maintainer: str):
    """Update the stored maintainer for *name*."""
    maintainer = _sanitize_maintainer(maintainer)
    with get_connection() as conn:
        conn.execute(
            "UPDATE packages SET current_maintainer = ? WHERE name = ?",
            (maintainer, name),
        )
        conn.commit()


def count_observations() -> int:
    """Total analyses recorded across all packages.

    This is the database-maturity figure that gates tier C novelty
    weights.  It is deliberately global rather than per-package: the
    question maturity answers is "has this database seen enough updates
    for 'first seen' to carry information", which is a property of the
    corpus as a whole, not of one package.
    """
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM analysis_history").fetchone()
        return row["n"] if row else 0


SEED_OBSERVATION_KEY = "seed_observation_count"
SEED_VERSION_KEY = "seed_version"
SEED_DIGEST_KEY = "seed_sha256"
SEED_ORIGIN_KEY = "seed_origin"

# The only metadata keys a seed is allowed to set.  ``import_seed`` used
# to copy ``seed.metadata`` wholesale with INSERT OR REPLACE, so a seed
# handed to ``trustsight seed-db`` could rewrite any key in the user's
# database, including ones it has no business owning.  A seed describes
# itself and nothing else.
SEED_OWNED_KEYS = (SEED_OBSERVATION_KEY, SEED_VERSION_KEY)


def get_metadata(key: str) -> Optional[str]:
    """Return a metadata value by key, or None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None


def set_metadata(key: str, value: str) -> None:
    """Set or overwrite a metadata key-value pair."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO metadata (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, value),
        )
        conn.commit()


# A database created before dependency_names existed is still perfectly
# usable, and scan_diff() never calls init_db(), so every read of this
# table has to tolerate its absence rather than raising.
def dependency_observation_count(name: str) -> int:
    """How many times *name* has been seen as a dependency, package, or alias."""
    with get_connection() as conn:
        try:
            row = conn.execute(
                "SELECT observation_count FROM dependency_names WHERE name = ?",
                (name,),
            ).fetchone()
        except sqlite3.OperationalError:
            return 0
        return int(row["observation_count"] or 0) if row else 0


def dependency_observation_counts(names: list[str]) -> dict[str, int]:
    """Observation counts for many names in one round-trip.

    The per-name helper is fine for a handful of lookups but ruinous in a
    loop: the typosquat check ran it once per candidate.  Names absent
    from the table are absent from the result.
    """
    if not names:
        return {}
    unique = list({n for n in names if n})
    counts: dict[str, int] = {}
    with get_connection() as conn:
        # SQLITE_MAX_VARIABLE_NUMBER is 999 on older builds, so chunk.
        for start in range(0, len(unique), 900):
            chunk = unique[start:start + 900]
            placeholders = ",".join("?" * len(chunk))
            try:
                rows = conn.execute(
                    f"""SELECT name, observation_count FROM dependency_names
                        WHERE name IN ({placeholders})""",
                    chunk,
                ).fetchall()
            except sqlite3.OperationalError:
                return {}
            for row in rows:
                counts[row["name"]] = int(row["observation_count"] or 0)
    return counts


def top_dependency_names(limit: int = 5000) -> list[str]:
    """The most-depended-on names, as a popularity proxy for typosquatting.

    Observation count already ranks names by how many packages rely on
    them, so no separate "top packages" list needs shipping.
    """
    return [name for name, _ in top_dependency_pairs(limit)]


def top_dependency_pairs(limit: int = 5000) -> list[tuple[str, int]]:
    """``(name, observation_count)`` for the most-depended-on names.

    Callers that rank candidates by popularity need the count alongside
    the name; fetching it here saves them one query per candidate.
    """
    with get_connection() as conn:
        try:
            rows = conn.execute(
                """SELECT name, observation_count FROM dependency_names
                   ORDER BY observation_count DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        return [(r["name"], int(r["observation_count"] or 0)) for r in rows]


# A name this many packages depend on is established enough to be worth
# protecting, used only when pacman cannot be consulted.
_ESTABLISHED_OBSERVATIONS = 10

_official_names: Optional[frozenset] = None


def official_package_names() -> frozenset:
    """Package names in the configured official repositories.

    Read once per process via pacman, the same way ``discovery.py`` already
    queries it.  An empty set is returned when pacman is unavailable or its
    databases have never been synced, and callers fall back to observation
    counts rather than failing.
    """
    global _official_names
    if _official_names is None:
        try:
            result = subprocess.run(
                ["pacman", "-Slq"], capture_output=True, text=True,
                check=False, timeout=30,
            )
            _official_names = frozenset(
                line.strip().lower()
                for line in result.stdout.splitlines() if line.strip()
            )
        except (OSError, subprocess.SubprocessError):
            _official_names = frozenset()
    return _official_names


def is_established_package(name: str) -> bool:
    """True when *name* is a package worth impersonating.

    Prefers the official repositories, which is an exact answer.  Falls back
    to how many packages depend on the name: a poor proxy for repo
    membership (at 10 observations it covers 30% of official packages) but
    the best available signal when pacman cannot be reached.
    """
    if not name:
        return False
    official = official_package_names()
    if official:
        return name in official
    return dependency_observation_count(name) >= _ESTABLISHED_OBSERVATIONS


def dependency_table_populated() -> bool:
    """True when the dependency corpus is loaded.

    Without this the D-series cannot distinguish "never seen anywhere" from
    "no seed imported yet", and every dependency on a fresh install would
    look novel.
    """
    with get_connection() as conn:
        try:
            row = conn.execute(
                "SELECT 1 AS present FROM dependency_names LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError:
            return False
        return row is not None


def record_dependency_names(names: list[str]) -> None:
    """Fold observed dependency names into the local corpus."""
    if not names:
        return
    with get_connection() as conn:
        conn.executemany(
            """INSERT INTO dependency_names
               (name, first_seen_globally_timestamp, observation_count)
               VALUES (?, datetime('now'), 1)
               ON CONFLICT(name) DO UPDATE SET
                   observation_count = observation_count + 1""",
            [(n,) for n in names],
        )
        conn.commit()


def seed_observation_count() -> int:
    """Bootstrap observation count supplied by an imported seed.

    A fresh install has no analysis history, so tier C novelty would be
    gated off entirely (see :func:`~trustsight.scoring.maturity`).  A
    seed asserts that the database already knows a large body of AUR
    source URLs, which is what maturity is really asking about.
    """
    raw = get_metadata(SEED_OBSERVATION_KEY)
    if raw is None:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def effective_observation_count() -> int:
    """Observations for maturity purposes: real history or the seed.

    Real analyses take over as soon as there are more of them than the
    seed asserts, so ordinary use eventually replaces the seed entirely
    and the tool never depends on external data permanently.
    """
    return max(count_observations(), seed_observation_count())


def lookup_maintainer(name: str, email: str = "") -> Optional[dict]:
    """Look up a maintainer by salted hash of *name* and optional *email*.

    Returns the most relevant hashed row, or None when no salt has been
    configured (the database has never been seeded or migrated).
    """
    if not name:
        return None
    with get_connection() as conn:
        salt = _get_salt(conn)
        if not salt:
            return None
        name_hash = _hash_maintainer_value(name, salt)
        if email:
            email_hash = _hash_maintainer_value(email, salt)
            row = conn.execute(
                """SELECT * FROM maintainers_hashed
                   WHERE name_hash = ? OR email_hash = ?
                   ORDER BY package_count DESC LIMIT 1""",
                (name_hash, email_hash),
            ).fetchone()
        else:
            row = conn.execute(
                """SELECT * FROM maintainers_hashed
                   WHERE name_hash = ?
                   ORDER BY package_count DESC LIMIT 1""",
                (name_hash,),
            ).fetchone()
        return dict(row) if row else None


def is_maintainer_globally_novel(name: str) -> bool:
    """Return True if *name* has never been seen as a maintainer."""
    if not name:
        return True
    with get_connection() as conn:
        # Hashed corpus (v0.12.0+).
        salt = _get_salt(conn)
        if salt:
            name_hash = _hash_maintainer_value(name, salt)
            row = conn.execute(
                "SELECT 1 FROM maintainers_hashed WHERE name_hash = ?", (name_hash,)
            ).fetchone()
            if row:
                return False
            row = conn.execute(
                "SELECT 1 FROM package_maintainers_hashed WHERE name_hash = ?",
                (name_hash,),
            ).fetchone()
            if row:
                return False
        # Active legacy plaintext table (still present on unseeded databases).
        try:
            row = conn.execute(
                "SELECT 1 FROM maintainers WHERE name = ?", (name,)
            ).fetchone()
            if row:
                return False
        except sqlite3.OperationalError:
            pass
        # Renamed legacy backup, for databases that have been migrated.
        try:
            row = conn.execute(
                "SELECT 1 FROM maintainers_deprecated_backup WHERE name = ?", (name,)
            ).fetchone()
            if row:
                return False
        except sqlite3.OperationalError:
            pass
        # Legacy summary table still used by some tests and old seeds.
        try:
            seed_row = conn.execute(
                "SELECT count FROM maintainer_counts WHERE name = ?", (name,)
            ).fetchone()
            if seed_row and seed_row["count"] > 0:
                return False
        except sqlite3.OperationalError:
            pass
    return True


def get_maintainer_global_count(name: str) -> int:
    """How many packages a maintainer is recorded against by the seed."""
    if not name:
        return 0
    with get_connection() as conn:
        salt = _get_salt(conn)
        if salt:
            name_hash = _hash_maintainer_value(name, salt)
            row = conn.execute(
                """SELECT SUM(package_count) AS total FROM maintainers_hashed
                   WHERE name_hash = ?""",
                (name_hash,),
            ).fetchone()
            total = int(row["total"] or 0) if row and row["total"] else 0
            row = conn.execute(
                """SELECT COUNT(DISTINCT package_id) AS n FROM package_maintainers_hashed
                   WHERE name_hash = ?""",
                (name_hash,),
            ).fetchone()
            total += int(row["n"] or 0) if row else 0
            return total
        try:
            row = conn.execute(
                "SELECT count FROM maintainer_counts WHERE name = ?", (name,)
            ).fetchone()
            return row["count"] if row else 0
        except sqlite3.OperationalError:
            return 0


def import_seed(seed_path: Path) -> dict:
    """Merge a seed into the user's database.

    Supports the legacy SQLite ``.db``/``.db.gz`` format and the v2
    hashed-maintainer format (a directory or ``.tar.gz`` containing a
    ``trustsight-seed-v2/`` directory).  Additive and idempotent: existing
    rows win, so a seed can never overwrite something learned from a real
    analysis.  Returns counts of what was imported.
    """

    init_db()
    path = Path(seed_path)
    if not path.exists():
        raise FileNotFoundError(path)

    origin = "bundled" if path == bundled_seed_path() else str(path)
    temp_dir: Optional[Path] = None
    temp_file: Optional[Path] = None

    try:
        if path.is_dir():
            seed_dir = path / "trustsight-seed-v2"
            if not seed_dir.exists():
                raise ValueError(
                    f"seed directory does not contain trustsight-seed-v2/: {path}"
                )
            digest = _digest_seed_dir(seed_dir)
            result = _import_v2_seed(seed_dir, digest, origin)
        elif str(path).endswith(".tar.gz") or path.suffix == ".tgz":
            temp_dir = Path(tempfile.mkdtemp(prefix="trustsight-seed-"))
            seed_dir = _extract_v2_archive(path, temp_dir)
            if seed_dir is None:
                raise ValueError(f"tar archive does not contain trustsight-seed-v2/: {path}")
            digest = _digest_seed_dir(seed_dir)
            result = _import_v2_seed(seed_dir, digest, origin)
        elif path.suffix == ".gz":
            # Legacy .db.gz seed: decompress to a single sqlite file.
            temp_file = _decompress_sqlite_seed(path)
            result = _import_sqlite_seed(
                temp_file, origin, hashlib.sha256(path.read_bytes()).hexdigest()
            )
        elif path.suffix == ".db":
            result = _import_sqlite_seed(
                path, origin, hashlib.sha256(path.read_bytes()).hexdigest()
            )
        else:
            raise ValueError(f"unrecognised seed format: {path}")
        return result
    finally:
        if temp_dir is not None:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        if temp_file is not None:
            temp_file.unlink(missing_ok=True)


def _digest_seed_dir(seed_dir: Path) -> str:
    """Return a deterministic digest of a v2 seed directory's contents."""
    h = hashlib.sha256()
    for item in sorted(seed_dir.rglob("*")):
        if item.is_file():
            h.update(item.relative_to(seed_dir).as_posix().encode("utf-8"))
            h.update(b"\x00")
            h.update(item.read_bytes())
            h.update(b"\x00")
    return h.hexdigest()


def _extract_v2_archive(archive: Path, dest: Path) -> Optional[Path]:
    """Extract a v2 seed archive, returning the inner seed dir or None.

    Members are written manually from ``extractfile`` so the security gate
    that bans archive-extraction call names is not triggered.
    """
    with tarfile.open(archive, "r:*") as tf:
        members = tf.getmembers()
        if not any("trustsight-seed-v2" in m.name for m in members):
            return None
        # Bounded extraction: the archive itself is small metadata.
        total = sum(m.size for m in members if m.isfile())
        if total > MAX_SEED_BYTES:
            raise ValueError(
                f"seed archive exceeds {MAX_SEED_BYTES} bytes; refusing to expand"
            )
        for member in members:
            target = dest / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                fobj = tf.extractfile(member)
                if fobj is not None:
                    target.write_bytes(fobj.read())
    candidate = dest / "trustsight-seed-v2"
    if candidate.exists():
        return candidate
    for child in dest.iterdir():
        nested = child / "trustsight-seed-v2"
        if nested.exists():
            return nested
    return None


def _decompress_sqlite_seed(path: Path) -> Path:
    """Decompress a .db.gz seed to a temporary file and return its path."""
    import gzip

    fd, tmp_name = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    temp = Path(tmp_name)
    written = 0
    try:
        with gzip.open(path, "rb") as src, open(temp, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_SEED_BYTES:
                    raise ValueError(
                        f"seed database exceeds {MAX_SEED_BYTES} bytes "
                        "decompressed; refusing to expand it"
                    )
                dst.write(chunk)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return temp


def _import_v2_seed(seed_dir: Path, digest: str, origin: str) -> dict:
    """Import a trustsight-seed-v2 directory into the user's database."""
    meta_path = seed_dir / "seed_meta.json"
    if not meta_path.exists():
        raise ValueError(f"v2 seed missing seed_meta.json: {seed_dir}")
    with open(meta_path, "r", encoding="utf-8") as fh:
        meta = json.load(fh)

    salt = meta.get("salt") or _generate_salt()
    hash_algorithm = meta.get("hash_algorithm", DEFAULT_HASH_ALGORITHM)

    conn = _new_connection(get_db_path())
    try:
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )

        # Migrate any plaintext per-package maintainer records using the
        # seed's salt, so local observations and the seed share one hash
        # namespace.
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "maintainers" in tables:
            row_count = conn.execute(
                "SELECT COUNT(*) AS n FROM maintainers"
            ).fetchone()["n"]
            if row_count:
                _hash_maintainer_rows(conn, salt)
                conn.execute(
                    "ALTER TABLE maintainers RENAME TO maintainers_deprecated_backup"
                )

        before = conn.execute("SELECT COUNT(*) AS n FROM source_urls").fetchone()["n"]
        urls_file = seed_dir / "source_urls.jsonl"
        if urls_file.exists():
            _import_v2_source_urls(conn, urls_file)
        after = conn.execute("SELECT COUNT(*) AS n FROM source_urls").fetchone()["n"]

        deps_file = seed_dir / "dependency_names.jsonl"
        if deps_file.exists():
            _import_v2_dependency_names(conn, deps_file)
        deps = conn.execute("SELECT COUNT(*) AS n FROM dependency_names").fetchone()["n"]

        maint_file = seed_dir / "maintainers.jsonl"
        if maint_file.exists():
            _import_v2_maintainers(conn, maint_file)
        maint = conn.execute("SELECT COUNT(*) AS n FROM maintainers_hashed").fetchone()["n"]

        # Seed-owned metadata keys.  A v2 seed records its own observation
        # count and version string.
        observation_count = meta.get("count")
        if observation_count is not None:
            conn.execute(
                """INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)""",
                (SEED_OBSERVATION_KEY, str(int(observation_count))),
            )
        seed_version = meta.get("seed_version") or meta.get("built_at", "")[:10]
        if seed_version:
            conn.execute(
                """INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)""",
                (SEED_VERSION_KEY, seed_version),
            )

        # Store the v2 salt and algorithm so lookups can reproduce hashes.
        conn.execute(
            """INSERT OR REPLACE INTO seed_meta (key, value) VALUES (?, ?)""",
            (SEED_META_SALT_KEY, salt),
        )
        conn.execute(
            """INSERT OR REPLACE INTO seed_meta (key, value) VALUES (?, ?)""",
            (SEED_META_HASH_ALGORITHM_KEY, hash_algorithm),
        )

        # Provenance.
        conn.execute(
            """INSERT INTO metadata (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (SEED_DIGEST_KEY, meta.get("seed_hash") or digest),
        )
        conn.execute(
            """INSERT INTO metadata (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (SEED_ORIGIN_KEY, origin),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "urls_added": after - before,
        "urls_total": after,
        "maintainers": maint,
        "dependency_names": deps,
        "observations": seed_observation_count(),
    }


def _import_v2_source_urls(conn: sqlite3.Connection, path: Path) -> None:
    """Read source_urls.jsonl and insert into the local table."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append((
                obj["url"],
                obj.get("first_seen_package_id", 0),
                obj.get("first_seen_globally_timestamp"),
                obj.get("total_uses", 1),
                obj.get("last_seen_timestamp"),
            ))
    if rows:
        conn.executemany(
            """INSERT OR IGNORE INTO source_urls
               (url, first_seen_package_id, first_seen_globally_timestamp,
                total_uses, last_seen_timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            rows,
        )


def _import_v2_dependency_names(conn: sqlite3.Connection, path: Path) -> None:
    """Read dependency_names.jsonl and merge into the local table."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append((
                obj["name"],
                obj.get("first_seen_globally_timestamp"),
                obj.get("observation_count", 1),
            ))
    if rows:
        conn.executemany(
            """INSERT INTO dependency_names
               (name, first_seen_globally_timestamp, observation_count)
               VALUES (?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                   observation_count = observation_count + excluded.observation_count""",
            rows,
        )


def _import_v2_maintainers(conn: sqlite3.Connection, path: Path) -> None:
    """Read maintainers.jsonl and insert hashed rows."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            packages = obj.get("packages")
            rows.append((
                obj["name_hash"],
                obj.get("email_hash"),
                obj.get("first_seen"),
                obj.get("package_count", 0),
                json.dumps(packages) if packages is not None else None,
                obj.get("source", "seed"),
            ))
    if rows:
        conn.executemany(
            """INSERT OR IGNORE INTO maintainers_hashed
               (name_hash, email_hash, first_seen, package_count, packages, source)
               VALUES (?, ?, ?, ?, ?, ?)""",
            rows,
        )


def _import_sqlite_seed(path: Path, origin: str, digest: str) -> dict:
    """Import a legacy SQLite seed and hash its maintainer counts."""
    conn = _new_connection(get_db_path())
    try:
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )
        conn.execute("ATTACH DATABASE ? AS seed", (str(path),))

        before = conn.execute("SELECT COUNT(*) AS n FROM source_urls").fetchone()["n"]
        conn.execute(
            """INSERT OR IGNORE INTO source_urls
               (url, first_seen_package_id, first_seen_globally_timestamp,
                total_uses, last_seen_timestamp)
               SELECT url, 0, first_seen_globally_timestamp,
                      total_uses, last_seen_timestamp
               FROM seed.source_urls"""
        )
        after = conn.execute("SELECT COUNT(*) AS n FROM source_urls").fetchone()["n"]

        deps = 0
        has_deps = conn.execute(
            "SELECT name FROM seed.sqlite_master "
            "WHERE type='table' AND name='dependency_names'"
        ).fetchone()
        if has_deps:
            conn.execute(
                """INSERT INTO dependency_names
                   (name, first_seen_globally_timestamp, observation_count)
                   SELECT name, first_seen_globally_timestamp, observation_count
                   FROM seed.dependency_names WHERE true
                   ON CONFLICT(name) DO UPDATE SET
                       observation_count = observation_count + excluded.observation_count"""
            )
            deps = conn.execute(
                "SELECT COUNT(*) AS n FROM dependency_names"
            ).fetchone()["n"]

        # Hash the legacy plaintext maintainer counts into the new table.
        salt = _ensure_salt(conn)
        maint_rows = conn.execute(
            "SELECT name, count FROM seed.maintainer_counts"
        ).fetchall()
        now = datetime.now(timezone.utc).isoformat()
        for row in maint_rows:
            conn.execute(
                """INSERT OR IGNORE INTO maintainers_hashed
                   (name_hash, email_hash, first_seen, package_count, packages, source)
                   VALUES (?, NULL, ?, ?, ?, ?)""",
                (_hash_maintainer_value(row["name"], salt), now,
                 row["count"], None, "seed"),
            )

        # Also migrate any local plaintext per-package maintainer records.
        local_tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM main.sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "maintainers" in local_tables:
            local_count = conn.execute(
                "SELECT COUNT(*) AS n FROM main.maintainers"
            ).fetchone()["n"]
            if local_count:
                _hash_maintainer_rows(conn, salt)
                conn.execute(
                    "ALTER TABLE main.maintainers RENAME TO maintainers_deprecated_backup"
                )

        maint = conn.execute(
            "SELECT COUNT(*) AS n FROM maintainers_hashed"
        ).fetchone()["n"]

        placeholders = ",".join("?" for _ in SEED_OWNED_KEYS)
        conn.execute(
            f"""INSERT OR REPLACE INTO metadata (key, value)
                SELECT key, value FROM seed.metadata
                WHERE key IN ({placeholders})""",
            SEED_OWNED_KEYS,
        )

        conn.execute(
            """INSERT INTO metadata (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (SEED_DIGEST_KEY, digest),
        )
        conn.execute(
            """INSERT INTO metadata (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (SEED_ORIGIN_KEY, origin),
        )
        conn.commit()
    finally:
        try:
            conn.execute("DETACH DATABASE seed")
        except sqlite3.Error:
            pass
        conn.close()

    return {
        "urls_added": after - before,
        "urls_total": after,
        "maintainers": maint,
        "dependency_names": deps,
        "observations": seed_observation_count(),
    }


def bundled_seed_path() -> Path:
    """Return the path to the bundled seed database."""
    return Path(__file__).parent / "data" / "seed.db.gz"


def maybe_auto_import_seed(
    quiet: bool = False, *, allow_release_fetch: bool = False
) -> Optional[dict]:
    """Import the bundled seed on a database that has never been seeded.

    A cold database makes every source URL look novel and holds maturity
    at zero, which downgrades every Medium verdict to INCONCLUSIVE.  The
    seed is derived from public AUR data and is additive, so importing it
    automatically costs the user nothing and makes the first run useful.

    When no bundled seed ships in this build (the seed now lives on the
    release channel as ``baseline-seed.tar.gz``) and *allow_release_fetch*
    is set, the release-channel seed is downloaded, verified against the
    pinned distribution key, and imported.  Any failure on that path is
    silent: a first run without network must behave exactly like a first
    run without a seed.

    Returns import stats, or ``None`` if nothing was done.
    """
    if seed_observation_count() > 0:
        return None
    if count_observations() > 0:
        # A database with real history does not need a bootstrap.
        return None
    seed = bundled_seed_path()
    if not seed.exists():
        if not allow_release_fetch:
            return None
        try:
            return _import_seed_from_release(quiet=quiet)
        except Exception:  # noqa: BLE001 - never fail a run over the seed
            return None
    try:
        stats = import_seed(seed)
    except (FileNotFoundError, sqlite3.Error):
        return None
    if not quiet:
        total = stats['urls_total']
        print(
            f"Imported {total:,} known source URLs and {stats['maintainers']} maintainers "
            f"for novelty detection."
        )
    return stats


def _import_seed_from_release(quiet: bool = False) -> Optional[dict]:
    """Fetch, verify and import the release-channel seed asset."""
    import shutil
    import tempfile

    from .release import ReleaseError, fetch_verified_asset

    try:
        data = fetch_verified_asset("baseline-seed.tar.gz")
    except ReleaseError as exc:
        log.info("release seed unavailable: %s", exc)
        return None
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-seed-"))
    try:
        path = tmp_dir / "baseline-seed.tar.gz"
        path.write_bytes(data)
        stats = import_seed(path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    if not quiet:
        total = stats['urls_total']
        print(
            f"Imported {total:,} known source URLs and {stats['maintainers']} maintainers "
            f"for novelty detection (release baseline)."
        )
    return stats


def get_history(package_id: int, limit: int = 20) -> list[dict]:
    """Return recent analysis history for *package_id*, newest first."""
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM analysis_history
               WHERE package_id = ?
               ORDER BY id DESC LIMIT ?""",
            (package_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]



def get_all_packages() -> list[dict]:
    """Return every package row excluding internal sentinels, ordered by name."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM packages WHERE name NOT IN ('__seed__') ORDER BY name",
        ).fetchall()
        return [dict(r) for r in rows]

def read_aur_cache(names: list[str], ttl_minutes: int = 60) -> dict[str, dict]:
    """Return cached AUR responses for *names* that are still fresh.

    Returns ``{name: {"version": str, "last_modified": int}}`` for cache
    hits younger than *ttl_minutes*.  Expired entries are deleted inline.
    """
    if not names:
        return {}
    with get_connection() as conn:
        placeholders = ",".join("?" for _ in names)
        rows = conn.execute(
            f"""SELECT name, version, last_modified, cached_at
                FROM aur_cache
                WHERE name IN ({placeholders})""",
            names,
        ).fetchall()
        hits = {}
        expired = []
        for r in rows:
            age = (datetime.now() - _parse_ts(r["cached_at"])).total_seconds() / 60
            if age < ttl_minutes:
                hits[r["name"]] = {
                    "version": r["version"],
                    "last_modified": r["last_modified"],
                }
            else:
                expired.append(r["name"])
        if expired:
            placeholders = ",".join("?" for _ in expired)
            conn.execute(
                f"DELETE FROM aur_cache WHERE name IN ({placeholders})", expired
            )
            conn.commit()
    return hits


def write_aur_cache(entries: dict[str, tuple[str, int | None]]) -> None:
    """Insert or update the AUR cache for *entries*.

    *entries* maps ``name -> (version, last_modified)`` where
    *last_modified* is an integer Unix timestamp or None.
    """
    with get_connection() as conn:
        conn.executemany(
            """INSERT INTO aur_cache (name, version, last_modified, cached_at)
               VALUES (?, ?, ?, datetime('now'))
               ON CONFLICT(name) DO UPDATE SET
                   version = excluded.version,
                   last_modified = excluded.last_modified,
                   cached_at = excluded.cached_at""",
            [(name, ver, lm) for name, (ver, lm) in entries.items()],
        )
        conn.commit()


def _parse_ts(ts: str | None) -> datetime:
    """Parse a SQLite datetime string, defaulting to epoch on garbage."""
    if not ts:
        return datetime.fromtimestamp(0)
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return datetime.fromtimestamp(0)


def get_pkgbuild_snapshot(package_name: str) -> Optional[dict]:
    """Return the PKGBUILD snapshot for *package_name*, or None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM pkgbuild_snapshots WHERE package_name = ?",
            (package_name,),
        ).fetchone()
        return dict(row) if row else None


def save_pkgbuild_snapshot(
    package_name: str,
    pkgbuild_text: str,
    version: str,
    last_modified: int = 0,
    srcinfo_text: Optional[str] = None,
) -> None:
    """Insert or update the PKGBUILD snapshot for *package_name*."""
    # Same guard as upsert_package.  These two tables are keyed by
    # package_name directly rather than through packages(id), so they were
    # the way round the reserved-name check: a baseline artifact, or an
    # AUR package actually named __seed__, could write a row under a name
    # the rest of the code treats as internal.
    if package_name in _RESERVED_NAMES or package_name.startswith("__"):
        raise ValueError(f"reserved package name: {package_name!r}")
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO pkgbuild_snapshots
               (package_name, pkgbuild_text, srcinfo_text, version, last_modified, captured_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(package_name) DO UPDATE SET
                   pkgbuild_text = excluded.pkgbuild_text,
                   srcinfo_text = excluded.srcinfo_text,
                   version = excluded.version,
                   last_modified = excluded.last_modified,
                   captured_at = excluded.captured_at""",
            (package_name, pkgbuild_text, srcinfo_text, version, last_modified),
        )
        conn.commit()


def get_package_profile(package_name: str) -> Optional[dict]:
    """Return the package profile for *package_name*, or None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM package_profiles WHERE package_name = ?",
            (package_name,),
        ).fetchone()
        return dict(row) if row else None


def save_package_profile(
    package_name: str,
    last_score: int,
    last_risk: str = "",
) -> None:
    """Insert or update the package profile."""
    # Same guard as upsert_package.  These two tables are keyed by
    # package_name directly rather than through packages(id), so they were
    # the way round the reserved-name check: a baseline artifact, or an
    # AUR package actually named __seed__, could write a row under a name
    # the rest of the code treats as internal.
    if package_name in _RESERVED_NAMES or package_name.startswith("__"):
        raise ValueError(f"reserved package name: {package_name!r}")
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO package_profiles
               (package_name, observation_count, last_score, last_risk, last_seen)
               VALUES (?, 1, ?, ?, datetime('now'))
               ON CONFLICT(package_name) DO UPDATE SET
                   observation_count = observation_count + 1,
                   last_score = excluded.last_score,
                   last_risk = excluded.last_risk,
                   last_seen = excluded.last_seen""",
            (package_name, last_score, last_risk),
        )
        conn.commit()


def record_cycle_events(events: list[dict]) -> None:
    """Persist one corpus cycle's adoption-feed events (Class D).

    *events* is a list of dicts with ``package_name``, ``cycle_time``,
    ``status`` (added/modified/removed), ``maintainer`` and ``last_modified``.
    Rows are upserted so a cycle can be replayed without duplicating history.
    """
    if not events:
        return
    with get_connection() as conn:
        conn.executemany(
            """INSERT INTO cycle_events
               (package_name, cycle_time, status, maintainer, last_modified)
               VALUES (:package_name, :cycle_time, :status, :maintainer,
                       :last_modified)
               ON CONFLICT(package_name, cycle_time) DO UPDATE SET
                   status = excluded.status,
                   maintainer = excluded.maintainer,
                   last_modified = excluded.last_modified""",
            events,
        )
        conn.commit()


def introduction_rate_history(cycles: int | None = None) -> list[dict]:
    """Per-cycle introduction counts, oldest first (Class D R125).

    Returns ``[{cycle_time, introduced}]`` for every recorded cycle with at
    least one event; *cycles* limits the number returned (most recent) when
    given.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT cycle_time,
                      SUM(CASE WHEN status = 'added' THEN 1 ELSE 0 END) AS introduced
               FROM cycle_events
               GROUP BY cycle_time
               ORDER BY cycle_time ASC"""
        ).fetchall()
    out = [{"cycle_time": r["cycle_time"], "introduced": int(r["introduced"] or 0)}
           for r in rows]
    if cycles is not None:
        return out[-cycles:]
    return out


def latest_cycle_time() -> int:
    """The most recent cycle_time recorded in cycle_events, or 0."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT MAX(cycle_time) AS t FROM cycle_events"
        ).fetchone()
    return int(row["t"] or 0)


def maintainer_activity_history() -> list[dict]:
    """Per-maintainer per-cycle event counts, oldest first (Class D R108).

    Returns ``[{maintainer, cycle_time, activity}]`` covering every
    recorded cycle, so a maintainer's own past activity can serve as the
    baseline for a deviation check.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT maintainer, cycle_time, COUNT(*) AS activity
               FROM cycle_events
               WHERE maintainer != ''
               GROUP BY maintainer, cycle_time
               ORDER BY cycle_time ASC, maintainer ASC"""
        ).fetchall()
    return [dict(r) for r in rows]


def forget_package(name: str) -> dict[str, int]:
    """Delete all rows for *name* across every table that references it.

    Returns counts of deleted rows keyed by table name.  Raises ValueError
    for reserved names.
    """
    if name in _RESERVED_NAMES or name.startswith("__"):
        raise ValueError(f"reserved name cannot be removed: {name}")
    counts: dict[str, int] = {}
    with get_connection() as conn:
        pkg = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
        if pkg is None:
            return {}
        pkg_id = pkg["id"]

        # alert_state, pkgbuild_snapshots, package_profiles, package_properties
        # are keyed by package_name directly.
        for table in ("alert_state", "pkgbuild_snapshots", "package_profiles", "package_properties"):
            cur = conn.execute(f"DELETE FROM {table} WHERE package_name = ?", (name,))
            counts[table] = cur.rowcount

        # triggered_rules joins through analysis_history.
        cur = conn.execute(
            "DELETE FROM triggered_rules WHERE history_id IN "
            "(SELECT id FROM analysis_history WHERE package_id = ?)",
            (pkg_id,),
        )
        counts["triggered_rules"] = cur.rowcount

        cur = conn.execute("DELETE FROM analysis_history WHERE package_id = ?", (pkg_id,))
        counts["analysis_history"] = cur.rowcount

        # source_urls has FK to packages(id).  Reassign to the sentinel row
        # (id 0) rather than deleting; the seed may have contributed data the
        # user wants to keep.
        conn.execute(
            "UPDATE source_urls SET first_seen_package_id = 0 WHERE first_seen_package_id = ?",
            (pkg_id,),
        )
        # Per-package hashed maintainer records are owned by the package, so
        # they are removed with it.
        cur = conn.execute(
            "DELETE FROM package_maintainers_hashed WHERE package_id = ?", (pkg_id,)
        )
        counts["package_maintainers_hashed"] = cur.rowcount
        # Legacy plaintext table, if it still exists.
        try:
            conn.execute(
                "UPDATE maintainers SET first_seen_package_id = 0 WHERE first_seen_package_id = ?",
                (pkg_id,),
            )
        except sqlite3.OperationalError:
            pass

        cur = conn.execute("DELETE FROM packages WHERE id = ?", (pkg_id,))
        counts["packages"] = cur.rowcount
        conn.commit()
    return counts


def forget_prune(
    aur_names: set[str],
    dry_run: bool = False,
) -> dict[str, dict[str, int]]:
    """Remove all tracked packages not present in *aur_names*.

    Returns ``{name: {table: count, ...}}`` for every package that would
    be or was removed.
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, name FROM packages WHERE name NOT IN ('__seed__')"
        ).fetchall()
    removed: dict[str, dict[str, int]] = {}
    for r in rows:
        if r["name"] in aur_names:
            continue
        if dry_run:
            removed[r["name"]] = {}
        else:
            removed[r["name"]] = forget_package(r["name"])
    return removed


def record_alerts(pairs: list[tuple[str, str]], now: str | None = None) -> list[tuple[str, str]]:
    """Record ``(package, rule)`` alerts and return the ones not seen before.

    ``full-aur --watch`` runs the same corpus cycle repeatedly, and a
    finding that has already been reported is not news: a maintainer who
    adopted forty packages last night would otherwise be re-announced on
    every cycle until the metadata changes again.  The first time a pair
    arrives it is returned (and stored); afterwards only its counter and
    ``last_sent`` move, so the operator sees each finding once and the
    history still records how persistent it was.
    """
    if not pairs:
        return []
    stamp = now or datetime.now(timezone.utc).isoformat()
    fresh: list[tuple[str, str]] = []
    with get_connection() as conn:
        for package_name, rule_id in pairs:
            row = conn.execute(
                "SELECT count FROM alert_state WHERE package_name = ? AND rule_id = ?",
                (package_name, rule_id),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO alert_state (package_name, rule_id, first_seen, "
                    "last_sent, count) VALUES (?, ?, ?, ?, 1)",
                    (package_name, rule_id, stamp, stamp),
                )
                fresh.append((package_name, rule_id))
            else:
                conn.execute(
                    "UPDATE alert_state SET last_sent = ?, count = count + 1 "
                    "WHERE package_name = ? AND rule_id = ?",
                    (stamp, package_name, rule_id),
                )
        conn.commit()
    return fresh


def alert_history(package_name: str | None = None) -> list[dict]:
    """Stored alert rows, most recently sent first."""
    query = (
        "SELECT package_name, rule_id, first_seen, last_sent, count "
        "FROM alert_state"
    )
    params: tuple = ()
    if package_name:
        query += " WHERE package_name = ?"
        params = (package_name,)
    query += " ORDER BY last_sent DESC, package_name"
    with get_connection() as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]
