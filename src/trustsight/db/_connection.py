"""Extracted from db.py: _connection."""

from datetime import datetime, timezone
import json
import threading
import os
import sqlite3
import warnings
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
from ..rule_id_history import RENAMED_RULE_IDS

__all__ = ['DEFAULT_HASH_ALGORITHM', 'MAX_SEED_BYTES', 'MAX_SEED_MEMBERS', 'MAX_SEED_MEMBER_BYTES', 'SEED_META_HASH_ALGORITHM_KEY', 'SEED_META_SALT_KEY', '_ADDED_COLUMNS', '_SCHEMA_VERSION', '_SYNC_MODES', '_SYNC_SQL', '_ensure_salt', '_generate_salt', '_get_salt', '_hash_maintainer_rows', '_hash_maintainer_value', '_local', '_migrate', '_migrate_plaintext_maintainers', '_migrate_rule_ids', '_new_connection', '_synchronous_mode', 'close_connections', 'get_connection', 'get_db_path', 'get_read_only_connection', 'init_db']

MAX_SEED_BYTES = 2 * 1024 * 1024 * 1024

MAX_SEED_MEMBERS = 100_000

MAX_SEED_MEMBER_BYTES = 256 * 1024 * 1024

def get_db_path() -> Path:
    """Return the path to the SQLite database file.

    ``DATA_DIR`` is resolved on the ``trustsight.db`` package at call time so
    callers can redirect storage by patching ``trustsight.db.DATA_DIR``.
    """
    from . import DATA_DIR
    return DATA_DIR / "trustsight.db"

_local = threading.local()

_SYNC_MODES = frozenset({"OFF", "NORMAL", "FULL", "EXTRA"})

_SYNC_SQL = {
    "OFF": "PRAGMA synchronous=OFF",
    "NORMAL": "PRAGMA synchronous=NORMAL",
    "FULL": "PRAGMA synchronous=FULL",
    "EXTRA": "PRAGMA synchronous=EXTRA",
}

def _synchronous_mode() -> str:
    value = os.environ.get("TRUSTSIGHT_SQLITE_SYNCHRONOUS", "NORMAL").strip().upper()
    return value if value in _SYNC_MODES else "NORMAL"

_BUSY_TIMEOUT_DEFAULT_MS = 30_000

def _busy_timeout_ms() -> int:
    """Milliseconds a connection waits for a lock before raising.

    A ``seed fetch`` and a corpus cycle are both large writers; with the old
    5 s default the second writer to arrive gave up, and the watcher logged
    ``Cycle failed (database is locked)`` on any overlap.  30 s rides out a
    normal cycle.  ``TRUSTSIGHT_SQLITE_BUSY_TIMEOUT`` overrides it (a
    non-negative integer of milliseconds; anything else keeps the default).
    """
    raw = os.environ.get("TRUSTSIGHT_SQLITE_BUSY_TIMEOUT", "").strip()
    if not raw:
        return _BUSY_TIMEOUT_DEFAULT_MS
    try:
        value = int(raw)
    except ValueError:
        return _BUSY_TIMEOUT_DEFAULT_MS
    return value if value >= 0 else _BUSY_TIMEOUT_DEFAULT_MS

def _new_connection(db_path: Path) -> sqlite3.Connection:
    # The parent may not exist yet on a path that never went through
    # `config.ensure_dirs` (a first import, or a test that points DATA_DIR at
    # a fresh tmpdir).  Create it owner-only rather than let SQLite fail with
    # a path-dependent "unable to open database file".
    db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existed = db_path.exists()
    # `timeout` is the busy handler: a writer waits this long for a lock
    # instead of raising "database is locked".  Set here rather than with
    # `PRAGMA busy_timeout` so no value ever reaches SQL text.
    conn = sqlite3.connect(str(db_path), timeout=_busy_timeout_ms() / 1000)
    if not existed:
        # SQLite creates the file 0666 & ~umask; the database holds package
        # names, maintainers and analysis history, so pin it to the owner.
        try:
            os.chmod(db_path, 0o600)
        except OSError:
            pass
    conn.row_factory = sqlite3.Row
    # journal_mode is a persistent property of the file, so this only does
    # real work the first time a database is created; foreign_keys and
    # synchronous are per-connection and have to be set on every one.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_SYNC_SQL[_synchronous_mode()])
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

@contextmanager
def get_read_only_connection():
    """Yield a read-only SQLite connection to the current database.

    Used by ``--allow-uninstalled`` without ``--record``: the analysis
    reads accumulated history for novelty and maturity but never writes
    observations.  This bounds the self-inflicted state-poisoning class
    (A15): auditing a suspicious package must not warm the local state
    so that a future legitimate package looks established.
    """
    db_path = get_db_path()
    uri = f"file:{db_path}?mode=ro"
    # A reader in WAL still needs the busy handler: it waits on a checkpoint
    # or a schema lock, and without a timeout a busy database reads as an
    # error rather than a short wait.  The connect `timeout` sets it.
    conn = sqlite3.connect(uri, uri=True, timeout=_busy_timeout_ms() / 1000)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

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

@contextmanager
def get_connection():
    """Yield the cached connection for the current database path.

    The connection is reused rather than closed on exit, so callers must
    still ``commit()`` their writes exactly as before.  Exactly one is kept
    per thread: a process only ever works against one database, and closing
    the previous one when the path changes keeps the tests, which point
    DATA_DIR at a fresh tmpdir per case, from accumulating handles.

    A body that raises gets its transaction rolled back: a partial write
    left open on the cached connection would otherwise be persisted by the
    next caller's ``commit()``.
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
    try:
        yield _local.cached[1]
    except Exception:
        _local.cached[1].rollback()
        raise

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

            CREATE TABLE IF NOT EXISTS property_transitions (
                id INTEGER PRIMARY KEY,
                package_name TEXT NOT NULL,
                property_key TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_property_transitions_package
                ON property_transitions(package_name);
            CREATE INDEX IF NOT EXISTS idx_property_transitions_key
                ON property_transitions(package_name, property_key);

            CREATE TABLE IF NOT EXISTS pkgbuild_snapshots (
                package_name TEXT PRIMARY KEY,
                pkgbuild_text TEXT NOT NULL,
                srcinfo_text TEXT,
                install_text TEXT,
                version TEXT NOT NULL,
                last_modified INTEGER DEFAULT 0,
                captured_at TEXT NOT NULL
            );

            /* the corpus as documents. Per observed package
               version, the RecipeDoc's scalars and arrays (never the full
               text) are stored so "has this exact source-array tuple
               appeared before" is set membership rather than a statistical
               guess.  Bounded per package like every other corpus table. */
            CREATE TABLE IF NOT EXISTS recipe_observations (
                package_name TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                scalars_json TEXT NOT NULL,
                PRIMARY KEY (package_name, observed_at)
            );

            CREATE TABLE IF NOT EXISTS recipe_array_observations (
                package_name TEXT NOT NULL,
                array_name TEXT NOT NULL,
                entries_hash TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_recipe_array_observations
                ON recipe_array_observations(
                    package_name, array_name, entries_hash);

            CREATE TABLE IF NOT EXISTS alert_state (
                package_name TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_sent TEXT,
                count INTEGER DEFAULT 1,
                PRIMARY KEY (package_name, rule_id)
            );

            /* Campaign alert mode: corroborated campaigns that keep a
               package's scope "primed" for a bounded number of observations.
               TTL is in observation units (see OBSERVATION_SEQ_KEY), not
               wall-clock: the tool must not consult a clock it does not
               control.  An expired campaign is filtered out by query, so
               expiry is structural rather than a sweep. */
            CREATE TABLE IF NOT EXISTS campaign_alerts (
                campaign_id TEXT PRIMARY KEY,
                scope_json TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT '',
                activated_at_obs INTEGER NOT NULL,
                ttl_obs INTEGER NOT NULL,
                expiry_announced INTEGER NOT NULL DEFAULT 0
            );

            /* Class D adoption feed: one row per package per corpus cycle.
               The metadata-dump diff between cycles is the first-class
               stream the corpus sweep consumes; H045/H055/H052/H073 read
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

            /* (T-series): the ecosystem index the temporal
               rules read.  One row per signing key and per maintainer
               domain the corpus has ever observed, with its first-seen
               stamp, so "is this key/domain new to the ecosystem" is set
               membership rather than a guess.  Bounded by row count. */
            CREATE TABLE IF NOT EXISTS observed_signing_keys (
                key TEXT PRIMARY KEY,
                first_seen TEXT
            );
            CREATE TABLE IF NOT EXISTS observed_maintainer_domains (
                domain TEXT PRIMARY KEY,
                first_seen TEXT
            );

            /* added literals per package, so G002 (Shared
               Added Literal) can join across packages instead of scanning
               every package's diff in memory each cycle.  The literal is
               stored bounded; the join is over its content, so two packages
               that added the same blob meet here. */
            CREATE TABLE IF NOT EXISTS observed_added_literals (
                package_name TEXT NOT NULL,
                literal TEXT NOT NULL,
                literal_len INTEGER NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_added_literals_package
                ON observed_added_literals(package_name);

            /* three indexed views the G-series correlates
               over at cycle end (O(cycle) queries, not O(packages^2)).
               equivalent tables exist - these are the queryable surfaces. */
            CREATE VIEW IF NOT EXISTS gained_hosts_window AS
                SELECT pt.package_name AS package_name,
                       je.value AS host,
                       pt.observed_at AS observed_at
                FROM property_transitions pt, json_each(pt.new_value) je
                WHERE pt.property_key = 'source_hosts'
                  AND je.value NOT IN (
                      SELECT je2.value
                      FROM json_each(COALESCE(pt.old_value, '[]')) je2);

            CREATE VIEW IF NOT EXISTS added_literal_hashes AS
                SELECT package_name, literal, literal_len, observed_at
                FROM observed_added_literals;

            CREATE VIEW IF NOT EXISTS adoption_events AS
                SELECT pt.package_name AS package_name,
                       json_extract(pt.new_value, '$') AS maintainer,
                       CASE WHEN json_extract(pt.old_value, '$') IS NULL
                                 OR json_extract(pt.old_value, '$') = ''
                            THEN 'H086' ELSE 'H044' END AS predicate,
                       pt.observed_at AS observed_at
                FROM property_transitions pt
                WHERE pt.property_key = 'maintainer'
                  AND COALESCE(json_extract(pt.new_value, '$'), '') <> '';
        """)
        _migrate(conn)
        conn.commit()

_ADDED_COLUMNS = {
    "packages": {
        "current_maintainer": "TEXT DEFAULT ''",
        # H086: whether the AUR reported this package as orphaned the last
        # time we asked.  -1 means "never asked", which is not the same as
        # "was not orphaned": an adoption can only be claimed against a
        # recorded prior observation, never against an absence of one.
        "aur_orphaned": "INTEGER DEFAULT -1",
    },
    # The ``.install`` scriptlet captured beside the PKGBUILD, so the corpus
    # path can scan it for an unconditional root fetch/write at install time.
    "pkgbuild_snapshots": {
        "install_text": "TEXT",
    },
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

    _migrate_rule_ids(conn)

_SCHEMA_VERSION = 1

def _migrate_rule_ids(conn: sqlite3.Connection) -> None:
    """Rewrite stored rule ids for the heuristic rules renamed to ``H``.

    Alert de-duplication keys on ``(package_name, rule_id)``.  Without this,
    the release that renames ``R060`` to ``H015`` makes every alert an
    operator has already seen look new, and the first run after upgrading
    re-notifies for the entire watchlist.

    The rewrite cannot collide: the mapping is injective and ``H`` ids never
    existed before it, so no updated row can land on a primary key that is
    already occupied.
    """
    if conn.execute("PRAGMA user_version").fetchone()[0] >= _SCHEMA_VERSION:
        return
    pairs = [(new, old) for old, new in RENAMED_RULE_IDS.items()]
    conn.executemany(
        "UPDATE alert_state SET rule_id = ? WHERE rule_id = ?", pairs)
    conn.executemany(
        "UPDATE triggered_rules SET rule_id = ? WHERE rule_id = ?", pairs)
    # A literal, because PRAGMA does not take bound parameters. The value is
    # a module constant, never anything read from a database or a diff.
    conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION:d}")

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
    # Drop any leftover backup from a previous failed migration before
    # renaming.  A previous run may have hashed the rows but crashed
    # before the RENAME, leaving both tables in place.
    if "maintainers_deprecated_backup" in tables:
        conn.execute("DROP TABLE IF EXISTS maintainers_deprecated_backup")
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
    from ..seed_build import _hash_value

    return _hash_value(value, salt)
