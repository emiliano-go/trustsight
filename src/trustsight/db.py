import atexit
from datetime import datetime, timezone
import os
import re
import sqlite3
import subprocess
import threading
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


def is_maintainer_globally_novel(name: str) -> bool:
    """Return True if *name* has never been seen as a maintainer."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM maintainers WHERE name = ?", (name,)
        ).fetchone()
        if row:
            return False
        seed_row = conn.execute(
            "SELECT count FROM maintainer_counts WHERE name = ?", (name,)
        ).fetchone()
        if seed_row and seed_row["count"] > 0:
            return False
    return True


def get_maintainer_global_count(name: str) -> int:
    """How many packages a maintainer is recorded against by the seed."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT count FROM maintainer_counts WHERE name = ?", (name,)
        ).fetchone()
        return row["count"] if row else 0


def import_seed(seed_path: Path) -> dict:
    """Merge a seed database into the user's database.

    Additive and idempotent: existing rows win, so a seed can never
    overwrite something learned from a real analysis.  Returns counts of
    what was imported.
    """
    import gzip
    import hashlib
    import tempfile

    init_db()
    path = Path(seed_path)
    if not path.exists():
        raise FileNotFoundError(path)

    # Digest the artifact as delivered, before decompression, so the
    # recorded value identifies the exact file that was trusted.
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    origin = "bundled" if path == bundled_seed_path() else str(path)

    temp: Optional[Path] = None
    if path.suffix == ".gz":
        fd, tmp_name = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        temp = Path(tmp_name)
        # Bounded: the bundled seed is ~20 MB compressed, but `seed-db`
        # accepts a path, and a gzip file that expands without limit would
        # otherwise fill the disk before SQLite ever looked at it.
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
        path = temp

    try:
        # A dedicated connection rather than the pooled one: this ATTACHes a
        # second database, and an exception between ATTACH and DETACH would
        # otherwise leave the cached connection holding the seed forever, so
        # every later import in the same process would fail to re-attach.
        conn = _new_connection(get_db_path())
        try:
            # source_urls.first_seen_package_id references packages(id),
            # and foreign_keys is ON, so the sentinel row must exist.
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
            conn.execute(
                # OR IGNORE, not OR REPLACE: a high maintainer count is what
                # makes a maintainer look established, and an established
                # maintainer suppresses R071/R090.  A seed may supply that
                # number on a cold database; it may not overwrite one this
                # install learned, which would be a suppression primitive
                # handed to whoever wrote the seed.
                """INSERT OR IGNORE INTO maintainer_counts (name, count)
                   SELECT name, count FROM seed.maintainer_counts"""
            )
            maint = conn.execute(
                "SELECT COUNT(*) AS n FROM maintainer_counts"
            ).fetchone()["n"]
            # A seed predating dependency_names is still importable; the
            # table simply stays empty and every dependency reads as novel,
            # which is why the D-series checks for an empty table.
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
                           observation_count = observation_count
                                               + excluded.observation_count"""
                )
                deps = conn.execute(
                    "SELECT COUNT(*) AS n FROM dependency_names"
                ).fetchone()["n"]
            placeholders = ",".join("?" for _ in SEED_OWNED_KEYS)
            conn.execute(
                f"""INSERT OR REPLACE INTO metadata (key, value)
                    SELECT key, value FROM seed.metadata
                    WHERE key IN ({placeholders})""",
                SEED_OWNED_KEYS,
            )
            # Provenance, so "where did these priors come from" is a
            # question the database can answer.  A seed cannot raise a
            # score, but it can lower one by making a URL look familiar,
            # and that is worth being able to attribute.
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
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def bundled_seed_path() -> Path:
    """Return the path to the bundled seed database."""
    return Path(__file__).parent / "data" / "seed.db.gz"


def maybe_auto_import_seed(quiet: bool = False) -> Optional[dict]:
    """Import the bundled seed on a database that has never been seeded.

    A cold database makes every source URL look novel and holds maturity
    at zero, which downgrades every Medium verdict to INCONCLUSIVE.  The
    seed is derived from public AUR data and is additive, so importing it
    automatically costs the user nothing and makes the first run useful.

    Returns import stats, or ``None`` if nothing was done.
    """
    if seed_observation_count() > 0:
        return None
    if count_observations() > 0:
        # A database with real history does not need a bootstrap.
        return None
    seed = bundled_seed_path()
    if not seed.exists():
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

        # source_urls and maintainers have FK to packages(id).  Reassign to
        # the sentinel row (id 0) rather than deleting; the seed may have
        # contributed data the user wants to keep.
        conn.execute(
            "UPDATE source_urls SET first_seen_package_id = 0 WHERE first_seen_package_id = ?",
            (pkg_id,),
        )
        conn.execute(
            "UPDATE maintainers SET first_seen_package_id = 0 WHERE first_seen_package_id = ?",
            (pkg_id,),
        )

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
