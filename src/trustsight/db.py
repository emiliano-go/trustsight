import os
import sqlite3
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .config import DATA_DIR


def get_db_path() -> Path:
    return DATA_DIR / "trustsight.db"


@contextmanager
def get_connection():
    db_path = get_db_path()
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def init_db():
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
        """)
        conn.commit()


def upsert_package(name: str, version: str) -> int:
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
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM packages WHERE name = ?", (name,)).fetchone()
        return row["id"] if row else None


def get_package(name: str) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None


def get_last_analysis(package_id: int) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(
            """SELECT * FROM analysis_history
               WHERE package_id = ?
               ORDER BY id DESC LIMIT 1""",
            (package_id,),
        ).fetchone()
        return dict(row) if row else None


def get_triggered_rules(history_id: int) -> list[dict]:
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
    with get_connection() as conn:
        conn.execute(
            "UPDATE packages SET current_version = ?, last_checked = datetime('now') WHERE name = ?",
            (version, name),
        )
        conn.commit()


def update_package_maintainer(name: str, maintainer: str):
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


def get_metadata(key: str) -> Optional[str]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None


def set_metadata(key: str, value: str) -> None:
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


def top_dependency_names(limit: int = 5000) -> list[str]:
    """The most-depended-on names, as a popularity proxy for typosquatting.

    Observation count already ranks names by how many packages rely on
    them, so no separate "top packages" list needs shipping.
    """
    with get_connection() as conn:
        try:
            rows = conn.execute(
                """SELECT name FROM dependency_names
                   ORDER BY observation_count DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        return [r["name"] for r in rows]


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
    import shutil
    import tempfile

    init_db()
    path = Path(seed_path)
    if not path.exists():
        raise FileNotFoundError(path)

    temp: Optional[Path] = None
    if path.suffix == ".gz":
        fd, tmp_name = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        temp = Path(tmp_name)
        with gzip.open(path, "rb") as src, open(temp, "wb") as dst:
            shutil.copyfileobj(src, dst)
        path = temp

    try:
        with get_connection() as conn:
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
                """INSERT OR REPLACE INTO maintainer_counts (name, count)
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
            conn.execute(
                """INSERT OR REPLACE INTO metadata (key, value)
                   SELECT key, value FROM seed.metadata"""
            )
            conn.commit()
            conn.execute("DETACH DATABASE seed")
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
        print(
            f"Imported novelty seed: {stats['urls_total']} source URLs, "
            f"{stats['maintainers']} maintainers "
            f"({stats['observations']} observations)."
        )
    return stats


def get_history(package_id: int, limit: int = 20) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM analysis_history
               WHERE package_id = ?
               ORDER BY id DESC LIMIT ?""",
            (package_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_packages() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM packages ORDER BY name").fetchall()
        return [dict(r) for r in rows]
