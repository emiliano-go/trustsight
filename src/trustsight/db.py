import sqlite3
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
        temp = Path(tempfile.mkstemp(suffix=".db")[1])
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
