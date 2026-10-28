"""Extracted from db.py: _connection."""

from datetime import datetime, timezone
import json
import threading
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional
from ._common import log

__all__ = ['DEFAULT_HASH_ALGORITHM', 'MAX_SEED_BYTES', 'MAX_SEED_MEMBERS', 'MAX_SEED_MEMBER_BYTES', 'SEED_META_HASH_ALGORITHM_KEY', 'SEED_META_SALT_KEY', '_ADDED_COLUMNS', '_SCHEMA_VERSION', '_SYNC_MODES', '_SYNC_SQL', '_ensure_salt', '_generate_salt', '_get_salt', '_hash_maintainer_rows', '_hash_maintainer_value', '_local', '_migrate', '_migrate_plaintext_maintainers', '_migrate_rule_ids', '_new_connection', '_synchronous_mode', 'close_connections', 'get_connection', 'get_db_path', 'get_read_only_connection', 'init_db', 'write_batch']

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

class _BatchConnection(sqlite3.Connection):
    """A connection whose ``commit()`` is deferred inside :func:`write_batch`.

    Every corpus writer commits itself, so persisting one package used to be
    a dozen separate transactions - a WAL append each, and each one a
    candidate for the autocheckpoint to copy pages back into the database.
    While a batch is open ``commit()`` is a no-op; the outermost
    :func:`write_batch` block commits the whole thing once (or rolls it back
    as one unit on error).  A normal caller outside a batch is unaffected.
    """

    def commit(self) -> None:
        if getattr(_local, "batch_depth", 0):
            return
        super().commit()

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
    conn = sqlite3.connect(
        str(db_path), timeout=_busy_timeout_ms() / 1000,
        factory=_BatchConnection,
    )
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
    # A corpus cycle writes thousands of rows.  The default autocheckpoint
    # (1000 pages, ~4 MB) copies the WAL back into the database every few
    # megabytes, and on an encrypted volume that copy dominated the run;
    # defer it to 2000 pages (~8 MB) and cap the file so one burst cannot
    # grow the WAL without bound.  cache_size is raised from the 2 MB default
    # so a cycle's hot pages are not evicted between writes, but kept to
    # 32 MB: the watcher runs on small hosts and the OS page cache already
    # holds the snapshot.
    conn.execute("PRAGMA wal_autocheckpoint=2000")
    conn.execute("PRAGMA journal_size_limit=16777216")
    conn.execute("PRAGMA cache_size=-32768")
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
    next caller's ``commit()``.  Inside a :func:`write_batch` the rollback
    is left to the batch: an inner block must not unilaterally discard the
    writes the batch has already deferred, and a best-effort writer that
    catches its own error is expected to continue in the same transaction.
    """
    conn = _cached_connection()
    try:
        yield conn
    except Exception:
        if not getattr(_local, "batch_depth", 0):
            conn.rollback()
        raise

def _cached_connection() -> sqlite3.Connection:
    """The cached connection for the current path, opened on first use."""
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
    return _local.cached[1]

@contextmanager
def write_batch():
    """Commit the writes inside as a single transaction.

    The corpus writers each ``commit()`` on their own, so persisting one
    package used to be a dozen separate transactions.  Inside this block
    those commits are deferred and the whole block is committed once (and
    rolled back together on error), so a package's writes cost one
    transaction rather than twelve.  Nesting is safe: only the outermost
    block commits, so a helper may open a batch of its own without leaking a
    partial commit.
    """
    depth = getattr(_local, "batch_depth", 0)
    conn: Optional[sqlite3.Connection] = None
    if depth == 0:
        conn = _cached_connection()
    _local.batch_depth = depth + 1
    try:
        yield
    except BaseException:
        _local.batch_depth = depth
        if conn is not None:
            try:
                conn.rollback()
            except sqlite3.Error:
                log.debug("write batch rollback failed", exc_info=True)
        raise
    else:
        _local.batch_depth = depth
        if conn is not None:
            # A failed commit is the batch's write being lost; let it
            # propagate rather than look like a clean cycle.
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

# Schema creation lives in ``_schema``; re-export the names the db facade
# and older callers import from this module.  The import is at the bottom so
# the schema module can import the connection helpers lazily.
from ._schema import (  # noqa: E402,F401
    _ADDED_COLUMNS,
    _SCHEMA_VERSION,
    _migrate,
    _migrate_plaintext_maintainers,
    _migrate_rule_ids,
    init_db,
)
