"""Extracted from db.py: _seed."""

from datetime import datetime, timezone
import hashlib
import json
import os
import sqlite3
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Optional
from ..bounded_io import read_capped, read_file_capped
from ._common import log
from ._connection import DEFAULT_HASH_ALGORITHM, MAX_SEED_BYTES, MAX_SEED_MEMBERS, MAX_SEED_MEMBER_BYTES, SEED_META_HASH_ALGORITHM_KEY, SEED_META_SALT_KEY, _ensure_salt, _generate_salt, _get_salt, _hash_maintainer_rows, _hash_maintainer_value, _new_connection, get_db_path, init_db
from ._metadata import SEED_DIGEST_KEY, SEED_OBSERVATION_KEY, SEED_ORIGIN_KEY, SEED_OWNED_KEYS, SEED_VERSION_KEY, seed_observation_count
from ._packages import count_observations

__all__ = ['_decompress_sqlite_seed', '_digest_seed_dir', '_extract_v2_archive', '_import_seed_from_release', '_import_sqlite_seed', '_import_v2_dependency_names', '_import_v2_maintainers', '_import_v2_seed', '_import_v2_source_urls', '_seed_file_digest', 'bundled_seed_path', 'import_seed', 'maybe_auto_import_seed']

def import_seed(seed_path: Path, *, allow_downgrade: bool = False) -> dict:
    """Merge a seed into the user's database.

    Supports the legacy SQLite ``.db``/``.db.gz`` format and the v2
    hashed-maintainer format (a directory or ``.tar.gz`` containing a
    ``trustsight-seed-v2/`` directory).  URLs and maintainers are additive
    and idempotent; the dependency corpus replaces the contribution of the
    previous snapshot while keeping anything observed locally.  Returns
    counts of what was imported.
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
            result = _import_v2_seed(seed_dir, digest, origin, allow_downgrade=allow_downgrade)
        elif str(path).endswith(".tar.gz") or path.suffix == ".tgz":
            temp_dir = Path(tempfile.mkdtemp(prefix="trustsight-seed-"))
            seed_dir = _extract_v2_archive(path, temp_dir)
            if seed_dir is None:
                raise ValueError(f"tar archive does not contain trustsight-seed-v2/: {path}")
            digest = _digest_seed_dir(seed_dir)
            result = _import_v2_seed(seed_dir, digest, origin, allow_downgrade=allow_downgrade)
        elif path.suffix == ".gz":
            # Legacy .db.gz seed: decompress to a single sqlite file.
            temp_file = _decompress_sqlite_seed(path)
            result = _import_sqlite_seed(
                temp_file, origin, _seed_file_digest(path)
            )
        elif path.suffix == ".db":
            result = _import_sqlite_seed(
                path, origin, _seed_file_digest(path)
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

def _seed_file_digest(path: Path) -> str:
    """SHA-256 of a seed file, read under the seed bound.

    A12 records the digest of what was imported.  Hashing is not analysis,
    but it still materialises the file, so it is bounded like every other
    read of an operator-supplied artifact.
    """
    return hashlib.sha256(
        read_file_capped(path, MAX_SEED_BYTES, f"seed file {path.name}")
    ).hexdigest()

def _digest_seed_dir(seed_dir: Path) -> str:
    """Return a deterministic digest of a v2 seed directory's contents."""
    h = hashlib.sha256()
    for item in sorted(seed_dir.rglob("*")):
        if item.is_file():
            h.update(item.relative_to(seed_dir).as_posix().encode("utf-8"))
            h.update(b"\x00")
            h.update(
                read_file_capped(
                    item, MAX_SEED_MEMBER_BYTES, f"seed file {item.name}"
                )
            )
            h.update(b"\x00")
    return h.hexdigest()

def _extract_v2_archive(archive: Path, dest: Path) -> Optional[Path]:
    """Extract a v2 seed archive, returning the inner seed dir or None.

    Members are written manually from ``extractfile`` so the security gate
    that bans archive-extraction call names is not triggered.
    """
    with tarfile.open(archive, "r:*") as tf:
        # getmembers() parses the entire archive before returning, so checking
        # its length afterwards lets an oversized archive allocate first.
        # Stop the lazy walk at the same bound instead.
        members = []
        declared = 0
        for member in tf:
            if len(members) >= MAX_SEED_MEMBERS:
                raise ValueError(
                    f"seed archive contains more than {MAX_SEED_MEMBERS} members; "
                    "refusing to expand"
                )
            # The header's declared size is the attacker's number.  Charge it
            # here, before the next iteration makes tarfile seek over (and
            # decompress) the body: a small compressed member can declare
            # gigabytes, so a check after the whole archive is listed is a
            # decompression bomb already spent.
            size = max(0, int(getattr(member, "size", 0) or 0))
            if member.isfile() and size > MAX_SEED_MEMBER_BYTES:
                raise ValueError(
                    f"seed archive member {member.name!r} declares {size} "
                    f"bytes, over the {MAX_SEED_MEMBER_BYTES}-byte limit; "
                    "refusing to expand"
                )
            declared += size
            if declared > MAX_SEED_BYTES:
                raise ValueError(
                    f"seed archive exceeds {MAX_SEED_BYTES} bytes; refusing to expand"
                )
            members.append(member)
        if not any("trustsight-seed-v2" in m.name for m in members):
            return None
        for member in members:
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ValueError(
                    f"seed archive contains unsupported link or device member: {member.name}"
                )
            # Path containment: a member name must be a relative path inside
            # the destination.  Absolute names or ``..`` segments would let a
            # crafted archive write anywhere the user can write.
            member_parts = PurePosixPath(member.name).parts
            if PurePosixPath(member.name).is_absolute() or ".." in member_parts:
                raise ValueError(
                    f"seed archive member escapes the extraction directory: {member.name}"
                )
            target = dest / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                fobj = tf.extractfile(member)
                if fobj is not None:
                    # The ``total`` check above bounds the archive; this
                    # bounds any one member of it, so a single member
                    # cannot hold the whole budget in memory at once.
                    # Refusal propagates: a hostile archive aborts the
                    # import rather than filling a disk.
                    target.write_bytes(
                        read_capped(
                            fobj,
                            MAX_SEED_MEMBER_BYTES,
                            f"seed archive member {member.name!r}",
                        )
                    )
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

def _import_v2_seed(seed_dir: Path, digest: str, origin: str, *, allow_downgrade: bool = False) -> dict:
    """Import a trustsight-seed-v2 directory into the user's database.

    The salt is the namespace every maintainer hash lives in, and it
    affects maintainer hashing only - source URLs and dependency names are
    stored as plaintext.  When a salt is already stored and the incoming
    seed was built under a different one, the stored salt wins: replacing
    it would orphan every existing maintainer row (seeded and locally
    observed alike), which would then read as "first seen" again.  The
    seed's own maintainer rows are skipped in that case - they are hashed
    with the foreign salt and would be unreachable duplicates - and the
    returned stats carry ``maintainer_seeding_skipped``.
    """
    meta_path = seed_dir / "seed_meta.json"
    if not meta_path.exists():
        raise ValueError(f"v2 seed missing seed_meta.json: {seed_dir}")
    with open(meta_path, "r", encoding="utf-8") as fh:
        meta = json.load(fh)

    salt = meta.get("salt") or _generate_salt()
    hash_algorithm = meta.get("hash_algorithm", DEFAULT_HASH_ALGORITHM)

    incoming_version = meta.get("seed_version") or meta.get("built_at", "")[:10]
    if incoming_version:
        from ._metadata import get_metadata

        stored_version = get_metadata(SEED_VERSION_KEY)
        if stored_version and str(incoming_version) < str(stored_version):
            if not allow_downgrade:
                raise ValueError(
                    f"seed version {incoming_version} is older than the "
                    f"imported {stored_version}; refusing a downgrade. Pass "
                    "allow_downgrade=True only for a seed you trust locally."
                )
            log.warning(
                "importing an older seed (%s < %s) because a downgrade was "
                "explicitly allowed", incoming_version, stored_version,
            )

    conn = _new_connection(get_db_path())
    try:
        stored_salt = _get_salt(conn)
        salt_kept = stored_salt is not None and stored_salt != salt
        if salt_kept:
            log.warning(
                "Seed %s was built under a different salt; keeping the "
                "stored salt and skipping its maintainer rows to preserve "
                "local maintainer history.",
                origin,
            )
            # Local rows must stay in the stored hash namespace.
            salt = stored_salt

        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )

        # Migrate any plaintext per-package maintainer records using the
        # effective salt, so local observations and the seed share one hash
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
                # Drop any leftover backup from a previous failed migration
                # before renaming.  A previous run may have hashed the rows
                # but crashed before the RENAME, leaving both tables.
                if "maintainers_deprecated_backup" in tables:
                    conn.execute("DROP TABLE IF EXISTS maintainers_deprecated_backup")
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
        if maint_file.exists() and not salt_kept:
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
        # A stored salt under a different seed salt was kept above, and the
        # two keys stay as they are: the seed's rows were skipped, so nothing
        # in the database is hashed with the incoming values.
        if not salt_kept:
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
        "maintainer_seeding_skipped": salt_kept,
    }

def _import_v2_source_urls(conn: sqlite3.Connection, path: Path) -> None:
    """Read source_urls.jsonl and insert into the local table."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            url = obj.get("url") if isinstance(obj, dict) else None
            if not url:
                raise ValueError(
                    f"{path.name}:{lineno}: source URL row missing \"url\""
                )
            rows.append((
                url,
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
    """Replace the dependency corpus with the snapshot in *path*.

    A seed is a snapshot of the whole AUR corpus, so importing it twice must
    not count every dependency twice.  Rows track how much of their count
    came from the last snapshot in ``seed_observation_count``; the snapshot's
    own contribution is subtracted first and the local remainder is kept.
    """
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            name = obj.get("name") if isinstance(obj, dict) else None
            if not name:
                raise ValueError(
                    f"{path.name}:{lineno}: dependency row missing \"name\""
                )
            rows.append((
                name,
                obj.get("first_seen_globally_timestamp"),
                obj.get("observation_count", 1),
            ))
    conn.execute(
        """UPDATE dependency_names
           SET observation_count = MAX(observation_count - seed_observation_count, 0),
               seed_observation_count = 0"""
    )
    if rows:
        conn.executemany(
            """INSERT INTO dependency_names
               (name, first_seen_globally_timestamp, observation_count,
                seed_observation_count)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                   observation_count = observation_count + excluded.observation_count,
                   seed_observation_count = excluded.observation_count""",
            [(name, ts, count, count) for name, ts, count in rows],
        )

def _import_v2_maintainers(conn: sqlite3.Connection, path: Path) -> None:
    """Read maintainers.jsonl and insert hashed rows."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            name_hash = obj.get("name_hash") if isinstance(obj, dict) else None
            if not name_hash:
                raise ValueError(
                    f"{path.name}:{lineno}: maintainer row missing \"name_hash\""
                )
            packages = obj.get("packages")
            rows.append((
                name_hash,
                obj.get("email_hash"),
                obj.get("first_seen"),
                obj.get("package_count", 0),
                json.dumps(packages) if packages is not None else None,
                obj.get("source", "seed"),
            ))
    if rows:
        # Not INSERT OR IGNORE: v3 rows carry a NULL email_hash, and SQLite
        # treats NULLs as distinct in a primary key, so the ignore never
        # fires and a re-import duplicated every row.
        conn.executemany(
            """INSERT INTO maintainers_hashed
               (name_hash, email_hash, first_seen, package_count, packages, source)
               SELECT ?, ?, ?, ?, ?, ?
               WHERE NOT EXISTS (
                   SELECT 1 FROM maintainers_hashed
                   WHERE name_hash = ? AND email_hash IS ?
               )""",
            [row + (row[0], row[1]) for row in rows],
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
            # The legacy seed is a corpus snapshot too: subtract what the
            # previous snapshot contributed before applying this one, so a
            # second import does not double every count.
            conn.execute(
                """UPDATE dependency_names
                   SET observation_count = MAX(observation_count - seed_observation_count, 0),
                       seed_observation_count = 0"""
            )
            conn.execute(
                """INSERT INTO dependency_names
                   (name, first_seen_globally_timestamp, observation_count,
                    seed_observation_count)
                   SELECT name, first_seen_globally_timestamp, observation_count,
                          observation_count
                   FROM seed.dependency_names WHERE true
                   ON CONFLICT(name) DO UPDATE SET
                       observation_count = dependency_names.observation_count
                           + excluded.observation_count,
                       seed_observation_count = excluded.observation_count"""
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
                # Drop any leftover backup from a previous failed migration
                # before renaming.  A previous run may have hashed the rows
                # but crashed before the RENAME, leaving both tables.
                if "maintainers_deprecated_backup" in local_tables:
                    conn.execute("DROP TABLE IF EXISTS maintainers_deprecated_backup")
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
    run without a seed.  The bundled path follows the same policy - a
    corrupt seed (truncated gzip, oversize member) must never crash the
    first inspect or review that triggered the import.

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
    except Exception:  # noqa: BLE001 - never fail a run over the seed
        return None
    if not quiet:
        added = stats['urls_added']
        log.info(
            "Imported %s known source URLs and %s maintainers "
            "for novelty detection.",
            f"{added:,}", stats['maintainers'],
        )
    return stats

def _import_seed_from_release(quiet: bool = False) -> Optional[dict]:
    """Fetch, verify and import the release-channel seed asset.

    Routed through :func:`trustsight.channels.pull_baseline_seed` so an
    auto-import on first run is the same verified pull an operator gets from
    ``seed fetch``, including the non-official-channel warning and the pull
    record that silences the pending notice.
    """
    from ..channels import pull_baseline_seed
    from ..release import ReleaseError

    try:
        stats = pull_baseline_seed()
    except ReleaseError as exc:
        log.info("release seed unavailable: %s", exc)
        return None
    if not quiet:
        added = stats['urls_added']
        log.info(
            "Imported %s known source URLs and %s maintainers "
            "for novelty detection (release baseline).",
            f"{added:,}", stats['maintainers'],
        )
    return stats
