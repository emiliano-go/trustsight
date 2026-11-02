"""The operator watchlist: hand-curated accounts and packages.

Registration date, "Inactive since" and suspension state live on AUR profile
pages, and the pipeline reads only RPC metadata, so no machine rule can compute
them.  Where a human has established such a fact - the pattern Claudia triages
by hand, ``Inactive-since ~ Last Updated and Last Packager = Package
Maintainer`` - this list records it, and a package whose maintainer is listed is
reported as **G009 Watchlisted Subject** (weight 0) rather than silently
trusted.  A package can be listed directly for the same reason: the operator
wants it named in the report.

Maintainer entries are keyed by the same salted SHA-256 the
``maintainers_hashed`` table uses (:func:`trustsight.db._hash_maintainer_value`),
so no plaintext identity is retained.  The salt is per-installation, so an entry
only ever matches on the installation that added it - which is where the
operator's judgement applies.  Package names are already public in every record,
report and AUR page, so they are stored as written.

The file lives beside the other operator configuration::

    ~/.config/trustsight/watchlist.json

and is absent by default, so G009 is silent on a clean install.  Add a
maintainer with the local salt, or a package without one::

    python -c "from trustsight.watchlist import add_entry; add_entry('fennekuiper', 'June 2026 orphan sweep')"
    python -c "from trustsight.watchlist import add_package; add_package('xsp', 'June 2026 review')"
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

__all__ = ["add_entry", "add_package", "default_path", "import_release",
           "load_packages", "load_release_maintainers", "load_release_packages",
           "load_watchlist", "local_hash", "local_hash_many",
           "watchlist_hashes"]

#: The operator's file is trusted, but a corrupt or runaway file must not
#: decide how much memory the sweep spends (A4/A14).  Exceeding it is an
#: unreadable watchlist, which is already the documented empty case.
MAX_WATCHLIST_BYTES = 1024 * 1024
MAX_WATCHLIST_ENTRIES = 100_000
MAX_WATCHLIST_LABEL_CHARS = 500


def default_path() -> Path:
    """The watchlist's default location, beside the operator's other config."""
    from .config import CONFIG_DIR

    return CONFIG_DIR / "watchlist.json"


def _read(path) -> dict:
    from .bounded_io import ReadTooLarge, read_file_capped

    target = Path(path) if path else default_path()
    try:
        raw = read_file_capped(
            target, MAX_WATCHLIST_BYTES, "watchlist")
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, ReadTooLarge):
        return {}
    return data if isinstance(data, dict) else {}


def load_watchlist(path=None) -> dict[str, str]:
    """Return ``{name_hash: label}`` for the watchlist, empty when absent.

    An unreadable or malformed file is empty, never an error: a watchlist is an
    optional operator aid and must not break an analysis.
    """
    out: dict[str, str] = {}
    for entry in _read(path).get("entries") or ():
        if not isinstance(entry, dict):
            continue
        name_hash = str(entry.get("name_hash", "")).strip()
        if name_hash:
            out[name_hash] = str(entry.get("label", "") or "")
    if path is None:
        # The imported ``watchlist-*`` release is a separate, signed set; a
        # local entry wins on collision because the operator's own judgement
        # is the specific one.  A non-default *path* names another local
        # file and, like the default, is not mixed with the release.
        for name_hash, label in load_release_maintainers().items():
            out.setdefault(name_hash, label)
    return out


def watchlist_hashes(path=None) -> set[str]:
    """The set of watchlisted name hashes."""
    return set(load_watchlist(path))


def load_packages(path=None) -> dict[str, str]:
    """Return ``{package: label}`` for the watchlist's package entries.

    Package names are public, so they are stored as written rather than
    hashed.  A missing or malformed section is empty, never an error: the
    watchlist is an optional operator aid and must not break an analysis.
    """
    packages = _read(path).get("packages")
    if not isinstance(packages, dict):
        packages = {}
    out: dict[str, str] = {}
    for name, label in packages.items():
        package = str(name).strip()
        if package:
            out[package] = str(label or "")
    if path is None:
        for package, label in load_release_packages().items():
            out.setdefault(package, label)
    return out


def local_hash(name: str) -> str | None:
    """The name's hash under this installation's salt, or None if unseeded."""
    from .db import get_connection
    from .db._connection import _get_salt, _hash_maintainer_value

    if not name.strip():
        return None
    with get_connection() as conn:
        salt = _get_salt(conn)
    if not salt:
        return None
    return _hash_maintainer_value(name, salt)


def local_hash_many(names) -> dict[str, str]:
    """Hash several names under this installation's salt in one DB read.

    G009 used to call :func:`local_hash` per package, opening a connection
    and re-reading the salt for every record in a full-AUR sweep.  One salt
    read and one loop is the same result without the per-row connection.
    """
    from .db import get_connection
    from .db._connection import _get_salt, _hash_maintainer_value

    keys = {str(name).strip() for name in names or () if str(name).strip()}
    if not keys:
        return {}
    with get_connection() as conn:
        salt = _get_salt(conn)
    if not salt:
        return {}
    return {name: _hash_maintainer_value(name, salt) for name in keys}


def add_entry(name: str, label: str = "", path=None) -> str:
    """Add *name* to the watchlist and return its stored hash.

    The name is hashed with this installation's salt, so nothing plaintext is
    written.  Requires a seeded database: without a salt there is nothing the
    later lookup would match against.
    """
    name_hash = local_hash(name)
    if not name_hash:
        raise RuntimeError(
            "no maintainer salt is configured; seed or migrate the database "
            "before adding a watchlist entry"
        )
    target = Path(path) if path else default_path()
    data = _read(target)
    entries = [e for e in (data.get("entries") or ()) if isinstance(e, dict)]
    if not any(e.get("name_hash") == name_hash for e in entries):
        entries.append({"name_hash": name_hash, "label": label})
    data["version"] = 1
    data["entries"] = entries
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n")
    return name_hash


def add_package(name: str, label: str = "", path=None) -> str:
    """Add *name* to the watchlist's package entries and return it.

    Unlike :func:`add_entry`, no salted hash or seeded database is involved: a
    package name is already public in every record and report, so there is
    nothing to protect.
    """
    package = str(name).strip()
    if not package:
        raise ValueError("a watchlist package name cannot be empty")
    target = Path(path) if path else default_path()
    data = _read(target)
    packages = data.get("packages")
    if not isinstance(packages, dict):
        packages = {}
    packages.setdefault(package, label)
    data["version"] = 1
    data["packages"] = packages
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n")
    return package


def _db_entries(kind: str, source: str | None = None) -> dict[str, str]:
    """Return ``{value: label}`` for imported rows of *kind*.

    A database without the table (never initialised) is empty, never an
    error: like the file reader, this is a best-effort aid.
    """
    from .db import get_connection

    sql = "SELECT value, label FROM watchlist_entries WHERE kind = ?"
    params: tuple = (kind,)
    if source:
        sql += " AND source = ?"
        params = (kind, source)
    try:
        with get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
    except (sqlite3.Error, RuntimeError):
        return {}
    out: dict[str, str] = {}
    for row in rows:
        value = str(row["value"])
        if value:
            out.setdefault(value, str(row["label"] or ""))
    return out


def load_release_packages(source: str | None = None) -> dict[str, str]:
    """``{package: label}`` imported from a signed watchlist release."""
    return _db_entries("package", source)


def load_release_maintainers(source: str | None = None) -> dict[str, str]:
    """``{name_hash: label}`` imported from a signed watchlist release.

    The values are salted SHA-256 hashes, never plaintext: the release ships
    the same pseudonymous form the baseline seed does.
    """
    return _db_entries("maintainer", source)


def import_release(data: dict, source: str = "") -> dict:
    """Ingest a verified watchlist release into the database.

    *data* is the signed release document: ``packages`` (public names),
    ``maintainers`` (salted hashes), and the ``salt`` those hashes were
    built under.  The salt is handled exactly as ``db.import_seed`` handles a
    seed's: adopted when the database has none, and when a *different* salt
    is already stored the maintainer rows are skipped (they would be
    unreachable in the local hash namespace) while the packages still import.
    Idempotent per *source*: its previous rows are replaced.

    Returns import stats; raises ``ValueError`` for a document that is not an
    object.
    """
    if not isinstance(data, dict):
        raise ValueError("a watchlist release must be a JSON object")
    packages = data.get("packages")
    maintainers = data.get("maintainers")
    packages = packages if isinstance(packages, dict) else {}
    maintainers = maintainers if isinstance(maintainers, dict) else {}
    if len(packages) > MAX_WATCHLIST_ENTRIES or len(maintainers) > MAX_WATCHLIST_ENTRIES:
        raise ValueError("watchlist release exceeds the entry cap")
    release_salt = str(data.get("salt") or "").strip()
    source = str(source or data.get("source") or "").strip() or "official"

    from .db import get_connection, init_db
    from .db._connection import SEED_META_SALT_KEY, _get_salt

    init_db()
    new_packages = {
        str(name)[:MAX_WATCHLIST_LABEL_CHARS].strip():
            str(label or "")[:MAX_WATCHLIST_LABEL_CHARS]
        for name, label in packages.items()
        if str(name).strip()
    }
    new_maintainers = {
        str(name_hash)[:MAX_WATCHLIST_LABEL_CHARS].strip():
            str(label or "")[:MAX_WATCHLIST_LABEL_CHARS]
        for name_hash, label in maintainers.items()
        if str(name_hash).strip()
    }
    with get_connection() as conn:
        stored_salt = _get_salt(conn)
        adopted = bool(release_salt) and not stored_salt
        skipped = bool(stored_salt) and bool(release_salt) and stored_salt != release_salt
        if adopted:
            conn.execute(
                "INSERT OR REPLACE INTO seed_meta (key, value) VALUES (?, ?)",
                (SEED_META_SALT_KEY, release_salt),
            )
        conn.execute("DELETE FROM watchlist_entries WHERE source = ?", (source,))
        rows = [
            ("package", value, label, source)
            for value, label in new_packages.items()
        ]
        if not skipped:
            rows += [
                ("maintainer", value, label, source)
                for value, label in new_maintainers.items()
            ]
        conn.executemany(
            "INSERT OR IGNORE INTO watchlist_entries (kind, value, label, source) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    return {
        "source": source,
        "packages_imported": len(new_packages),
        "maintainers_imported": 0 if skipped else len(new_maintainers),
        "maintainers_skipped": len(new_maintainers) if skipped else 0,
        "salt_adopted": adopted,
    }
