"""Baseline artifact builder and importer.

The baseline artifact is a gzipped JSON file containing:
  - manifest:  builder metadata (version, corpus cutoff, tool versions)
  - profiles:  all package_profiles rows
  - snapshots: all pkgbuild_snapshots rows
  - observations: novelty observation tables (source URLs, dependency
    names, salted maintainer hashes) plus the salt they were hashed
    under; present since artifact version 2
  - metadata:  the full AUR metadata snapshot (as list)
  - signature: optional ed25519 detached signature (hex)

Version 1 artifacts carry no ``observations`` section; they still
verify and import, just without warming the novelty priors.

Reproducibility
  ``canonical_artifact_bytes()`` produces byte-identical output from
  the same inputs regardless of build time, process, or platform.
  Signing must only cover these canonical bytes so that anyone who
  builds from the same corpus cutoff can verify the signature.
"""

import gzip
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..bounded_io import read_file_capped
from ..db import (
    get_connection,
    save_pkgbuild_snapshot,
    save_package_profile,
)

log = logging.getLogger(__name__)

_ARTIFACT_VERSION = 2

# Public key shipped with the repo.  Rotations announced in release notes.
# Loaded lazily so verification works without signing infrastructure.
_TRUSTED_PUBKEY_FILE = Path(__file__).parent / "baseline_pubkey.pem"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class UnsignedBaselineError(Exception):
    """Raised when an unsigned artifact is imported without --allow-unsigned."""


class InvalidSignatureError(Exception):
    """Raised when the artifact signature does not verify."""


class NoTrustedKeyError(Exception):
    """Raised when this build pins no distribution key to verify against.

    Distinct from InvalidSignatureError on purpose: this one means the build
    cannot check an artifact either way, and accusing a good artifact of
    being forged is worse than saying nothing.  The shipped
    ``baseline_pubkey.pem`` carries the project's pinned ed25519 distribution
    key (32 raw bytes), so a healthy build raises this only if the file is
    missing or corrupt.
    """


# ---------------------------------------------------------------------------
# Reproducible serialization
# ---------------------------------------------------------------------------

def _row_sort_key(row) -> str:
    """Sort key for a profile/snapshot row, tolerating a malformed one."""
    if isinstance(row, dict):
        return str(row.get("package_name", ""))
    return ""


def canonical_artifact_bytes(
    profiles: list[dict],
    snapshots: list[dict],
    metadata_snapshot_hash: str,
    manifest: dict,
    observations: Optional[dict] = None,
) -> bytes:
    """Canonical JSON bytes for the signed payload.

    Identical inputs produce identical output.  The *manifest* must
    declare ``ruleset_version``, ``scorer_version``, and
    ``corpus_cutoff`` (the metadata snapshot etag used during build);
    it may contain ``created_at`` for display but this field is NOT
    covered by the reproducible contract.

    *observations* (artifact version 2+) is the novelty observation
    section built by :func:`_canonical_observations`.  When None the
    key is omitted entirely, so a version 1 payload re-canonicalises
    to the exact bytes it was signed over.
    """
    payload = {
        "manifest": {
            "version": manifest.get("version", _ARTIFACT_VERSION),
            "ruleset_version": manifest.get("ruleset_version", ""),
            "scorer_version": manifest.get("scorer_version", ""),
            "corpus_cutoff": manifest.get("corpus_cutoff", ""),
        },
        # Sorted defensively: this function is also called on rows read from
        # an untrusted artifact, where a row may be missing its name or not
        # be a mapping at all.  That is a malformed artifact to be reported
        # by the import, not a KeyError raised from inside the hasher.
        "profiles": sorted(profiles, key=_row_sort_key),
        "snapshots": sorted(snapshots, key=_row_sort_key),
        "metadata_snapshot_hash": metadata_snapshot_hash,
    }
    if observations is not None:
        payload["observations"] = observations
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Novelty observation rows (artifact version 2)
#
# These mirror the seed importer's tables and merge semantics exactly
# (``_import_v2_source_urls`` / ``_import_v2_dependency_names`` /
# ``_import_v2_maintainers`` in ``db.py``): source URLs ignore duplicates,
# dependency names add their observation counts onto any existing row, and
# maintainer rows are inserted only when the (name_hash, email_hash) pair
# is absent, under whichever salt the local database already uses.
# ---------------------------------------------------------------------------

def _canonical_observations(
    source_urls: list[dict],
    dependency_names: list[dict],
    maintainers: list[dict],
    salt: Optional[str],
) -> Optional[dict]:
    """Normalise observation rows into a deterministic, signable section.

    Returns None when there is nothing to carry (a builder that never
    saw the observation tables produces a version 1-shaped payload).
    Rows read back from an untrusted artifact may be ragged; each
    normaliser tolerates that so a bad row is skipped at import time,
    not a TypeError raised inside the hasher.
    """
    urls = sorted(
        (
            {
                "url": str(row.get("url", "")),
                "first_seen_package_id": row.get("first_seen_package_id") or 0,
                "first_seen_globally_timestamp": row.get("first_seen_globally_timestamp"),
                "total_uses": row.get("total_uses", 1),
                "last_seen_timestamp": row.get("last_seen_timestamp"),
            }
            for row in source_urls if isinstance(row, dict)
        ),
        key=lambda r: r["url"],
    )
    deps = sorted(
        (
            {
                "name": str(row.get("name", "")),
                "first_seen_globally_timestamp": row.get("first_seen_globally_timestamp"),
                "observation_count": int(row.get("observation_count") or 0),
            }
            for row in dependency_names if isinstance(row, dict)
        ),
        key=lambda r: r["name"],
    )
    maints = sorted(
        (
            {
                "name_hash": str(row.get("name_hash", "")),
                "email_hash": row.get("email_hash"),
                "first_seen": row.get("first_seen"),
                "package_count": int(row.get("package_count") or 0),
                "packages": row.get("packages"),
                "source": row.get("source", "seed"),
            }
            for row in maintainers if isinstance(row, dict)
        ),
        key=lambda r: (r["name_hash"], r["email_hash"] or ""),
    )
    if not (urls or deps or maints):
        return None
    return {
        "salt": salt,
        "source_urls": urls,
        "dependency_names": deps,
        "maintainers": maints,
    }


# ---------------------------------------------------------------------------
# Signing  (ed25519, feature-gated on cryptography)
# ---------------------------------------------------------------------------

_HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _HAS_CRYPTO = True
except ImportError:
    log.warning("cryptography library not available; signing disabled")


def sign_artifact(canonical_bytes: bytes, private_key_path: Path) -> bytes:
    """Sign canonical artifact bytes with an ed25519 key.

    Returns the detached signature bytes (64 bytes).
    Raises ``RuntimeError`` if cryptography is not installed.
    """
    if not _HAS_CRYPTO:
        raise RuntimeError(
            "cryptography library required for signing. "
            "Install with: pip install cryptography"
        )
    key = Ed25519PrivateKey.from_private_bytes(private_key_path.read_bytes())
    return key.sign(canonical_bytes)


def verify_artifact(canonical_bytes: bytes, signature: bytes, pubkey: bytes) -> bool:
    """Verify an ed25519 detached signature.

    Returns True on success, False on failure or if cryptography
    is unavailable (verification always requires the library).
    """
    if not _HAS_CRYPTO:
        log.error("cryptography library required for signature verification")
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, canonical_bytes)
        return True
    except Exception:
        return False


#: An ed25519 public key is exactly 32 raw bytes.  Anything else in the
#: pinned key file is not a key, whatever it is.
_ED25519_PUBKEY_BYTES = 32

#: Ceiling on a baseline artifact as it sits on disk, applied before the
#: gzip cap and before the signature check.  A corpus baseline is profiles
#: and snapshots for the AUR; this is well above a real one.
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


def _load_trusted_pubkey(path: Path) -> bytes:
    """The pinned distribution key, or a refusal that says which failure it is.

    A13 claims signed baselines are verified against a pinned key.  Until a
    key pair is actually generated for distribution that claim describes a
    code path, not a working import, and the operator is entitled to be told
    which of the two they are hitting.
    """
    raw = path.read_bytes()
    if len(raw) != _ED25519_PUBKEY_BYTES:
        raise NoTrustedKeyError(
            f"No distribution key is pinned in this build: {path} holds "
            f"{len(raw)} bytes, not a {_ED25519_PUBKEY_BYTES}-byte ed25519 "
            "public key.  Signed baseline import is unavailable until a key "
            "is shipped; this says nothing about whether your artifact is "
            "genuine.  A baseline you built yourself imports with "
            "--allow-unsigned."
        )
    return raw


class MalformedBaselineError(Exception):
    """Raised when an artifact cannot be parsed as one."""


def _read_artifact(path: Path) -> tuple[dict, Optional[bytes]]:
    """Read a gzipped artifact, returning (payload_dict, signature_bytes).

    If no signature is present, *signature* is None.  Decompression is
    capped: an artifact arrives from wherever the user got it, and a gzip
    member that claims to be terabytes costs nothing to write and the whole
    machine to expand.
    """
    from .metadata import gunzip_capped

    # The decompression below is capped; this is the read that feeds it.
    # Without a bound here the whole compressed artifact is materialised
    # before ``gunzip_capped`` ever sees it, so the cap guards the
    # expansion and nothing guards the file.
    raw = read_file_capped(path, MAX_ARTIFACT_BYTES, f"baseline artifact {path.name}")
    try:
        text = gunzip_capped(raw).decode("utf-8")
    except OSError:  # not gzip - a plain JSON artifact
        text = raw.decode("utf-8", errors="strict")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise MalformedBaselineError("artifact is not a JSON object")

    sig_hex = data.pop("signature", None)
    sig: Optional[bytes] = None
    if sig_hex is not None:
        if not isinstance(sig_hex, str):
            raise MalformedBaselineError("signature field is not a hex string")
        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError as exc:
            raise MalformedBaselineError(f"signature is not hex: {exc}") from exc
    return data, sig


def _metadata_snapshot_hash(metadata_list: list[dict]) -> str:
    """Stable hash of the metadata snapshot list."""
    raw = json.dumps(metadata_list, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_artifact(
    export_path: str,
    private_key_path: Optional[str] = None,
    corpus_cutoff: str = "",
) -> None:
    """Assemble and optionally sign the baseline artifact."""
    log.info("Building baseline artifact ...")

    with get_connection() as conn:
        profiles = [
            dict(r) for r in
            conn.execute("SELECT * FROM package_profiles ORDER BY package_name").fetchall()
        ]
        snapshots = [
            dict(r) for r in
            conn.execute("SELECT * FROM pkgbuild_snapshots ORDER BY package_name").fetchall()
        ]
        from ..db import _get_salt
        obs_salt = _get_salt(conn)
        obs_source_urls = [
            dict(r) for r in conn.execute(
                "SELECT url, first_seen_package_id, first_seen_globally_timestamp, "
                "total_uses, last_seen_timestamp FROM source_urls ORDER BY url"
            ).fetchall()
        ]
        obs_dependency_names = [
            dict(r) for r in conn.execute(
                "SELECT name, first_seen_globally_timestamp, observation_count "
                "FROM dependency_names ORDER BY name"
            ).fetchall()
        ]
        obs_maintainers = [
            dict(r) for r in conn.execute(
                "SELECT name_hash, email_hash, first_seen, package_count, "
                "packages, source FROM maintainers_hashed "
                "ORDER BY name_hash, email_hash"
            ).fetchall()
        ]

    observations = _canonical_observations(
        obs_source_urls, obs_dependency_names, obs_maintainers, obs_salt,
    )

    from .metadata import default_metadata_path
    meta_path = default_metadata_path()
    metadata_list: list[dict] = []
    if meta_path.exists():
        from .metadata import load_metadata
        loaded = load_metadata(meta_path)
        if loaded:
            metadata_list = list(loaded.values())

    from .. import __version__ as _ver
    # This import accesses importlib.metadata so it's lazy
    manifest = {
        "version": _ARTIFACT_VERSION,
        "ruleset_version": _ver,
        "scorer_version": _ver,
        "corpus_cutoff": corpus_cutoff,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    m_hash = _metadata_snapshot_hash(metadata_list)
    canonical = canonical_artifact_bytes(
        profiles, snapshots, m_hash, manifest, observations=observations,
    )

    artifact = {
        "signature": None,
        **json.loads(canonical),
    }

    if private_key_path:
        path = Path(private_key_path)
        if not path.exists():
            # A requested signature is part of the contract: the artifact
            # cannot be produced as asked, so failing loudly beats shipping
            # an artifact the operator believes is signed.
            raise FileNotFoundError(
                f"signing key not found at {private_key_path}; refusing to "
                "build an artifact the caller asked to sign. Run the export "
                "without --sign for an unsigned local artifact."
            )
        sig = sign_artifact(canonical, path)
        artifact["signature"] = sig.hex()
        log.info("artifact signed with %s", private_key_path)

    # Include metadata outside the signed payload (it is hashed, not embedded)
    artifact["metadata_snapshot"] = metadata_list

    path = Path(export_path)
    raw = json.dumps(artifact, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    compressed = gzip.compress(raw)
    path.write_bytes(compressed)
    log.info("Baseline artifact written to %s (%d bytes, signed=%s)",
             export_path, len(compressed), bool(private_key_path))


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

def import_baseline(
    path: str,
    json_output: bool = False,
    allow_unsigned: bool = False,
) -> None:
    """Verify and import a signed baseline artifact.

    Merges profiles, snapshots, the metadata snapshot, and (version 2
    artifacts) the novelty observation tables into the local database.
    Raises ``UnsignedBaselineError``, ``NoTrustedKeyError`` or
    ``InvalidSignatureError``.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Baseline artifact not found: {path}")
    if not path_obj.is_file():
        raise ValueError(f"Baseline artifact is not a regular file: {path}")

    data, sig = _read_artifact(path_obj)

    version = data.get("manifest", {}).get("version", 0)
    if version not in (1, _ARTIFACT_VERSION):
        log.warning("Baseline artifact version %d != current %d; may be incompatible",
                     version, _ARTIFACT_VERSION)

    # Re-construct canonical bytes for verification.  A version 1
    # artifact has no ``observations`` section; passing None keeps the
    # key out so the re-canonicalised bytes match what was signed.
    m_hash = data.get("metadata_snapshot_hash", "")
    manifest = data.get("manifest", {})
    profiles_in = data.get("profiles", [])
    snapshots_in = data.get("snapshots", [])
    observations_in = data.get("observations")
    canonical = canonical_artifact_bytes(
        profiles_in, snapshots_in, m_hash, manifest,
        observations=observations_in if isinstance(observations_in, dict) else None,
    )

    if sig is None:
        if not allow_unsigned:
            raise UnsignedBaselineError(
                "Refusing to import unsigned baseline.  An unsigned corpus artifact "
                "cannot be distinguished from a tampered one.  Use --allow-unsigned "
                "for a baseline you built yourself on this machine."
            )
        log.warning("importing UNSIGNED baseline; local builds only, never distribute")
    else:
        pubkey_path = _TRUSTED_PUBKEY_FILE
        if not pubkey_path.exists():
            log.error("trusted public key not found at %s; refusing import", pubkey_path)
            raise FileNotFoundError(f"trusted public key not found: {pubkey_path}")
        pubkey = _load_trusted_pubkey(pubkey_path)
        if not verify_artifact(canonical, sig, pubkey):
            raise InvalidSignatureError("Baseline signature verification failed.")
        # The manifest is inside the signed bytes, so this cannot be a
        # forgery; it catches a publish job that signed with a key the
        # release does not pin, which is the mistake rotation makes.
        named = str(manifest.get("distribution_pubkey", "")).strip().lower()
        if named and named != pubkey.hex():
            raise InvalidSignatureError(
                "The signed manifest names a different distribution key than "
                "the one this build pins; refusing to import. Re-pin the key "
                "or fetch a baseline signed with it."
            )
        log.info("signature verified")

    imported = {"profiles": 0, "snapshots": 0, "metadata_items": 0,
                "packages_warmed": 0, "source_urls": 0, "dependency_names": 0,
                "maintainers": 0}

    # A13 reports the shape of what a baseline did rather than warning on
    # it.  A threshold on "novelty dropped across many packages" would fire
    # on the success case: reducing novelty across many packages is a
    # baseline's entire function.  So state the delta as a fact and let the
    # operator judge.
    from ..db import get_package_profile

    had_history = {
        profile["package_name"] for profile in profiles_in
        if isinstance(profile, dict) and isinstance(profile.get("package_name"), str)
        and get_package_profile(profile["package_name"]) is not None
    }

    # A row without a name is not a row.  Skipping is right where raising
    # would be wrong: the artifact is signed, so a malformed entry is a
    # builder bug, and losing one profile must not lose the import.
    for profile in profiles_in:
        if not isinstance(profile, dict) or not isinstance(
            profile.get("package_name"), str
        ):
            log.warning("skipping baseline profile without a package name")
            continue
        try:
            save_package_profile(
                package_name=profile["package_name"],
                last_score=profile.get("last_score", 0),
                last_risk=profile.get("last_risk", ""),
            )
        except ValueError as exc:
            # A reserved name.  Same treatment as a row with no name: one
            # bad entry must not abort an otherwise good import.
            log.warning("skipping baseline profile: %s", exc)
            continue
        imported["profiles"] += 1

    for snap in snapshots_in:
        if not isinstance(snap, dict) or not isinstance(
            snap.get("package_name"), str
        ):
            log.warning("skipping baseline snapshot without a package name")
            continue
        try:
            save_pkgbuild_snapshot(
                package_name=snap["package_name"],
                pkgbuild_text=snap.get("pkgbuild_text", ""),
                version=snap.get("version", ""),
                last_modified=snap.get("last_modified", 0),
                srcinfo_text=snap.get("srcinfo_text"),
            )
        except ValueError as exc:
            log.warning("skipping baseline snapshot: %s", exc)
            continue
        imported["snapshots"] += 1

    metadata_list = data.get("metadata_snapshot", [])
    if metadata_list:
        # The metadata rides *outside* the signed payload - only its hash is
        # signed - so without this check a validly signed artifact could be
        # re-published with an attacker's entire AUR metadata snapshot
        # attached: maintainers, versions, dependency edges, everything
        # discovery, H045/H052/H064 and `corpus pivot` read.  The signature
        # would still verify.  Recompute and compare, and refuse on
        # mismatch even for an unsigned import: a hash that does not match
        # its own payload means the artifact is damaged either way.
        actual = _metadata_snapshot_hash(metadata_list)
        if actual != m_hash:
            raise InvalidSignatureError(
                "Baseline metadata does not match the signed hash "
                f"(expected {m_hash[:16]}..., got {actual[:16]}...)."
            )
        meta_dict = {
            pkg["Name"]: pkg for pkg in metadata_list
            if isinstance(pkg, dict) and isinstance(pkg.get("Name"), str)
        }
        from .metadata import default_metadata_path, save_metadata
        save_metadata(meta_dict, default_metadata_path())
        imported["metadata_items"] = len(meta_dict)

    if isinstance(observations_in, dict):
        imported.update(_import_observations(observations_in))

    imported["packages_warmed"] = imported["profiles"] - len(had_history)

    if json_output:
        print(json.dumps(imported))
    else:
        log.info("Imported %(profiles)d profiles, %(snapshots)d snapshots, "
                 "%(metadata_items)d metadata items, %(source_urls)d new source "
                 "URLs, %(dependency_names)d dependency names and "
                 "%(maintainers)d maintainer hashes", imported)
        # The number that matters to a reader: how much of the corpus this
        # artifact just moved from no-history to warm.
        log.info(
            "%d package(s) moved from no-history to warm; novelty signals on "
            "those will be quieter from now on",
            imported["packages_warmed"],
        )


def _import_observations(observations_in: dict) -> dict:
    """Merge a version 2 observation section into the local database.

    The merge semantics are the seed importer's: source URLs ignore rows
    already present, dependency names add their counts onto the existing
    row, and maintainer rows are inserted only when their
    (name_hash, email_hash) pair is new, in the local salt's namespace.
    Like the seed importer, a stored salt wins over a foreign artifact
    salt and the incoming maintainer rows are skipped rather than
    orphaned (the stored salt is the namespace every existing row lives
    in; replacing it would re-read everything as first-seen).
    """
    from ..db import (
        SEED_META_HASH_ALGORITHM_KEY,
        SEED_META_SALT_KEY,
        _get_salt,
        get_connection,
    )

    counts = {"source_urls": 0, "dependency_names": 0, "maintainers": 0}
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )
        before = conn.execute(
            "SELECT COUNT(*) AS n FROM source_urls"
        ).fetchone()["n"]

        url_rows = [
            (
                row.get("url"),
                row.get("first_seen_package_id") or 0,
                row.get("first_seen_globally_timestamp"),
                row.get("total_uses", 1),
                row.get("last_seen_timestamp"),
            )
            for row in observations_in.get("source_urls", [])
            if isinstance(row, dict) and isinstance(row.get("url"), str)
        ]
        if url_rows:
            # INSERT OR IGNORE, exactly as the seed importer: an existing
            # URL keeps its local first-seen and use history.
            conn.executemany(
                """INSERT OR IGNORE INTO source_urls
                   (url, first_seen_package_id, first_seen_globally_timestamp,
                    total_uses, last_seen_timestamp)
                   VALUES (?, ?, ?, ?, ?)""",
                url_rows,
            )
        counts["source_urls"] = (
            conn.execute("SELECT COUNT(*) AS n FROM source_urls").fetchone()["n"]
            - before
        )

        dep_rows = [
            (
                row.get("name"),
                row.get("first_seen_globally_timestamp"),
                int(row.get("observation_count") or 0),
            )
            for row in observations_in.get("dependency_names", [])
            if isinstance(row, dict) and isinstance(row.get("name"), str)
        ]
        if dep_rows:
            # Counts accumulate onto the existing row, as the seed importer
            # does; a baseline assert observations, it never rewrites them.
            conn.executemany(
                """INSERT INTO dependency_names
                   (name, first_seen_globally_timestamp, observation_count)
                   VALUES (?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                       observation_count = observation_count + excluded.observation_count""",
                dep_rows,
            )
            counts["dependency_names"] = len(dep_rows)

        maint_rows = [
            (
                row.get("name_hash"),
                row.get("email_hash"),
                row.get("first_seen"),
                int(row.get("package_count") or 0),
                row.get("packages"),
                row.get("source", "seed"),
            )
            for row in observations_in.get("maintainers", [])
            if isinstance(row, dict) and isinstance(row.get("name_hash"), str)
        ]
        if maint_rows:
            stored_salt = _get_salt(conn)
            artifact_salt = observations_in.get("salt")
            skip_maintainers = (
                stored_salt is not None
                and artifact_salt is not None
                and stored_salt != artifact_salt
            )
            if skip_maintainers:
                log.warning(
                    "Baseline was hashed under a different salt; keeping the "
                    "stored salt and skipping its maintainer rows to preserve "
                    "local maintainer history."
                )
            else:
                if stored_salt is None and isinstance(artifact_salt, str) and artifact_salt:
                    # No local namespace yet: adopt the artifact's salt so
                    # the rows it carries are reachable, same as a first
                    # seed import.
                    conn.execute(
                        """INSERT OR REPLACE INTO seed_meta (key, value)
                           VALUES (?, ?)""",
                        (SEED_META_SALT_KEY, artifact_salt),
                    )
                    conn.execute(
                        """INSERT OR REPLACE INTO seed_meta (key, value)
                           VALUES (?, ?)""",
                        (SEED_META_HASH_ALGORITHM_KEY, "sha256"),
                    )
                # Not INSERT OR IGNORE: rows carry a NULL email_hash and
                # SQLite treats NULLs as distinct in a primary key, so the
                # ignore never fires and a re-import duplicates every row.
                conn.executemany(
                    """INSERT INTO maintainers_hashed
                       (name_hash, email_hash, first_seen, package_count,
                        packages, source)
                       SELECT ?, ?, ?, ?, ?, ?
                       WHERE NOT EXISTS (
                           SELECT 1 FROM maintainers_hashed
                           WHERE name_hash = ? AND email_hash IS ?
                       )""",
                    [row + (row[0], row[1]) for row in maint_rows],
                )
                counts["maintainers"] = len(maint_rows)
        conn.commit()
    return counts
