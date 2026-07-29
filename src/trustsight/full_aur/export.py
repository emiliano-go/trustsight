"""Baseline artifact builder and importer.

The baseline artifact is a gzipped JSON file containing:
  - manifest:  builder metadata (version, corpus cutoff, tool versions)
  - profiles:  all package_profiles rows
  - snapshots: all pkgbuild_snapshots rows
  - metadata:  the full AUR metadata snapshot (as list)
  - signature: optional ed25519 detached signature (hex)

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

from ..config import load_config
from ..db import (
    get_connection,
    save_pkgbuild_snapshot,
    save_package_profile,
)
from ..db import get_db_path

log = logging.getLogger(__name__)

_ARTIFACT_VERSION = 1

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


# ---------------------------------------------------------------------------
# Reproducible serialization
# ---------------------------------------------------------------------------

def canonical_artifact_bytes(
    profiles: list[dict],
    snapshots: list[dict],
    metadata_snapshot_hash: str,
    manifest: dict,
) -> bytes:
    """Canonical JSON bytes for the signed payload.

    Identical inputs produce identical output.  The *manifest* must
    declare ``ruleset_version``, ``scorer_version``, and
    ``corpus_cutoff`` (the metadata snapshot etag used during build);
    it may contain ``created_at`` for display but this field is NOT
    covered by the reproducible contract.
    """
    payload = {
        "manifest": {
            "version": manifest.get("version", _ARTIFACT_VERSION),
            "ruleset_version": manifest.get("ruleset_version", ""),
            "scorer_version": manifest.get("scorer_version", ""),
            "corpus_cutoff": manifest.get("corpus_cutoff", ""),
        },
        "profiles": sorted(profiles, key=lambda p: p["package_name"]),
        "snapshots": sorted(snapshots, key=lambda s: s["package_name"]),
        "metadata_snapshot_hash": metadata_snapshot_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


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


def _read_artifact(path: Path) -> tuple[dict, Optional[bytes]]:
    """Read a gzipped artifact, returning (payload_dict, signature_bytes).

    If no signature is present, *signature* is None.
    """
    raw = path.read_bytes()
    try:
        data = json.loads(gzip.decompress(raw).decode("utf-8"))
    except Exception:
        data = json.loads(raw.decode("utf-8"))

    sig_hex = data.pop("signature", None)
    sig: Optional[bytes] = None
    if sig_hex is not None:
        sig = bytes.fromhex(sig_hex)
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
    db_path = get_db_path()

    with get_connection() as conn:
        profiles = [
            dict(r) for r in
            conn.execute("SELECT * FROM package_profiles ORDER BY package_name").fetchall()
        ]
        snapshots = [
            dict(r) for r in
            conn.execute("SELECT * FROM pkgbuild_snapshots ORDER BY package_name").fetchall()
        ]

    meta_path = Path("full-aur-meta.json.gz")
    metadata_list: list[dict] = []
    if meta_path.exists():
        from .metadata import load_metadata_snapshot
        loaded = load_metadata_snapshot(meta_path)
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
    canonical = canonical_artifact_bytes(profiles, snapshots, m_hash, manifest)

    artifact = {
        "signature": None,
        **json.loads(canonical),
    }

    if private_key_path:
        path = Path(private_key_path)
        if not path.exists():
            log.warning("private key not found at %s; building unsigned", private_key_path)
        else:
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

    Merges profiles, snapshots, and metadata into the local database.
    Raises ``UnsignedBaselineError`` or ``InvalidSignatureError``.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Baseline artifact not found: {path}")

    data, sig = _read_artifact(path_obj)

    version = data.get("manifest", {}).get("version", 0)
    if version != _ARTIFACT_VERSION:
        log.warning("Baseline artifact version %d != current %d; may be incompatible",
                     version, _ARTIFACT_VERSION)

    # Re-construct canonical bytes for verification
    m_hash = data.get("metadata_snapshot_hash", "")
    manifest = data.get("manifest", {})
    profiles_in = data.get("profiles", [])
    snapshots_in = data.get("snapshots", [])
    canonical = canonical_artifact_bytes(profiles_in, snapshots_in, m_hash, manifest)

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
        pubkey = pubkey_path.read_bytes()
        if not verify_artifact(canonical, sig, pubkey):
            raise InvalidSignatureError("Baseline signature verification failed.")
        log.info("signature verified")

    imported = {"profiles": 0, "snapshots": 0, "metadata_items": 0}

    for profile in profiles_in:
        save_package_profile(
            package_name=profile["package_name"],
            last_score=profile.get("last_score", 0),
            last_risk=profile.get("last_risk", ""),
        )
        imported["profiles"] += 1

    for snap in snapshots_in:
        save_pkgbuild_snapshot(
            package_name=snap["package_name"],
            pkgbuild_text=snap.get("pkgbuild_text", ""),
            version=snap.get("version", ""),
            last_modified=snap.get("last_modified", 0),
            srcinfo_text=snap.get("srcinfo_text"),
        )
        imported["snapshots"] += 1

    metadata_list = data.get("metadata_snapshot", [])
    if metadata_list:
        meta_dict = {pkg["Name"]: pkg for pkg in metadata_list}
        from .metadata import save_metadata_snapshot
        save_metadata_snapshot(meta_dict, Path("full-aur-meta.json.gz"))
        imported["metadata_items"] = len(meta_dict)

    if json_output:
        print(json.dumps(imported))
    else:
        log.info("Imported %(profiles)d profiles, %(snapshots)d snapshots, "
                 "%(metadata_items)d metadata items", imported)
