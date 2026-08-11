"""IOC Federation baseline loader and matcher (v0.12.0 spec §2).

A baseline is a directory containing:

  - manifest.json   metadata and Ed25519 signature (hex)
  - iocs.jsonl      one JSON object per line, each an indicator entry

The signature covers ``manifest.json`` concatenated with ``iocs.jsonl``,
so the signed payload is byte-for-byte the files the operator can inspect.
Baselines are additive and idempotent per source: importing a baseline for
``source`` replaces all rows for that source but leaves other sources and
expired rows untouched.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .db import get_connection

import sqlite3

log = logging.getLogger(__name__)

# Ed25519 verification uses the cryptography library, which is a project
# dependency.  Gate it anyway so a minimal install degrades gracefully.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - defensive import guard
    _HAS_CRYPTO = False


_IOC_TYPES = frozenset({"domain", "hash", "package"})

_HASH_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class UnsignedBaselineError(Exception):
    """Raised when a baseline is unsigned and ``allow_unsigned`` is False."""


class InvalidSignatureError(Exception):
    """Raised when the Ed25519 signature does not verify."""


class MalformedBaselineError(Exception):
    """Raised when the baseline files cannot be parsed."""


@dataclass(frozen=True)
class BaselineManifest:
    """Parsed ``manifest.json`` for an IOC baseline."""

    version: int = 1
    source: str = ""
    created_at: str = ""
    expires_at: str = ""
    signature: str = ""
    public_key: str = ""
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class IocEntry:
    """One indicator row as stored in and loaded from the database."""

    type: str
    value: str
    source: str
    confidence: str = ""
    provenance: str = ""
    campaign: str = ""
    added: str = ""
    expires_at: str = ""


@dataclass(frozen=True)
class IocMatch:
    """A single match against an active IOC entry."""

    type: str
    value: str
    source: str
    confidence: str = ""
    provenance: str = ""
    campaign: str = ""
    added: str = ""
    surface: str = ""
    line: int | None = None
    expired: bool = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_hex_digest(value: str) -> bool:
    if not value:
        return False
    return len(value) in _HASH_LENGTHS and _HEX_RE.match(value) is not None


def _normalize_value(type_: str, value: str) -> str | None:
    """Return the canonical form of *value* for *type_*, or None."""
    value = str(value).strip().strip("'\"")
    if not value:
        return None
    if type_ == "hash":
        lowered = value.lower()
        if not _is_hex_digest(lowered):
            return None
        return lowered
    if type_ == "domain":
        return _normalize_domain(value)
    if type_ == "package":
        return value.lower()
    return None


def _normalize_domain(value: str) -> str | None:
    """Return the registered domain for *value*, or the exact host if none."""
    value = value.lower().rstrip(".")
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    if not value:
        return None
    try:
        # IDNA/punycode so unicode and xn-- forms collapse to one value.
        ascii_host = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        ascii_host = value
    try:
        extracted = _tldextract(ascii_host)
    except Exception:
        extracted = None
    if extracted and extracted.domain and extracted.suffix:
        registered = f"{extracted.domain}.{extracted.suffix}"
        return registered.lower()
    # Fallback for hosts on suffixes tldextract does not know: use the last
    # two labels as the canonical registered domain so subdomains still match.
    labels = ascii_host.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:]).lower()
    return ascii_host


_extractor = None


def _tldextract(host: str):
    """Lazy, offline tldextract instance mirroring buckets.py."""
    global _extractor
    if _extractor is None:
        import tldextract

        _extractor = tldextract.TLDExtract(suffix_list_urls=())
    return _extractor(host)


def _load_text(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    return path.read_bytes()


def _load_manifest(path: Path) -> BaselineManifest:
    """Parse ``manifest.json`` into a :class:`BaselineManifest`."""
    raw = _load_text(path)
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise MalformedBaselineError(f"manifest.json is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise MalformedBaselineError("manifest.json must be a JSON object")
    return BaselineManifest(
        version=int(data.get("version", 1)),
        source=str(data.get("source", "")),
        created_at=str(data.get("created_at", "")),
        expires_at=str(data.get("expires_at", "")),
        signature=str(data.get("signature", "")),
        public_key=str(data.get("public_key", "")),
        extra={k: v for k, v in data.items() if k not in {
            "version", "source", "created_at", "expires_at",
            "signature", "public_key",
        }},
    )


def _load_iocs(path: Path) -> list[IocEntry]:
    """Parse ``iocs.jsonl`` into :class:`IocEntry` rows."""
    raw = _load_text(path)
    entries: list[IocEntry] = []
    for lineno, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise MalformedBaselineError(
                f"iocs.jsonl line {lineno} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise MalformedBaselineError(f"iocs.jsonl line {lineno} is not an object")
        type_ = str(row.get("type", "")).strip().lower()
        if type_ not in _IOC_TYPES:
            log.warning("iocs.jsonl line %d: unknown type %r; skipping", lineno, row.get("type"))
            continue
        value = _normalize_value(type_, row.get("value", ""))
        if value is None:
            log.warning(
                "iocs.jsonl line %d: unusable value %r for type %s; skipping",
                lineno, row.get("value"), type_,
            )
            continue
        source = str(row.get("source", "")).strip()
        if not source:
            log.warning("iocs.jsonl line %d: missing source; skipping", lineno)
            continue
        entries.append(
            IocEntry(
                type=type_,
                value=value,
                source=source,
                confidence=str(row.get("confidence", "")).strip().lower(),
                provenance=str(row.get("provenance", "")),
                campaign=str(row.get("campaign", "")),
                added=str(row.get("added", "")),
                expires_at=str(row.get("expires_at", "")),
            )
        )
    return entries


def _verify_signature(
    manifest_path: Path,
    iocs_path: Path,
    signature_hex: str,
    public_key_hex: str,
) -> bool:
    """Verify the Ed25519 signature over ``manifest.json || iocs.jsonl``.

    The signed manifest is the canonical JSON of ``manifest.json`` with the
    ``signature`` field removed, so the payload is stable regardless of how
    the signed manifest file was pretty-printed.

    Returns ``True`` on success, ``False`` on any verification failure.
    """
    if not _HAS_CRYPTO:
        log.error("cryptography library not available; cannot verify signature")
        return False
    if not signature_hex:
        return False
    if not public_key_hex:
        return False
    try:
        signature = bytes.fromhex(signature_hex)
        pubkey = bytes.fromhex(public_key_hex)
    except ValueError:
        return False
    manifest = _load_manifest(manifest_path)
    manifest_dict = {
        "version": manifest.version,
        "source": manifest.source,
        "created_at": manifest.created_at,
        "expires_at": manifest.expires_at,
        "signature": "",
        "public_key": manifest.public_key,
        **manifest.extra,
    }
    manifest_bytes = json.dumps(
        manifest_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    payload = manifest_bytes + _load_text(iocs_path)
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, payload)
        return True
    except Exception:
        return False


def import_baseline(
    path: str | Path,
    source_name: str | None = None,
    allow_unsigned: bool = False,
) -> dict:
    """Import an IOC federation baseline directory.

    *path* must contain ``manifest.json`` and ``iocs.jsonl``.  If
    *source_name* is given it overrides ``manifest.source``.  The import is
    idempotent per source: existing rows for the source are deleted and
    replaced with the new baseline.  Expired rows from previous imports are
    kept.

    Returns a dict with ``source``, ``entries_imported``,
    ``entries_skipped``, and ``verified``.
    """
    base = Path(path)
    if not base.is_dir():
        raise FileNotFoundError(f"Baseline directory not found: {base}")
    manifest_path = base / "manifest.json"
    iocs_path = base / "iocs.jsonl"

    manifest = _load_manifest(manifest_path)
    entries = _load_iocs(iocs_path)

    signature_hex = manifest.signature
    public_key_hex = manifest.public_key
    verified = False

    if signature_hex and public_key_hex:
        verified = _verify_signature(
            manifest_path, iocs_path, signature_hex, public_key_hex
        )
        if not verified and not allow_unsigned:
            raise InvalidSignatureError(
                "Baseline signature verification failed. "
                "Use --allow-unsigned only for a baseline you trust locally."
            )
        if not verified and allow_unsigned:
            log.warning("signature verification failed; importing unsigned as requested")
    elif not allow_unsigned:
        raise UnsignedBaselineError(
            "Baseline is not signed. Use --allow-unsigned for local-only baselines."
        )
    else:
        log.warning("importing unsigned baseline; local builds only, never distribute")

    source = (source_name or manifest.source or "unknown").strip()
    if not source or source == "unknown":
        log.warning("baseline has no source name; using directory name")
        source = base.name or "unknown"

    now = _now_iso()
    with get_connection() as conn:
        conn.execute("DELETE FROM ioc_entries WHERE source = ?", (source,))
        for entry in entries:
            conn.execute(
                """INSERT INTO ioc_entries
                   (type, value, source, confidence, provenance, campaign,
                    added, expires_at, imported_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.type,
                    entry.value,
                    source,
                    entry.confidence,
                    entry.provenance,
                    entry.campaign,
                    entry.added,
                    entry.expires_at,
                    now,
                ),
            )
        conn.commit()

    return {
        "source": source,
        "entries_imported": len(entries),
        "entries_skipped": 0,
        "verified": verified,
    }


def _row_to_entry(row: sqlite3.Row) -> IocEntry:
    return IocEntry(
        type=row["type"],
        value=row["value"],
        source=row["source"],
        confidence=row["confidence"] or "",
        provenance=row["provenance"] or "",
        campaign=row["campaign"] or "",
        added=row["added"] or "",
        expires_at=row["expires_at"] or "",
    )


def _is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    try:
        return datetime.fromisoformat(expires_at) < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False


def active_iocs(source: str | None = None, expired: bool = False) -> list[IocEntry]:
    """Return active IOC entries, optionally filtered by source.

    ``expired=True`` includes entries whose ``expires_at`` has passed.
    """
    query = "SELECT * FROM ioc_entries"
    params: tuple = ()
    if source:
        query += " WHERE source = ?"
        params = (source,)
    with get_connection() as conn:
        try:
            rows = conn.execute(query, params).fetchall()
        except sqlite3.OperationalError:
            return []
    entries = [_row_to_entry(r) for r in rows]
    if not expired:
        entries = [e for e in entries if not _is_expired(e.expires_at)]
    return entries


def all_ioc_sources() -> list[str]:
    """Return the distinct source names currently stored."""
    with get_connection() as conn:
        try:
            rows = conn.execute(
                "SELECT DISTINCT source FROM ioc_entries ORDER BY source"
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    return [r["source"] for r in rows]


def match_ioc(type_: str, value: str) -> list[IocMatch]:
    """Return all active IOC entries matching (*type_*, *value*).

    Domain matching uses the registered domain, hash matching is exact and
    case-insensitive, package matching is exact and case-insensitive.
    """
    normalized = _normalize_value(type_, value)
    if normalized is None:
        return []

    query = "SELECT * FROM ioc_entries WHERE type = ? AND value = ?"
    params = (type_, normalized)
    with get_connection() as conn:
        try:
            rows = conn.execute(query, params).fetchall()
        except sqlite3.OperationalError:
            return []

    matches: list[IocMatch] = []
    for row in rows:
        entry = _row_to_entry(row)
        expired = _is_expired(entry.expires_at)
        matches.append(
            IocMatch(
                type=entry.type,
                value=entry.value,
                source=entry.source,
                confidence=entry.confidence,
                provenance=entry.provenance,
                campaign=entry.campaign,
                added=entry.added,
                surface="",
                line=None,
                expired=expired,
            )
        )
    return matches


def _domain_variants(host: str) -> set[str]:
    """Candidate domain forms to query for a host match.

    Includes the registered domain and the exact host so an indicator written
    as a full hostname still matches.
    """
    variants: set[str] = set()
    normalized = _normalize_domain(host)
    if normalized:
        variants.add(normalized)
    exact = host.lower().rstrip(".").split("://")[-1].split("/")[0].split("@")[-1].split(":")[0]
    if exact:
        try:
            exact = exact.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            pass
        variants.add(exact)
    return variants


def match_domain(host: str) -> list[IocMatch]:
    """Return active domain IOC matches for *host*."""
    matches: list[IocMatch] = []
    seen: set[tuple[str, str]] = set()
    for variant in _domain_variants(host):
        for m in match_ioc("domain", variant):
            key = (m.value, m.source)
            if key in seen:
                continue
            seen.add(key)
            matches.append(m)
    return matches


def match_hash(digest: str) -> list[IocMatch]:
    """Return active hash IOC matches for *digest*."""
    return match_ioc("hash", digest)


def match_package(name: str) -> list[IocMatch]:
    """Return active package IOC matches for *name*."""
    return match_ioc("package", name)
