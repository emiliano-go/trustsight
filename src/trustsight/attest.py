"""Deterministic tree attestations.

The attestation is a digest of the reviewed source tree. It is not a build:
TrustSight never runs ``makepkg``. The gate can record the tree it inspected
and a later check can refuse a tree whose bytes changed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import tempfile
from pathlib import Path

__all__ = [
    "ATTEST_VERSION", "check_tree", "digest_tree", "unpinned_sources",
    "write_attestation",
]

ATTEST_VERSION = 1
MAX_FILES = 200_000
MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_ATTESTATION_BYTES = 1024 * 1024
_SKIP_DIRS = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache"})
_VCS_PREFIXES = ("git+", "svn+", "hg+", "bzr+", "cvs+", "darcs+")
_CHECKSUM_ARRAYS = (
    "sha256sums", "sha512sums", "sha384sums", "sha224sums", "sha1sums",
    "b2sums", "md5sums", "cksums",
)


class AttestError(RuntimeError):
    """The tree could not be attested or the attestation does not match."""


def _raw_array(text: str, key: str) -> tuple[str, ...]:
    """An array declaration with empty elements preserved."""
    match = re.search(rf"(?ms)^\s*{re.escape(key)}\s*=\s*\((.*?)\)", text)
    if not match:
        return ()
    try:
        return tuple(shlex.split(match.group(1), comments=False, posix=True))
    except ValueError:
        return ()


def _records(root: Path):
    def walk_error(exc: OSError) -> None:
        raise AttestError(f"could not walk the source tree: {exc}") from exc

    files = 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(
            root, followlinks=False, onerror=walk_error):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            try:
                stat = path.stat()
            except OSError as exc:
                raise AttestError(f"could not stat {rel}: {exc}") from exc
            size = stat.st_size
            executable = bool(stat.st_mode & 0o111)
            files += 1
            total += size
            if files > MAX_FILES or total > MAX_BYTES:
                raise AttestError("source tree exceeds the attestation bounds")
            digest = hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
            except OSError as exc:
                raise AttestError(f"could not read {rel}: {exc}") from exc
            try:
                after = path.stat()
            except OSError as exc:
                raise AttestError(f"could not stat {rel}: {exc}") from exc
            if (after.st_size, after.st_mtime_ns) != (stat.st_size, stat.st_mtime_ns):
                raise AttestError(f"{rel} changed while it was being attested")
            yield rel, size, executable, digest.hexdigest()


def digest_tree(root: str | Path) -> dict:
    path = Path(root)
    if not path.is_dir():
        raise AttestError(f"not a directory: {path}")
    digest = hashlib.sha256()
    count = 0
    total = 0
    for rel, size, executable, file_digest in _records(path):
        digest.update(rel.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        digest.update(b"1" if executable else b"0")
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        count += 1
        total += size
    return {
        "version": ATTEST_VERSION,
        "algorithm": "sha256",
        "digest": "sha256:" + digest.hexdigest(),
        "files": count,
        "bytes": total,
    }


def write_attestation(root: str | Path, output: str | Path) -> dict:
    payload = digest_tree(root)
    payload["unpinned_sources"] = unpinned_sources(root)
    target = Path(output)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass
    return payload


def check_tree(root: str | Path, attestation: str | Path) -> dict:
    source = Path(attestation)
    try:
        if source.stat().st_size > MAX_ATTESTATION_BYTES:
            raise AttestError("attestation document is too large")
    except OSError as exc:
        raise AttestError(f"could not read attestation: {exc}") from exc
    try:
        expected = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise AttestError(f"could not read attestation: {exc}") from exc
    if not isinstance(expected, dict) or expected.get("version") != ATTEST_VERSION:
        raise AttestError("unsupported attestation document")
    actual = digest_tree(root)
    if expected.get("digest") != actual["digest"]:
        raise AttestError(
            f"tree digest changed: expected {expected.get('digest')}, "
            f"got {actual['digest']}")
    return actual


def unpinned_sources(root: str | Path) -> list[dict[str, str]]:
    """VCS/SKIP/unchecksummed sources declared by a tree's PKGBUILD.

    This is a bounded, read-only convenience for the attestation consumer. It
    never fetches anything and never treats a malformed recipe as a finding.
    """
    path = Path(root) / "PKGBUILD"
    try:
        if path.stat().st_size > 1024 * 1024:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        from .recipedoc import parse_recipe

        recipe = parse_recipe(text)
    except Exception:  # noqa: BLE001 - a broken recipe has no inventory
        return []
    sources = _raw_array(text, "source") or recipe.arrays.get("source", ())
    sums = next((_raw_array(text, name) or recipe.arrays.get(name, ())
                 for name in _CHECKSUM_ARRAYS
                 if _raw_array(text, name) or recipe.arrays.get(name)), ())
    out: list[dict[str, str]] = []
    for index, entry in enumerate(sources[:256]):
        raw = entry.strip()
        if not raw:
            continue
        name, _, url = raw.rpartition("::")
        target = url or name
        checksum = sums[index].strip() if index < len(sums) else ""
        reason = ""
        lowered = target.lower()
        if lowered.startswith(_VCS_PREFIXES):
            reason = "vcs"
        elif checksum.upper() == "SKIP":
            reason = "skip"
        elif not checksum:
            reason = "unpinned"
        if reason:
            out.append({"name": name or target, "url": target, "reason": reason})
    return out
