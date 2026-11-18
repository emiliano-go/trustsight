"""Deterministic tree attestations.

The attestation is a digest of the reviewed source tree. It is not a build:
TrustSight never runs ``makepkg``. The gate can record the tree it inspected
and a later check can refuse a tree whose bytes changed.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

__all__ = ["ATTEST_VERSION", "check_tree", "digest_tree", "write_attestation"]

ATTEST_VERSION = 1
MAX_FILES = 200_000
MAX_BYTES = 2 * 1024 * 1024 * 1024
_SKIP_DIRS = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache"})


class AttestError(RuntimeError):
    """The tree could not be attested or the attestation does not match."""


def _records(root: Path):
    files = 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            size = path.stat().st_size
            files += 1
            total += size
            if files > MAX_FILES or total > MAX_BYTES:
                raise AttestError("source tree exceeds the attestation bounds")
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            yield rel, size, bool(path.stat().st_mode & 0o111), digest.hexdigest()


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
    Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
    return payload


def check_tree(root: str | Path, attestation: str | Path) -> dict:
    try:
        expected = json.loads(Path(attestation).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AttestError(f"could not read attestation: {exc}") from exc
    if not isinstance(expected, dict) or expected.get("version") != ATTEST_VERSION:
        raise AttestError("unsupported attestation document")
    actual = digest_tree(root)
    if expected.get("digest") != actual["digest"]:
        raise AttestError(
            f"tree digest changed: expected {expected.get('digest')}, "
            f"got {actual['digest']}")
    return actual
