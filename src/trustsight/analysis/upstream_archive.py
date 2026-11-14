"""Bounded, in-memory manifest extraction from a declared source archive.

The archive is attacker-controlled bytes.  This parser never writes to disk,
never follows a link, and never yields a path outside the archive:

* tar and zip are both read in memory;
* absolute paths, ``..`` segments, symlinks and hardlinks are refused;
* member count, decompressed bytes, per-file bytes and file count are capped;
* only files the manifest layer knows (dependency manifests, lockfiles,
  resolver configs) and committed CI workflows are retained.

The function runs in the read-role manifest worker (A17), so the tar/zip
parsers are reached only through the sandboxed child on the hostile path.
"""

from __future__ import annotations

import io
import tarfile
import zipfile

from .manifests._common import (
    MAX_UPSTREAM_MANIFEST_FILES,
    manifest_format,
)
from .upstream_release import is_ci_workflow_path

__all__ = ["parse_upstream_archive"]

MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_UNCOMPRESSED = 268_435_456
MAX_ARCHIVE_FILE_BYTES = 512 * 1024

_ZIP_MAGIC = b"PK\x03\x04"
_SYMLINK_MODE = 0o120000


def _selected(path: str) -> bool:
    return manifest_format(path) is not None or is_ci_workflow_path(path)


def _safe_name(raw: str) -> str | None:
    name = str(raw or "").replace("\\", "/").strip()
    if not name or name.startswith("/") or name.startswith("../"):
        return None
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        return None
    if not parts:
        return None
    return "/".join(parts)


def _empty() -> dict:
    return {
        "manifest_texts": [],
        "complete": True,
        "refused": False,
        "malformed": False,
    }


def _tar(data: bytes, result: dict, *, max_members: int,
         max_file_bytes: int, max_total_bytes: int, max_files: int) -> None:
    texts = result["manifest_texts"]
    seen = kept = total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for member in tar:
            seen += 1
            if seen > max_members:
                result["complete"] = False
                result["refused"] = True
                return
            if not member.isfile() or member.issym() or member.islnk():
                continue
            name = _safe_name(member.name)
            if name is None:
                result["refused"] = True
                continue
            if not _selected(name):
                continue
            if member.size <= 0 or member.size > max_file_bytes:
                result["refused"] = True
                continue
            total += member.size
            if total > max_total_bytes or kept >= max_files:
                result["complete"] = False
                result["refused"] = True
                return
            handle = tar.extractfile(member)
            if handle is None:
                continue
            raw = handle.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes or b"\x00" in raw:
                result["refused"] = True
                continue
            texts.append((name, raw.decode("utf-8", errors="replace")))
            kept += 1


def _zip(data: bytes, result: dict, *, max_members: int,
         max_file_bytes: int, max_total_bytes: int, max_files: int) -> None:
    texts = result["manifest_texts"]
    seen = kept = total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            seen += 1
            if seen > max_members:
                result["complete"] = False
                result["refused"] = True
                return
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == _SYMLINK_MODE:
                result["refused"] = True
                continue
            name = _safe_name(info.filename)
            if name is None:
                result["refused"] = True
                continue
            if not _selected(name):
                continue
            if info.file_size <= 0 or info.file_size > max_file_bytes:
                result["refused"] = True
                continue
            total += info.file_size
            if total > max_total_bytes or kept >= max_files:
                result["complete"] = False
                result["refused"] = True
                return
            with archive.open(info) as handle:
                raw = handle.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes or b"\x00" in raw:
                result["refused"] = True
                continue
            texts.append((name, raw.decode("utf-8", errors="replace")))
            kept += 1


def parse_upstream_archive(
    data: bytes,
    *,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_file_bytes: int = MAX_ARCHIVE_FILE_BYTES,
    max_total_bytes: int = MAX_ARCHIVE_UNCOMPRESSED,
    max_files: int = MAX_UPSTREAM_MANIFEST_FILES,
) -> dict:
    """Return ``manifest_texts``, ``complete``, ``refused`` and ``malformed``.

    No exception escapes: a refused bound or an unreadable archive is a
    result the caller turns into a named boundary, never a silent empty set.
    """
    result = _empty()
    if not isinstance(data, (bytes, bytearray)) or not data:
        result["malformed"] = True
        return result
    if max_members <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        result["malformed"] = True
        return result
    try:
        if data[:4] == _ZIP_MAGIC:
            _zip(data, result, max_members=max_members,
                 max_file_bytes=max_file_bytes,
                 max_total_bytes=max_total_bytes, max_files=max_files)
        else:
            _tar(data, result, max_members=max_members,
                 max_file_bytes=max_file_bytes,
                 max_total_bytes=max_total_bytes, max_files=max_files)
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError,
            ValueError):
        result["malformed"] = True
        result["manifest_texts"] = []
    return result
