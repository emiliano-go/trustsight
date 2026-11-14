"""Bounded, in-memory manifest extraction from a declared source archive.

The archive is attacker-controlled bytes.  This parser never writes to disk,
never follows a link, and never yields a path outside the archive:

* tar and zip are both read in memory;
* a **decompressed-byte cap** wraps the tar stream, so a gzip/xz/bz2 bomb - or
  a pax header that declares far more than it carries - is refused before the
  parser can allocate it (the CVE-2019-20907 class);
* absolute paths, ``..`` segments, symlinks and hardlinks are refused;
* member count, per-file bytes, actual decompressed bytes and retained file
  count are capped, and the *actual* bytes read are counted rather than the
  size a header declares;
* only files the manifest layer knows (dependency manifests, lockfiles,
  resolver configs) and committed CI workflows are retained.

The function runs in the read-role manifest worker (A17), so the tar/zip
parsers are reached only through the sandboxed child on the hostile path.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile

from .manifests._common import (
    MAX_UPSTREAM_MANIFEST_FILES,
    manifest_format,
)
from .upstream_release import is_ci_workflow_path

__all__ = ["parse_upstream_archive"]

MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_UNCOMPRESSED = 64 * 1024 * 1024
MAX_ARCHIVE_FILE_BYTES = 512 * 1024
#: Hard ceilings: a caller may lower these, never raise them.
_HARD_MEMBERS = 10_000
_HARD_FILE_BYTES = 1024 * 1024
_HARD_TOTAL_BYTES = 256 * 1024 * 1024
_HARD_FILES = 64

_ZIP_MAGIC = b"PK\x03\x04"
_ZIP_EOCD = b"PK\x05\x06"
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_SYMLINK_MODE = 0o120000


class _ArchiveTooLarge(Exception):
    """The decompressed stream passed its byte cap."""


class _LimitedReader:
    """A stream that refuses to hand out more than *limit* bytes in total.

    Wrapped around the decompressor, this bounds the *decompressed* bytes the
    tar parser can read, including extended headers, so a header that declares
    a huge length cannot make the parser allocate it.  It is a plain wrapper
    (``tarfile`` only needs ``read``), not an ``io.RawIOBase`` override.
    """

    def __init__(self, inner, limit: int):
        self._inner = inner
        self._remaining = limit

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._remaining < 0:
            raise _ArchiveTooLarge("decompressed bytes exceeded the cap")
        if size is None or size < 0:
            size = self._remaining + 1
        amount = min(size, self._remaining + 1)
        chunk = self._inner.read(amount)
        if not chunk:
            return b""
        if len(chunk) > self._remaining:
            raise _ArchiveTooLarge("decompressed bytes exceeded the cap")
        self._remaining -= len(chunk)
        return chunk

    def close(self) -> None:
        try:
            self._inner.close()
        except Exception:  # noqa: BLE001 - close must never mask the result
            pass


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


def _clamp(value: int, ceiling: int) -> int:
    return max(1, min(int(value), ceiling))


def _decompressed(data: bytes):
    if data[:2] == _GZIP_MAGIC:
        return gzip.GzipFile(fileobj=io.BytesIO(data))
    if data[:3] == _BZ2_MAGIC:
        return bz2.BZ2File(io.BytesIO(data))
    if data[:6] == _XZ_MAGIC:
        return lzma.LZMAFile(io.BytesIO(data))
    return io.BytesIO(data)


def _tar(data: bytes, result: dict, *, max_members: int,
         max_file_bytes: int, max_total_bytes: int, max_files: int) -> None:
    texts = result["manifest_texts"]
    seen = kept = 0
    stream = _LimitedReader(_decompressed(data), max_total_bytes)
    try:
        tar_context = tarfile.open(fileobj=stream, mode="r|")
    except Exception:
        stream.close()
        raise
    with tar_context as tar:
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
            if kept >= max_files:
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
    stream.close()


def _zip_declared_entries(data: bytes) -> int | None:
    """The entry count from the EOCD, read before ``infolist()`` materialises.

    The central directory is parsed into Python objects by ``infolist()``, so a
    count that is already over the cap is refused first.  Zip64 (0xFFFF) is
    left to the post-materialisation check.
    """
    window = data[-65_557:]
    index = window.rfind(_ZIP_EOCD)
    if index < 0 or index + 12 > len(window):
        return None
    total = int.from_bytes(window[index + 10:index + 12], "little")
    return None if total == 0xFFFF else total


def _zip(data: bytes, result: dict, *, max_members: int,
         max_file_bytes: int, max_total_bytes: int, max_files: int) -> None:
    texts = result["manifest_texts"]
    declared = _zip_declared_entries(data)
    if declared is not None and declared > max_members:
        result["complete"] = False
        result["refused"] = True
        return
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > max_members:
            result["complete"] = False
            result["refused"] = True
            return
        kept = total = 0
        for info in entries:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                result["refused"] = True  # encrypted member
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
            if kept >= max_files:
                result["complete"] = False
                result["refused"] = True
                return
            with archive.open(info) as handle:
                raw = handle.read(max_file_bytes + 1)
            actual = len(raw)
            if actual > max_file_bytes or b"\x00" in raw:
                result["refused"] = True
                continue
            total += actual
            if total > max_total_bytes:
                result["complete"] = False
                result["refused"] = True
                return
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
    max_members = _clamp(max_members, _HARD_MEMBERS)
    max_file_bytes = _clamp(max_file_bytes, _HARD_FILE_BYTES)
    max_total_bytes = _clamp(max_total_bytes, _HARD_TOTAL_BYTES)
    max_files = _clamp(max_files, _HARD_FILES)
    try:
        if data[:4] == _ZIP_MAGIC:
            _zip(data, result, max_members=max_members,
                 max_file_bytes=max_file_bytes,
                 max_total_bytes=max_total_bytes, max_files=max_files)
        else:
            _tar(data, result, max_members=max_members,
                 max_file_bytes=max_file_bytes,
                 max_total_bytes=max_total_bytes, max_files=max_files)
    except _ArchiveTooLarge:
        result["complete"] = False
        result["refused"] = True
        result["manifest_texts"] = []
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError,
            ValueError, lzma.LZMAError):
        result["malformed"] = True
        result["manifest_texts"] = []
    return result
