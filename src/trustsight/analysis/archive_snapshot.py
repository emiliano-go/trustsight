"""Pure AUR snapshot archive parsing.

The snapshot tarball is package-controlled bytes parsed by :mod:`tarfile` and
:mod:`zlib`.  This module is the parser: it has no network, no database and no
filesystem access, so it can run in the read-role sandbox worker.  The fetch
module keeps the HTTP transport and calls here through
``sandbox.manifest_client``.
"""

from __future__ import annotations

import struct
import tarfile
from io import BytesIO
from typing import Optional

from ..bounded_io import ReadTooLarge, read_capped

MAX_TAR_MEMBERS = 10_000
MAX_TAR_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TAR_TOTAL_BYTES = 256 * 1024 * 1024
_HEAD_BYTES = 64


def _bounded_members(tf: tarfile.TarFile, *, max_members: int,
                     max_total_bytes: int) -> tuple[list, bool]:
    """Enumerate members once, stopping at the declared-size and count caps.

    No body is read here, so a member that declares a huge size is stopped at
    the declaration rather than after ``tarfile`` seeks over it.  Returns the
    members seen and whether the walk reached the end of the archive.
    """
    members: list = []
    walked = 0
    for seen, member in enumerate(tf):
        if seen >= max_members:
            return members, False
        walked += max(0, int(getattr(member, "size", 0) or 0))
        if walked > max_total_bytes:
            return members, False
        members.append(member)
    return members, True


def _pkgbuild_member(members: list, name: str):
    """The exact ``<name>/PKGBUILD`` if present, else the first suffix match."""
    exact = f"{name}/PKGBUILD"
    fallback = None
    for member in members:
        if member.name == exact:
            return member
        if fallback is None and member.name.endswith("/PKGBUILD"):
            fallback = member
    return fallback


def _read_pkgbuild(tf: tarfile.TarFile, members: list, name: str,
                   max_member_bytes: int) -> Optional[str]:
    member = _pkgbuild_member(members, name)
    if member is None:
        return None
    content = tf.extractfile(member)
    if content is None:
        return None
    raw = read_capped(
        content, max_member_bytes, f"PKGBUILD member of the {name} snapshot")
    return raw.decode("utf-8", errors="replace")


def _read_install(tf: tarfile.TarFile, members: list,
                  max_member_bytes: int, name: str
                  ) -> Optional[tuple[str, str]]:
    for member in members:
        if not member.isfile() or not member.name.endswith(".install"):
            continue
        handle = tf.extractfile(member)
        if handle is None:
            continue
        raw = read_capped(
            handle, max_member_bytes,
            f"install member of the {name} snapshot")
        return (raw.decode("utf-8", errors="replace"),
                member.name.rsplit("/", 1)[-1])
    return None


def _read_manifest(tf: tarfile.TarFile, members: list, walk_complete: bool
                   ) -> tuple[list[tuple[str, bytes]], list[tuple[str, str]], bool]:
    from .manifests import (
        MAX_MANIFEST_BYTES,
        MAX_UPSTREAM_MANIFEST_BYTES,
        MAX_UPSTREAM_MANIFEST_FILES,
        manifest_format,
    )

    manifest: list[tuple[str, bytes]] = []
    texts: list[tuple[str, str]] = []
    complete = walk_complete
    budget = MAX_UPSTREAM_MANIFEST_BYTES
    text_files = 0
    for member in members:
        if not member.isfile():
            continue
        try:
            handle = tf.extractfile(member)
        except (tarfile.TarError, OSError):
            continue
        if handle is None:
            continue
        if manifest_format(member.name) is None:
            manifest.append((member.name, handle.read(_HEAD_BYTES)))
            continue
        too_large = (member.size > MAX_MANIFEST_BYTES
                     or member.size > budget
                     or text_files >= MAX_UPSTREAM_MANIFEST_FILES)
        if too_large or not complete:
            complete = False
            manifest.append((member.name, handle.read(_HEAD_BYTES)))
            continue
        data = handle.read(member.size)
        if len(data) != member.size:
            complete = False
            manifest.append((member.name, data[:_HEAD_BYTES]))
            continue
        manifest.append((member.name, data[:_HEAD_BYTES]))
        texts.append((member.name, data.decode("utf-8", "replace")))
        budget -= len(data)
        text_files += 1
    return manifest, texts, complete


def pkgbuild_from_tarfile(tf: tarfile.TarFile, name: str, *,
                          max_members: int = MAX_TAR_MEMBERS,
                          max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
                          max_total_bytes: int = MAX_TAR_TOTAL_BYTES,
                          ) -> Optional[str]:
    """Extract the PKGBUILD text from an open snapshot tarball."""
    members, _ = _bounded_members(
        tf, max_members=max_members, max_total_bytes=max_total_bytes)
    return _read_pkgbuild(tf, members, name, max_member_bytes)


def install_from_tarfile(tf: tarfile.TarFile, name: str, *,
                         max_members: int = MAX_TAR_MEMBERS,
                         max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
                         max_total_bytes: int = MAX_TAR_TOTAL_BYTES,
                         ) -> Optional[tuple[str, str]]:
    """The first top-level ``*.install`` scriptlet in the snapshot, or None."""
    members, _ = _bounded_members(
        tf, max_members=max_members, max_total_bytes=max_total_bytes)
    return _read_install(tf, members, max_member_bytes, name)


def snapshot_manifest(tf: tarfile.TarFile, *,
                      max_members: int = MAX_TAR_MEMBERS,
                      max_total_bytes: int = MAX_TAR_TOTAL_BYTES,
                      ) -> tuple[list[tuple[str, bytes]], list[tuple[str, str]], bool]:
    """Heads, bounded manifest text, and whether the text is complete."""
    members, walk_complete = _bounded_members(
        tf, max_members=max_members, max_total_bytes=max_total_bytes)
    return _read_manifest(tf, members, walk_complete)


def parse_snapshot(data: bytes, name: str, *,
                   max_members: int = MAX_TAR_MEMBERS,
                   max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
                   max_total_bytes: int = MAX_TAR_TOTAL_BYTES) -> dict:
    """Parse one snapshot tarball.  No exception escapes this function.

    ``refused`` means a read bound dropped content (a coverage gap);
    ``malformed`` means the bytes were not a usable tarball (fall back to the
    text endpoint).  Both are explicit so the parent never guesses.

    The archive is opened and decompressed once: member headers are bounded in
    a single walk, then the selected bodies are read from the same handle.
    """
    from .archives import check_archive_trailer

    result = {
        "pkgbuild": None,
        "manifest": [],
        "trailer": None,
        "install_text": None,
        "install_name": None,
        "manifest_texts": [],
        "manifest_complete": True,
        "refused": False,
        "malformed": False,
    }
    try:
        with tarfile.open(fileobj=BytesIO(data), mode="r:gz") as tf:
            members, walk_complete = _bounded_members(
                tf, max_members=max_members, max_total_bytes=max_total_bytes)
            pkgbuild = _read_pkgbuild(tf, members, name, max_member_bytes)
            manifest, texts, manifest_complete = _read_manifest(
                tf, members, walk_complete)
            install = None
            if pkgbuild is not None:
                install = _read_install(tf, members, max_member_bytes, name)
            result.update({
                "pkgbuild": pkgbuild,
                "manifest": [[path, head.hex()] for path, head in manifest],
                "trailer": check_archive_trailer(data),
                "install_text": install[0] if install else None,
                "install_name": install[1] if install else None,
                "manifest_texts": [[path, text] for path, text in texts],
                "manifest_complete": manifest_complete,
            })
    except ReadTooLarge:
        result["refused"] = True
    except (tarfile.TarError, OSError, EOFError, ValueError, struct.error):
        result["malformed"] = True
    return result
