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


def pkgbuild_from_tarfile(tf: tarfile.TarFile, name: str, *,
                          max_members: int = MAX_TAR_MEMBERS,
                          max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
                          max_total_bytes: int = MAX_TAR_TOTAL_BYTES,
                          ) -> Optional[str]:
    """Extract the PKGBUILD text from an open snapshot tarball."""
    pkgbuild_path = f"{name}/PKGBUILD"
    member = None
    walked = 0
    for seen, m in enumerate(tf):
        if seen >= max_members:
            break
        walked += max(0, int(getattr(m, "size", 0) or 0))
        if walked > max_total_bytes:
            return None
        if m.name == pkgbuild_path:
            member = m
            break
        if member is None and m.name.endswith("/PKGBUILD"):
            member = m
    if member is None:
        return None
    content = tf.extractfile(member)
    if content is None:
        return None
    raw = read_capped(
        content, max_member_bytes, f"PKGBUILD member of the {name} snapshot")
    return raw.decode("utf-8", errors="replace")


def install_from_tarfile(tf: tarfile.TarFile, name: str, *,
                         max_members: int = MAX_TAR_MEMBERS,
                         max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
                         max_total_bytes: int = MAX_TAR_TOTAL_BYTES,
                         ) -> Optional[tuple[str, str]]:
    """The first top-level ``*.install`` scriptlet in the snapshot, or None."""
    walked = 0
    for seen, member in enumerate(tf):
        if seen >= max_members:
            break
        walked += max(0, int(getattr(member, "size", 0) or 0))
        if walked > max_total_bytes:
            return None
        if member.isfile() and member.name.endswith(".install"):
            handle = tf.extractfile(member)
            if handle is None:
                continue
            raw = read_capped(
                handle, max_member_bytes,
                f"install member of the {name} snapshot")
            return (raw.decode("utf-8", errors="replace"),
                    member.name.rsplit("/", 1)[-1])
    return None


def snapshot_manifest(tf: tarfile.TarFile, *,
                      max_members: int = MAX_TAR_MEMBERS,
                      max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
                      max_total_bytes: int = MAX_TAR_TOTAL_BYTES,
                      ) -> tuple[list[tuple[str, bytes]], list[tuple[str, str]], bool]:
    """Heads, bounded manifest text, and whether the text is complete."""
    from .manifests import (
        MAX_MANIFEST_BYTES,
        MAX_UPSTREAM_MANIFEST_BYTES,
        MAX_UPSTREAM_MANIFEST_FILES,
        manifest_format,
    )

    manifest: list[tuple[str, bytes]] = []
    texts: list[tuple[str, str]] = []
    complete = True
    budget = MAX_UPSTREAM_MANIFEST_BYTES
    text_files = 0
    walked = 0
    for seen, member in enumerate(tf):
        if seen >= max_members:
            complete = False
            break
        walked += max(0, int(getattr(member, "size", 0) or 0))
        if walked > max_total_bytes:
            complete = False
            break
        if not member.isfile():
            continue
        try:
            f = tf.extractfile(member)
        except (tarfile.TarError, OSError):
            continue
        if f is None:
            continue
        if manifest_format(member.name) is None:
            manifest.append((member.name, f.read(64)))
            continue
        too_large = (member.size > MAX_MANIFEST_BYTES
                     or member.size > budget
                     or text_files >= MAX_UPSTREAM_MANIFEST_FILES)
        if too_large or not complete:
            complete = False
            manifest.append((member.name, f.read(64)))
            continue
        data = f.read(member.size)
        if len(data) != member.size:
            complete = False
            manifest.append((member.name, data[:64]))
            continue
        manifest.append((member.name, data[:64]))
        texts.append((member.name, data.decode("utf-8", "replace")))
        budget -= len(data)
        text_files += 1
    return manifest, texts, complete


def parse_snapshot(data: bytes, name: str, *,
                   max_members: int = MAX_TAR_MEMBERS,
                   max_member_bytes: int = MAX_TAR_MEMBER_BYTES,
                   max_total_bytes: int = MAX_TAR_TOTAL_BYTES) -> dict:
    """Parse one snapshot tarball.  No exception escapes this function.

    ``refused`` means a read bound dropped content (a coverage gap);
    ``malformed`` means the bytes were not a usable tarball (fall back to
    the text endpoint).  Both are explicit so the parent never guesses.
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
            pkgbuild = pkgbuild_from_tarfile(
                tf, name, max_members=max_members,
                max_member_bytes=max_member_bytes,
                max_total_bytes=max_total_bytes)
            manifest, texts, complete = snapshot_manifest(
                tf, max_members=max_members,
                max_member_bytes=max_member_bytes,
                max_total_bytes=max_total_bytes)
            install = None
            if pkgbuild is not None:
                with tarfile.open(fileobj=BytesIO(data), mode="r:gz") as tf2:
                    install = install_from_tarfile(
                        tf2, name, max_members=max_members,
                        max_member_bytes=max_member_bytes,
                        max_total_bytes=max_total_bytes)
            result.update({
                "pkgbuild": pkgbuild,
                "manifest": [[path, head.hex()] for path, head in manifest],
                "trailer": check_archive_trailer(data),
                "install_text": install[0] if install else None,
                "install_name": install[1] if install else None,
                "manifest_texts": [[path, text] for path, text in texts],
                "manifest_complete": complete,
            })
    except ReadTooLarge:
        result["refused"] = True
    except (tarfile.TarError, OSError, EOFError, ValueError, struct.error):
        result["malformed"] = True
    return result
