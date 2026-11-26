#!/usr/bin/env python3
"""Produce an L9 artifact manifest from a built package, without executing it.

The L9 lane inspects a manifest an external build produced; TrustSight itself
never builds or runs package code.  This script is that external producer for
a local package archive: it streams the ``.pkg.tar.zst`` through ``zstd`` and
``tarfile``, reads member metadata and selected file content, and writes the
``{manifest, declared}`` JSON the lane consumes.

Nothing here executes a package: there is no extraction to disk, no ``makepkg``
and no loader.  ELF metadata comes from :func:`trustsight.analysis.elf.parse_elf`
on bounded bytes.

Usage:
    python scripts/artifact_manifest.py PKG.tar.zst --out manifest.json
    python scripts/artifact_manifest.py PKG.tar.zst --recipe PKGBUILD \\
        --units /usr/lib/systemd/system/x.service --out manifest.json
    python scripts/artifact_manifest.py --installed PKGNAME --out manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.analysis.artifact import MAX_CONTENT_BYTES  # noqa: E402
from trustsight.analysis.artifact import MAX_MANIFEST_ENTRIES  # noqa: E402
from trustsight.analysis.elf import parse_elf  # noqa: E402

#: Per-member read window for ELF parsing.  Larger than the section-header
#: window the parser needs in practice, small enough to keep memory flat.
ELF_READ_BYTES = 8 * 1024 * 1024
#: Files whose shipped content the A011-A013 rules read.
_CONTENT_SUFFIXES = (".hook", ".rules", ".install")
_XATTR_CAPS = "SCHILY.xattr.security.capability"


def _pkg_version(path: Path) -> str:
    name = path.name
    for suffix in (".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _stream(path: Path):
    proc = subprocess.Popen(
        ["zstd", "-dc", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.stdout is None:  # pragma: no cover - Popen contract
        raise RuntimeError("zstd produced no output stream")
    return proc, proc.stdout


def _manifest_entry(name: str, member: tarfile.TarInfo,
                    handle) -> dict | None:
    path = "/" + name.lstrip("./").lstrip("/")
    if member.isdir():
        return {"path": path.rstrip("/") + "/", "mode": member.mode & 0o7777}
    if not member.isfile():
        # Symlinks and devices are not part of the artifact comparison yet;
        # the lane's contract is files, modes, links and shipped content.
        return None
    entry: dict = {"path": path, "mode": member.mode & 0o7777}
    caps = member.pax_headers.get(_XATTR_CAPS)
    if caps:
        raw = caps.encode("utf-8", "surrogateescape")
        entry["caps"] = "0x" + raw.hex()
    lower = path.lower()
    if lower.endswith((".bpf.o", ".bpf.c")):
        entry["bpf"] = True
    if member.size and lower.endswith(_CONTENT_SUFFIXES):
        content = handle.read(min(member.size, MAX_CONTENT_BYTES))
        if content:
            entry["content"] = content.decode("utf-8", "ignore")
    if member.size and handle is not None:
        head = handle.read(4)
        if head == b"\x7fELF":
            body = handle.read(ELF_READ_BYTES - len(head))
            info = parse_elf(head + body)
            if info is not None:
                entry["elf"] = {
                    "needed": list(info.needed),
                    "rpath": list(info.rpath),
                    "runpath": list(info.runpath),
                    "packed": info.packed,
                }
    return entry


def _blocks_members(members):
    """Yield members up to the manifest's fixed entry ceiling."""
    kept = 0
    for member in members:
        yield member
        if member.isfile() or member.isdir():
            kept += 1
            if kept > MAX_MANIFEST_ENTRIES:
                return


def _declared_from_pkginfo(text: str) -> dict:
    depends: list[str] = []
    provides: list[str] = []
    for line in text.splitlines():
        key, sep, value = line.partition(" = ")
        if not sep:
            continue
        if key == "depend":
            depends.append(value.strip())
        elif key == "provides":
            provides.append(value.strip())
    return {"depends": sorted(set(depends)), "provides": sorted(set(provides))}


def _declared_install_text(recipe: Path) -> str | None:
    """The recipe's ``install=`` file body, when the recipe names one."""
    try:
        text = recipe.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = re.search(r"(?m)^\s*install\s*=\s*['\"]?([^'\"\s]+)", text)
    if not match:
        return None
    target = recipe.parent / match.group(1)
    try:
        return target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def build_manifest(archive: Path, *, recipe: Path | None = None,
                   units: list[str] | None = None) -> dict:
    proc, stdout = _stream(archive)
    manifest: list[dict] = []
    declared: dict = {"depends": [], "units": sorted(units or [])}
    pkginfo = ""
    built_install = ""
    try:
        with tarfile.open(fileobj=stdout, mode="r|") as tar:
            for member in _blocks_members(tar):
                name = member.name
                if name in (".PKGINFO", ".BUILDINFO", ".MTREE"):
                    handle = tar.extractfile(member)
                    if handle is not None and name == ".PKGINFO":
                        pkginfo = handle.read().decode("utf-8", "replace")
                    continue
                if name == ".INSTALL":
                    handle = tar.extractfile(member)
                    if handle is not None:
                        built_install = handle.read().decode("utf-8", "replace")
                    continue
                handle = tar.extractfile(member) if member.isfile() else None
                entry = _manifest_entry(name, member, handle)
                if entry is not None:
                    manifest.append(entry)
    finally:
        stdout.close()
        proc.wait(timeout=30)

    if pkginfo:
        declared.update(_declared_from_pkginfo(pkginfo))
    if built_install:
        declared["built_install_text"] = built_install
    recipe_install = _declared_install_text(recipe) if recipe else None
    if recipe_install is not None:
        declared["install_text"] = recipe_install

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return {
        "package": _pkg_version(archive),
        "manifest": manifest,
        "declared": declared,
        "provenance": {
            "archive": str(archive),
            "archive_sha256": digest,
            "producer": "scripts/artifact_manifest.py",
            "entries": len(manifest),
            "truncated_at": MAX_MANIFEST_ENTRIES,
        },
    }


def _installed_manifest(name: str) -> dict:
    """Build a manifest from an installed package tree (no archive needed)."""
    files = subprocess.run(
        ["pacman", "-Ql", name], capture_output=True, text=True, check=True,
    ).stdout
    manifest: list[dict] = []
    for line in files.splitlines():
        _pkg, _, raw = line.partition(" ")
        path = raw.strip()
        if not path:
            continue
        if path.endswith("/"):
            mode = (os.lstat(path).st_mode & 0o7777
                    if os.path.exists(path) else 0o755)
            manifest.append({"path": path, "mode": mode})
            continue
        try:
            st = os.lstat(path)
        except OSError:
            continue
        entry: dict = {"path": path, "mode": st.st_mode & 0o7777}
        try:
            caps = os.getxattr(path, "security.capability")
        except OSError:
            caps = b""
        if caps:
            entry["caps"] = "0x" + caps.hex()
        try:
            with open(path, "rb") as handle:
                head = handle.read(ELF_READ_BYTES)
        except OSError:
            head = b""
        if head[:4] == b"\x7fELF":
            info = parse_elf(head)
            if info is not None:
                entry["elf"] = {
                    "needed": list(info.needed),
                    "rpath": list(info.rpath),
                    "runpath": list(info.runpath),
                    "packed": info.packed,
                }
        if path.lower().endswith(_CONTENT_SUFFIXES):
            entry["content"] = head[:MAX_CONTENT_BYTES].decode(
                "utf-8", "ignore")
        if path.lower().endswith((".bpf.o", ".bpf.c")):
            entry["bpf"] = True
        manifest.append(entry)
    depends = subprocess.run(
        ["pacman", "-Qi", name], capture_output=True, text=True,
    ).stdout
    declared: dict = {"depends": [], "units": []}
    for line in depends.splitlines():
        if line.startswith("Depends On") and ":" in line:
            declared["depends"] = sorted(line.split(":", 1)[1].split())
    return {
        "package": name,
        "manifest": manifest,
        "declared": declared,
        "provenance": {
            "source": "installed",
            "package": name,
            "producer": "scripts/artifact_manifest.py",
            "entries": len(manifest),
            "truncated_at": MAX_MANIFEST_ENTRIES,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Produce an L9 artifact manifest")
    parser.add_argument("archive", nargs="?", type=Path,
                        help="built .pkg.tar.zst")
    parser.add_argument("--installed", metavar="PACKAGE",
                        help="read an installed package tree instead")
    parser.add_argument("--recipe", type=Path,
                        help="PKGBUILD, for declared install= text")
    parser.add_argument("--units", action="append", default=[],
                        help="declared unit path (repeatable)")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.archive) == bool(args.installed):
        parser.error("pass exactly one of ARCHIVE or --installed")
    if args.installed:
        doc = _installed_manifest(args.installed)
    else:
        doc = build_manifest(args.archive, recipe=args.recipe, units=args.units)
    args.out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"{doc['package']}: {len(doc['manifest'])} entries -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
