"""Build the source tarball the AUR package is checksummed against.

GitHub's ``/archive/refs/tags/*.tar.gz`` are generated on demand and are not
contractually byte-stable: the gzip settings behind them have changed before
and invalidated recorded checksums across every distribution at once.  A
package whose integrity check depends on a file someone else regenerates is
not pinned, it is hoping.

More immediately, that archive cannot exist until the tag does, so its
checksum could only ever be recorded *after* tagging, by a second commit.
Between those two commits the PKGBUILD names a version whose recorded
checksum belongs to the previous release, and if the repair step ever fails
the tree stays that way.  That is the v0.13.1 failure.

This script removes both problems by making the tarball ours and making it a
pure function of the tree, so the checksum is knowable **before** the tag
exists and can ship in the same commit as the version bump.

Determinism is the whole point, so nothing that varies between builds is
allowed into the bytes:

* ``git archive`` stamps every member with the *commit* date, which would
  change the tarball every time a commit is made.  Every mtime is rewritten
  to a fixed epoch instead.
* uid/gid/uname/gname are zeroed, so the builder's account cannot leak in.
* Members are emitted in sorted order rather than tree order.
* gzip is called with ``mtime=0`` and no filename field, which is what
  ``gzip -n`` does; the default embeds the current time.

The result depends only on the paths and contents that ``git archive``
selects.  ``packaging/`` is excluded by ``.gitattributes export-ignore``, so
writing the checksum into ``packaging/aur/PKGBUILD`` does not change the
tarball that checksum describes.  Without that exclusion this would be
circular and no pre-tag checksum would be possible at all.

Usage::

    python scripts/build_release_tarball.py                  # working tree
    python scripts/build_release_tarball.py --rev v0.13.2
    python scripts/build_release_tarball.py --check <sha256>
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Any fixed value works; this one is stable, in the past, and obviously
# synthetic so nobody reads a build date into it.
FIXED_MTIME = 0


def version() -> str:
    with open(ROOT / "pyproject.toml", "rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def _worktree_tree() -> str:
    """Write a tree object for the current working tree and return its id.

    ``HEAD`` is the wrong input while preparing a release: the content that
    will be tagged is what is in the tree *now*, and hashing HEAD records a
    checksum for the previous commit's content.  Staging into a throwaway
    index leaves the real index untouched, and the tree object it writes is
    unreferenced until a commit adopts it.
    """
    index = ROOT / ".git" / "release-tarball.index"
    env = {**os.environ, "GIT_INDEX_FILE": str(index)}
    try:
        subprocess.run(["git", "read-tree", "HEAD"], cwd=ROOT, env=env,
                       check=True, capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=ROOT, env=env,
                       check=True, capture_output=True)
        result = subprocess.run(["git", "write-tree"], cwd=ROOT, env=env,
                                check=True, capture_output=True, text=True)
    finally:
        index.unlink(missing_ok=True)
    return result.stdout.strip()


def _git_archive(rev: str, prefix: str) -> bytes:
    result = subprocess.run(
        ["git", "archive", "--format=tar", f"--prefix={prefix}", rev],
        cwd=ROOT, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"git archive {rev} failed: {result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def _normalise(raw: bytes) -> bytes:
    """Rewrite a tar stream so it depends only on paths and contents."""
    members = []
    with tarfile.open(fileobj=io.BytesIO(raw)) as source:
        for info in source.getmembers():
            payload = source.extractfile(info).read() if info.isreg() else None
            info.mtime = FIXED_MTIME
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            # git archive already emits 0644/0755 only, but pinning the
            # bit pattern keeps a umask from ever reaching the output.
            info.mode = 0o755 if info.mode & 0o111 else 0o644
            members.append((info, payload))

    members.sort(key=lambda item: item[0].name)

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as out:
        for info, payload in members:
            out.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return buffer.getvalue()


def build(rev: str = "WORKTREE", pkgver: str | None = None) -> tuple[bytes, str]:
    """Return the tarball bytes and their sha256.

    ``rev="WORKTREE"`` archives the current working tree, which is what a
    release needs: the checksum must describe the content about to be
    tagged, not the content of the previous commit.
    """
    pkgver = pkgver or version()
    if rev == "WORKTREE":
        rev = _worktree_tree()
    tar = _normalise(_git_archive(rev, f"trustsight-{pkgver}/"))
    buffer = io.BytesIO()
    # mtime=0 and no embedded filename: the gzip header must not carry a
    # build timestamp, which is the default.
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9,
                       fileobj=buffer, mtime=0) as gz:
        gz.write(tar)
    blob = buffer.getvalue()
    return blob, hashlib.sha256(blob).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--rev", default="WORKTREE",
                        help="commit-ish to archive (default: the working tree)")
    parser.add_argument("--pkgver", default=None,
                        help="version for the path prefix (default: pyproject)")
    parser.add_argument("--output", type=Path, default=None,
                        help="write the tarball here (default: dist/)")
    parser.add_argument("--check", metavar="SHA256", default=None,
                        help="fail unless the built tarball has this sha256")
    parser.add_argument("--print-sha256", action="store_true",
                        help="print only the checksum")
    args = parser.parse_args()

    pkgver = args.pkgver or version()
    blob, digest = build(args.rev, pkgver)

    if args.check is not None and args.check != digest:
        print(f"::error::tarball sha256 {digest} does not match expected {args.check}",
              file=sys.stderr)
        return 1

    if args.print_sha256:
        print(digest)
        return 0

    output = args.output or (ROOT / "dist" / f"trustsight-{pkgver}.tar.gz")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(blob)
    print(f"{output.relative_to(ROOT) if output.is_relative_to(ROOT) else output}")
    print(f"sha256 {digest}")
    print(f"bytes  {len(blob)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
