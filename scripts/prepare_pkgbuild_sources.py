"""Stage a PKGBUILD and .SRCINFO for a release or a pre-release build.

``makepkg`` validates every declared source, even with ``--skippgpcheck``.
A release-prep branch has no tag and no ``trustsight-<version>.tar.gz.sig``
yet, so the container install test must build from a recipe without the
signature source. A tagged release keeps both entries and verifies the real
signature in ``pkgbuild.yml``.

One implementation is shared by the test and release tooling so the recipe
rewrite cannot drift between them.
"""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

__all__ = [
    "SIGNATURE_SUFFIX",
    "rewrite_pkgbuild",
    "rewrite_srcinfo",
    "stage_sources",
]

SIGNATURE_SUFFIX = ".tar.gz.sig"

_SHA_LINE_RE = re.compile(r"sha256sums=\('[0-9a-f]{64}'")
_SIG_SOURCE_RE = re.compile(r"^.*\.tar\.gz\.sig::.*\n", re.MULTILINE)
_TWO_SUMS_RE = re.compile(
    r"sha256sums=\('([0-9a-f]{64})'\s*\n\s*'[0-9a-f]{64}'\)"
)
_SRCINFO_SHA_RE = re.compile(
    r"(?m)^\tsha256sums = [0-9a-f]{64}$"
)
_SRCINFO_SIG_RE = re.compile(
    r"^\tsource = .*\.tar\.gz\.sig::.*\n", re.MULTILINE
)
_SRCINFO_TWO_SUMS_RE = re.compile(
    r"(?m)^(\tsha256sums = \S+\n)\tsha256sums = \S+\n"
)


def rewrite_pkgbuild(
    text: str, tarball_digest: str, *, signed: bool,
) -> str:
    """Pin *tarball_digest* and, when unsigned, drop the .sig source."""
    rewritten, count = _SHA_LINE_RE.subn(
        f"sha256sums=('{tarball_digest}'", text, count=1)
    if count != 1:
        raise ValueError("PKGBUILD has no sha256sums entry to rewrite")
    if signed:
        return rewritten

    rewritten, count = _SIG_SOURCE_RE.subn("", rewritten, count=1)
    if count != 1:
        raise ValueError("PKGBUILD has no signature source to drop")
    rewritten, count = _TWO_SUMS_RE.subn(
        r"sha256sums=('\1')", rewritten, count=1)
    if count != 1:
        raise ValueError("PKGBUILD has no two-entry checksum list to drop")
    return rewritten


def rewrite_srcinfo(
    text: str, tarball_digest: str, *, signed: bool,
) -> str:
    """Pin *tarball_digest* and, when unsigned, drop the .sig entries."""
    text, count = _SRCINFO_SHA_RE.subn(
        f"\tsha256sums = {tarball_digest}", text, count=1)
    if count != 1:
        raise ValueError(".SRCINFO has no sha256sums entry to rewrite")
    if signed:
        return text
    rewritten, count = _SRCINFO_SIG_RE.subn("", text, count=1)
    if count != 1:
        raise ValueError(".SRCINFO has no signature source to drop")
    rewritten, count = _SRCINFO_TWO_SUMS_RE.subn(r"\1", rewritten, count=1)
    if count != 1:
        raise ValueError(".SRCINFO has no two-entry checksum list to drop")
    return rewritten


def stage_sources(
    pkg_dir: str | Path,
    out_dir: str | Path,
    version: str,
    tarball_digest: str,
) -> bool:
    """Write a buildable PKGBUILD/.SRCINFO pair; return whether it is signed.

    The signature is copied only when the committed asset exists. The
    caller still provides the tarball itself.
    """
    pkg_dir = Path(pkg_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    signature = pkg_dir / f"trustsight-{version}{SIGNATURE_SUFFIX}"
    signed = signature.exists()
    (out_dir / "PKGBUILD").write_text(
        rewrite_pkgbuild(
            (pkg_dir / "PKGBUILD").read_text(),
            tarball_digest,
            signed=signed,
        ),
        encoding="utf-8",
    )
    (out_dir / ".SRCINFO").write_text(
        rewrite_srcinfo(
            (pkg_dir / ".SRCINFO").read_text(), tarball_digest,
            signed=signed,
        ),
        encoding="utf-8",
    )
    if signed:
        shutil.copy(signature, out_dir / signature.name)
    return signed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pkgbuild-dir", default="packaging/aur")
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tarball-digest", required=True)
    args = parser.parse_args(argv)
    signed = stage_sources(
        args.pkgbuild_dir, args.output, args.version, args.tarball_digest)
    print("signed" if signed else "unsigned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
