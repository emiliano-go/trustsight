"""Verify that release metadata and artifacts describe one software version.

Run after building ``dist/`` and the deterministic AUR source archive, before
creating a GitHub release or uploading anything to PyPI.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _version_from(pattern: str, path: Path) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise SystemExit(f"could not read version from {path.relative_to(ROOT)}")
    return match.group(1)


def _metadata_version(path: Path) -> str:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            metadata = next(
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            )
            text = archive.read(metadata).decode("utf-8")
    else:
        with tarfile.open(path) as archive:
            metadata = next(
                member for member in archive.getmembers()
                if member.name.endswith("/PKG-INFO")
            )
            text = archive.extractfile(metadata).read().decode("utf-8")
    match = re.search(r"^Version: (.+)$", text, re.MULTILINE)
    if match is None:
        raise SystemExit(f"could not read version from {path.name}")
    return match.group(1)


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag, e.g. v0.13.2")
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--release-tarball", type=Path, required=True)
    parser.add_argument("--write-checksums", type=Path)
    args = parser.parse_args()

    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        raise SystemExit(f"invalid software release tag: {args.tag}")
    version = args.tag[1:]
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project_version = tomllib.load(handle)["project"]["version"]
    pkgbuild_version = _version_from(r"^pkgver=(.+)$", ROOT / "packaging/aur/PKGBUILD")
    srcinfo_version = _version_from(r"^\s*pkgver = (.+)$", ROOT / "packaging/aur/.SRCINFO")
    versions = {
        "tag": version,
        "pyproject.toml": project_version,
        "PKGBUILD": pkgbuild_version,
        ".SRCINFO": srcinfo_version,
    }
    if len(set(versions.values())) != 1:
        raise SystemExit(f"version mismatch: {versions}")

    expected_tarball = f"trustsight-{version}.tar.gz"
    if args.release_tarball.name != expected_tarball:
        raise SystemExit(f"release tarball must be named {expected_tarball}")
    expected_sha = _version_from(
        r"^sha256sums=\('([0-9a-f]{64})'\)$", ROOT / "packaging/aur/PKGBUILD"
    )
    if _sha256(args.release_tarball) != expected_sha:
        raise SystemExit("release tarball checksum does not match PKGBUILD")
    subprocess.run(
        ["python", "scripts/build_release_tarball.py", "--check", expected_sha],
        cwd=ROOT,
        check=True,
    )

    artifacts = sorted(args.dist.glob("trustsight-*"))
    wheels = [path for path in artifacts if path.suffix == ".whl"]
    sdists = [path for path in artifacts if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("dist must contain exactly one wheel and one source distribution")
    for artifact in [*wheels, *sdists]:
        if _metadata_version(artifact) != version:
            raise SystemExit(f"{artifact.name} metadata does not match {version}")

    if args.write_checksums:
        # The PyPI sdist and the deterministic AUR archive intentionally have
        # the same filename. GitHub cannot attach both, so its manifest covers
        # the public AUR archive and wheel; the sdist is validated above and
        # published only to PyPI.
        paths = [args.release_tarball, *wheels]
        args.write_checksums.parent.mkdir(parents=True, exist_ok=True)
        args.write_checksums.write_text(
            "".join(f"{_sha256(path)}  {path.name}\n" for path in paths), encoding="ascii"
        )
    print(f"release preflight passed for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
