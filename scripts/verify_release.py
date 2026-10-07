"""Verify that release metadata and artifacts describe one software version.

Run after building ``dist/`` and the deterministic AUR source archive, before
creating a GitHub release or uploading anything to PyPI.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMIT_KEY = ROOT / "scripts" / "commit_signing_key.asc"


def _version_from(pattern: str, path: Path) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise SystemExit(f"could not read version from {path.relative_to(ROOT)}")
    return match.group(1)


def _verify_signature(signature: Path, artifact: Path, fingerprint: str) -> None:
    """Verify *signature* over *artifact* against the pinned key.

    Imported into a throwaway keyring so the machine's own keyring cannot
    make a signature look valid; the fingerprint is checked explicitly, the
    way the commit-signature workflow checks it.
    """
    if not signature.exists():
        raise SystemExit(f"missing detached signature {signature.relative_to(ROOT)}")
    with tempfile.TemporaryDirectory(prefix="trustsight-release-gnupg-") as home:
        os.chmod(home, 0o700)
        env = {**os.environ, "GNUPGHOME": home}
        imported = subprocess.run(
            ["gpg", "--batch", "--import", str(COMMIT_KEY)],
            env=env, capture_output=True, text=True,
        )
        if imported.returncode != 0:
            raise SystemExit(f"could not import {COMMIT_KEY.name}: {imported.stderr.strip()}")
        result = subprocess.run(
            ["gpg", "--batch", "--verify", "--status-fd", "1",
             str(signature), str(artifact)],
            env=env, capture_output=True, text=True,
        )
        for line in result.stdout.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG "):
                fields = line.split()
                signing = fields[2].upper()
                primary = fields[10].upper() if len(fields) > 10 else signing
                if fingerprint.upper() in (signing, primary):
                    return
        raise SystemExit(
            f"{signature.name} is not a valid signature by {fingerprint} "
            f"over {artifact.name}"
        )


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
    pkgbuild = ROOT / "packaging/aur/PKGBUILD"
    expected_sha = _version_from(
        r"^sha256sums=\(\s*'([0-9a-f]{64})'", pkgbuild
    )
    if _sha256(args.release_tarball) != expected_sha:
        raise SystemExit("release tarball checksum does not match PKGBUILD")
    subprocess.run(
        [sys.executable, "scripts/build_release_tarball.py", "--rev", "HEAD",
         "--check", expected_sha],
        cwd=ROOT,
        check=True,
    )

    # The tarball is signed offline; the key is pinned and never available to
    # CI, so an account, token or workflow compromise is not enough to forge
    # an artifact.
    fingerprint = _version_from(r"^validpgpkeys=\('([0-9A-Fa-f]{40})'", pkgbuild)
    signature = ROOT / "packaging/aur" / f"{expected_tarball}.sig"
    _verify_signature(signature, args.release_tarball, fingerprint)

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
        paths = [args.release_tarball, signature, *wheels]
        args.write_checksums.parent.mkdir(parents=True, exist_ok=True)
        args.write_checksums.write_text(
            "".join(f"{_sha256(path)}  {path.name}\n" for path in paths), encoding="ascii"
        )
    print(f"release preflight passed for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
