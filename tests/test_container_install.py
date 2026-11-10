"""Build and install the package in a disposable Arch container.

The release checklist's manual `makepkg -si` step, automated: build the
deterministic release tarball, hand the PKGBUILD and the tarball to a
throwaway Arch container, build and install there, and run the installed
entry point.  It runs the same `check()` every user's build runs, so a
PKGBUILD that cannot install is caught without a hand-run container.

Gated behind ``TRUSTSIGHT_CONTAINER=1`` so the per-interpreter test matrix
does not pull an image and run pacman on every push; the
``container-install`` CI job sets it.  It skips (never fails) when the
docker CLI or daemon is unavailable, so a checkout without Docker still
collects the suite.

    TRUSTSIGHT_CONTAINER=1 uv run pytest tests/test_container_install.py
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = ROOT / "packaging" / "aur"
IMAGE = os.environ.get("TRUSTSIGHT_CONTAINER_IMAGE", "archlinux:latest")

pytestmark = pytest.mark.skipif(
    os.environ.get("TRUSTSIGHT_CONTAINER") != "1",
    reason="set TRUSTSIGHT_CONTAINER=1 to build and install in a container",
)


def _run(*args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


def _exec(container: str, *command: str, user: str | None = None) -> str:
    prefix = ["docker", "exec"]
    if user is not None:
        prefix += ["-u", user]
    return _run(*prefix, container, *command).stdout


def _version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


@pytest.fixture
def arch_container() -> str:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI is not installed")
    probe = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if probe.returncode != 0:
        pytest.skip(f"docker daemon is unavailable: {probe.stderr.strip()[:120]}")
    container = _run(
        "docker", "run", "--detach", "--rm", "--memory=2g", "--privileged",
        IMAGE, "sleep", "infinity",
    ).stdout.strip()
    try:
        yield container
    finally:
        subprocess.run(["docker", "rm", "--force", container],
                       capture_output=True, text=True)


def test_pkgbuild_builds_and_installs(arch_container: str, tmp_path: Path) -> None:
    version = _version()

    # Build the deterministic tarball this PKGBUILD checksums, and stage the
    # package files with it.  makepkg finds the sources beside the PKGBUILD,
    # so the container needs no network beyond the Arch repositories.
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_release_tarball as brt

    blob, digest = brt.build("WORKTREE", version)
    tarball = tmp_path / f"trustsight-{version}.tar.gz"
    tarball.write_bytes(blob)
    for name in (".SRCINFO", f"trustsight-{version}.tar.gz.sig"):
        shutil.copy(PKG_DIR / name, tmp_path / name)

    # This test proves the package installs; the checksum *record* is pinned
    # by pkgbuild.yml and test_pkgbuild.py.  Checksum the freshly built
    # tarball into the temp PKGBUILD so a tree mid-edit still exercises the
    # build instead of failing on a stale recorded hash.  The committed
    # `.sig` needs no change: it describes the tarball, and only the tarball
    # is rebuilt here.
    pkgbuild = (PKG_DIR / "PKGBUILD").read_text()
    rewritten, count = re.subn(
        r"sha256sums=\('[0-9a-f]{64}'",
        f"sha256sums=('{digest}'", pkgbuild, count=1,
    )
    assert count == 1, "PKGBUILD has no sha256sums entry to rewrite"
    (tmp_path / "PKGBUILD").write_text(rewritten)

    # Seed the container's pacman and install the build tooling.
    _exec(arch_container, "pacman", "-Syu", "--noconfirm")
    _exec(arch_container, "pacman", "-S", "--needed", "--noconfirm",
          "base-devel", "sudo", "git", "python", "gnupg")

    # makepkg refuses to run as root; copy the sources in, give them to a
    # non-root builder, and let `makepkg -si` install without a password.
    _exec(arch_container, "useradd", "-m", "builder")
    _exec(arch_container, "bash", "-lc",
          "echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/10-builder")
    _exec(arch_container, "mkdir", "-p", "/tmp/pkg")
    _run("docker", "cp", f"{tmp_path}/.", f"{arch_container}:/tmp/pkg")
    _exec(arch_container, "chown", "-R", "builder:builder", "/tmp/pkg")

    # Pre-release: the committed `.sig` covers the tagged bytes, and this
    # tarball is rebuilt from the tree, so verify the checksum (makepkg does)
    # and skip the signature.  A tagged run verifies it in pkgbuild.yml.
    _exec(
        arch_container, "bash", "-lc",
        "cd /tmp/pkg && makepkg -si --noconfirm --skippgpcheck",
        user="builder",
    )

    installed = _exec(arch_container, "pacman", "-Q", "trustsight")
    assert installed.startswith("trustsight "), installed
    assert version in installed, f"{installed!r} does not name {version}"

    entry = _exec(arch_container, "trustsight", "--version")
    assert version in entry, f"installed entry point reports {entry.strip()!r}"
