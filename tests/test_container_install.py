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

import json
import os
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


def _as_trustsight(container: str, *command: str) -> str:
    """Run *command* as the documented isolated account."""
    return _exec(
        container, "runuser", "-u", "trustsight", "--", "env",
        "HOME=/home/trustsight",
        "XDG_CONFIG_HOME=/home/trustsight/.config",
        "XDG_CACHE_HOME=/home/trustsight/.cache",
        "PATH=/usr/bin:/bin",
        "TRUSTSIGHT_OFFLINE=1",
        "TRUSTSIGHT_NO_UPDATE_CHECK=1",
        *command,
    )


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
    import prepare_pkgbuild_sources as prepare

    blob, digest = brt.build("WORKTREE", version)
    tarball = tmp_path / f"trustsight-{version}.tar.gz"
    tarball.write_bytes(blob)
    # The helper drops the .sig source when this is a pre-tag branch: makepkg
    # validates every declared source even with --skippgpcheck.
    prepare.stage_sources(PKG_DIR, tmp_path, version, digest)

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

    # The setup documented in docs/guides/reducing-blast-radius.md: a
    # dedicated nologin account owns its state, and the first run after an
    # update adds missing rules and opens the database without root-owned
    # leftovers.
    _exec(arch_container, "useradd", "--create-home", "--shell",
          "/usr/bin/nologin", "trustsight")

    assert version in _as_trustsight(arch_container, "trustsight", "--version")
    status = json.loads(_as_trustsight(
        arch_container, "trustsight", "status", "--json"))
    assert status["missing_shipped_rules"] == []
    assert status["stale_rule_patterns"] == []
    checked = json.loads(_as_trustsight(
        arch_container, "trustsight", "db", "check", "--json"))
    assert checked == {"status": "ok", "errors": []}
    linted = json.loads(_as_trustsight(
        arch_container, "trustsight", "lint-rules", "--json"))
    assert linted["errors"] == 0

    # The tokenizer is the sandboxed hostile parser. It must start under the
    # unprivileged account, not only under root.
    probe = _as_trustsight(
        arch_container, "python3", "-c",
        "from trustsight.tokenizer import split_lines;"
        "assert split_lines('a\\nb') == ['a', 'b'];"
        "print('tokenizer-ok')")
    assert "tokenizer-ok" in probe

    for path in (
        "/home/trustsight/.config/trustsight",
        "/home/trustsight/.local/share/trustsight",
        "/home/trustsight/.cache/trustsight/repos",
    ):
        owner = _exec(arch_container, "stat", "-c", "%U:%G %a", path).strip()
        assert owner == "trustsight:trustsight 700", (path, owner)
    db_owner = _exec(
        arch_container, "stat", "-c", "%U:%G",
        "/home/trustsight/.local/share/trustsight/trustsight.db").strip()
    assert db_owner == "trustsight:trustsight", db_owner
    _exec(arch_container, "bash", "-lc",
          "test ! -e /root/.config/trustsight "
          "&& test ! -e /root/.local/share/trustsight")

    # Simulate the package being replaced in place, the update path the
    # account has to survive. A reinstall must not need a write to root's
    # home or change the ownership of the existing state.
    _exec(arch_container, "bash", "-lc",
          "pacman -U --noconfirm /tmp/pkg/trustsight-*.pkg.tar.zst")
    synced = json.loads(_as_trustsight(
        arch_container, "trustsight", "config", "sync-rules", "--update",
        "--json"))
    assert synced["added"] == []
    assert synced["updated"] == []
    backup = json.loads(_as_trustsight(
        arch_container, "trustsight", "db", "backup", "--json"))
    assert backup["status"] == "ok"
    assert json.loads(_as_trustsight(
        arch_container, "trustsight", "status", "--json")
    )["missing_shipped_rules"] == []
    assert json.loads(_as_trustsight(
        arch_container, "trustsight", "db", "check", "--json")
    )["status"] == "ok"
