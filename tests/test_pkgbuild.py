import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import tomllib

import trustsight

PKGBUILD_DIR = Path(__file__).resolve().parent.parent / "packaging" / "aur"
PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

_PKGBUILD_NEEDS_MAKEPKG = pytest.mark.skipif(
    not shutil.which("makepkg"),
    reason="makepkg not available (non-Arch system)",
)

# Map from pyproject.toml dependency name to Arch Python package name.
_PYPI_TO_ARCH = {
    "pygit2": "python-pygit2",
    "tldextract": "python-tldextract",
    "rich": "python-rich",
    "typer": "python-typer",
    "cryptography": "python-cryptography",
}


def _pkgbuild_text() -> str:
    return (PKGBUILD_DIR / "PKGBUILD").read_text()


def _depends_from_pkgbuild() -> set[str]:
    """Parse the depends array from PKGBUILD text without sourcing."""
    text = _pkgbuild_text()
    m = re.search(r"^depends=\(\n((?:\s+'.*'\n)*)\)", text, re.M)
    if not m:
        return set()
    return set(re.findall(r"'(.*?)'", m.group(1)))


def _optdepends_from_pkgbuild() -> set[str]:
    """Parse the optdepends array from PKGBUILD text."""
    text = _pkgbuild_text()
    m = re.search(r"^optdepends=\(\n((?:\s+'.*'\n)*)\)", text, re.M)
    if not m:
        return set()
    return set(re.findall(r"'(.*?)'", m.group(1)))


def _pkgver_from_pkgbuild() -> str | None:
    m = re.search(r"^pkgver=(\S+)", _pkgbuild_text(), re.M)
    return m.group(1) if m else None


def _version_from_pyproject() -> str:
    with open(PYPROJECT, "rb") as f:
        return tomllib.load(f)["project"]["version"]


def _read_pkgbuild() -> dict[str, str]:
    """Parse PKGBUILD variables by sourcing it in bash and printing them."""
    result = subprocess.run(
        ["bash", "-c", f"""
set -eu
source '{PKGBUILD_DIR / "PKGBUILD"}'
echo "pkgname=${{pkgname:-}}"
echo "pkgver=${{pkgver:-}}"
echo "pkgrel=${{pkgrel:-}}"
echo "pkgdesc=${{pkgdesc:-}}"
echo "arch=${{arch[*]:-}}"
echo "url=${{url:-}}"
echo "license=${{license[*]:-}}"
echo "depends=${{depends[*]:-}}"
echo "makedepends=${{makedepends[*]:-}}"
echo "optdepends=${{optdepends[*]:-}}"
"""],
        capture_output=True, text=True, check=True,
    )
    parsed = {}
    for line in result.stdout.strip().splitlines():
        if "=" in line:
            key, val = line.split("=", 1)
            parsed[key] = val
    return parsed


@_PKGBUILD_NEEDS_MAKEPKG
def test_pkgbuild_parses():
    """PKGBUILD must source without errors and define required fields."""
    parsed = _read_pkgbuild()
    assert parsed.get("pkgname") == "trustsight"
    assert parsed.get("pkgver"), "pkgver is required"
    assert parsed.get("pkgrel"), "pkgrel is required"
    assert parsed.get("pkgdesc"), "pkgdesc is required"
    assert "any" in parsed.get("arch", "")
    assert parsed.get("url") == "https://github.com/emiliano-go/trustsight"
    assert "MIT" in parsed.get("license", "")
    assert "python" in parsed.get("depends", "")
    assert "python-pygit2" in parsed.get("depends", "")


@_PKGBUILD_NEEDS_MAKEPKG
def test_pkgbuild_source_has_no_skipped_checksums():
    """sha256sums must not contain SKIP."""
    for line in _pkgbuild_text().splitlines():
        if line.startswith("sha256sums"):
            assert "SKIP" not in line, "sha256sums must not contain SKIP"


@_PKGBUILD_NEEDS_MAKEPKG
def test_makepkg_can_print_srcinfo():
    """makepkg --printsrcinfo must produce valid .SRCINFO output."""
    result = subprocess.run(
        ["makepkg", "--printsrcinfo"],
        capture_output=True, text=True,
        cwd=str(PKGBUILD_DIR),
    )
    assert result.returncode == 0, (
        f"makepkg --printsrcinfo failed:\n{result.stdout}\n{result.stderr}"
    )
    assert "pkgname =" in result.stdout
    assert "pkgver =" in result.stdout


def test_pkgbuild_version_matches_pyproject():
    """PKGBUILD pkgver must match pyproject.toml version."""
    assert _pkgver_from_pkgbuild() == _version_from_pyproject(), (
        f"PKGBUILD pkgver ({_pkgver_from_pkgbuild()}) "
        f"!= pyproject.toml version ({_version_from_pyproject()})"
    )


def test_pkgbuild_covers_all_pyproject_deps():
    """Every pyproject dependency must have a matching PKGBUILD depends."""
    pyproject_deps = set()
    with open(PYPROJECT, "rb") as f:
        for dep in tomllib.load(f)["project"]["dependencies"]:
            pkg = dep.split(">=")[0].split("<")[0].split("!=")[0].strip()
            pyproject_deps.add(pkg)

    pkgbuild_deps = _depends_from_pkgbuild()
    for pypi_name in pyproject_deps:
        arch_name = _PYPI_TO_ARCH.get(pypi_name)
        assert arch_name is not None, f"unknown mapping for {pypi_name!r}"
        assert arch_name in pkgbuild_deps, (
            f"{arch_name} (from {pypi_name}) missing from PKGBUILD depends"
        )


def test_cryptography_is_not_in_optdepends():
    """python-cryptography must be in depends, not optdepends."""
    deps = _depends_from_pkgbuild()
    opts = _optdepends_from_pkgbuild()
    assert "python-cryptography" in deps, (
        "python-cryptography must be a hard dependency"
    )
    assert not any(d.startswith("python-cryptography") for d in opts), (
        "python-cryptography must not appear in optdepends"
    )



