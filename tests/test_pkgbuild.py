import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

PKGBUILD_DIR = Path(__file__).resolve().parent.parent / "packaging" / "aur"

pytestmark = pytest.mark.skipif(
    not shutil.which("makepkg"),
    reason="makepkg not available (non-Arch system)",
)


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


def test_pkgbuild_source_has_no_skipped_checksums():
    """sha256sums must not contain SKIP."""
    pkgbuild = (PKGBUILD_DIR / "PKGBUILD").read_text()
    for line in pkgbuild.splitlines():
        if line.startswith("sha256sums"):
            assert "SKIP" not in line, "sha256sums must not contain SKIP"


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



