import re
import shutil
import subprocess
from pathlib import Path

import pytest
import tomllib


ROOT = Path(__file__).resolve().parent.parent
PKGBUILD_DIR = ROOT / "packaging" / "aur"
PYPROJECT = ROOT / "pyproject.toml"
SRCINFO = PKGBUILD_DIR / ".SRCINFO"

_PKGBUILD_NEEDS_MAKEPKG = pytest.mark.skipif(
    not shutil.which("makepkg"),
    reason="makepkg not available (non-Arch system)",
)

# Release archives exclude packaging/ by .gitattributes export-ignore (a
# tarball cannot contain the PKGBUILD for its own checksum), so the tests in
# this module cannot run from the shipped artifact; they run in the repo
# checkout, which is where the PKGBUILD lives.
pytestmark = pytest.mark.skipif(
    not (PKGBUILD_DIR / "PKGBUILD").exists(),
    reason="PKGBUILD not present (release archive excludes packaging/)",
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


def _srcinfo_field(name: str) -> str | None:
    """Read a top-level `key = value` field from .SRCINFO."""
    m = re.search(rf"^\s*{re.escape(name)} = (\S+)\s*$", SRCINFO.read_text(), re.M)
    return m.group(1) if m else None


@pytest.mark.skipif(not SRCINFO.exists(), reason=".SRCINFO not present")
def test_srcinfo_version_matches_pkgbuild():
    """.SRCINFO is what the AUR reads, and it is a generated file that is
    committed, so nothing forces it to agree with the PKGBUILD beside it.

    `release-pkgbuild.yml` regenerates it on every tag, but the version-bump
    commit that precedes the tag edits both by hand. A .SRCINFO left on the
    previous version advertises the wrong package to the AUR for the whole
    release window, and neither makepkg nor any other test notices.
    """
    assert _srcinfo_field("pkgver") == _pkgver_from_pkgbuild(), (
        f".SRCINFO pkgver ({_srcinfo_field('pkgver')}) "
        f"!= PKGBUILD pkgver ({_pkgver_from_pkgbuild()})"
    )
    assert _srcinfo_field("pkgver") == _version_from_pyproject()
    assert _srcinfo_field("pkgname") == "trustsight"


@pytest.mark.skipif(not SRCINFO.exists(), reason=".SRCINFO not present")
def test_srcinfo_source_and_checksum_match_pkgbuild():
    """.SRCINFO carries the *expanded* source line, so it can go stale in a
    way the pkgver field does not show.

    v0.13.1 shipped `pkgver = 0.13.1` beside
    `source = trustsight-0.13.0.tar.gz::.../v0.13.0.tar.gz`: the version
    field had been bumped by hand and the expanded line had not, because the
    workflow that regenerates this file never ran.
    """
    version = _pkgver_from_pkgbuild()
    source = _srcinfo_field("source")
    assert source is not None, ".SRCINFO declares no source"
    assert f"trustsight-{version}.tar.gz" in source, (
        f".SRCINFO source line does not name {version}: {source}"
    )
    assert f"/v{version}/" in source, (
        f".SRCINFO source line does not point at the v{version} release: {source}"
    )

    recorded = re.search(r"^sha256sums=\('(.*)'\)$", _pkgbuild_text(), re.M)
    assert recorded, "PKGBUILD records no sha256sums"
    assert _srcinfo_field("sha256sums") == recorded.group(1)


def test_source_is_a_release_asset_not_a_generated_archive():
    """GitHub generates `/archive/refs/tags/` tarballs on demand and does not
    guarantee their bytes; the gzip settings behind them changed in 2023 and
    invalidated recorded checksums across every distribution at once.

    A release asset is an immutable blob. Reverting to the generated archive
    would reintroduce that exposure silently, since it looks identical right
    up until the day the bytes move.
    """
    source = re.search(r"^source=\((.*)\)$", _pkgbuild_text(), re.M)
    assert source, "PKGBUILD declares no source"
    assert "/releases/download/" in source.group(1), (
        f"source must be a release asset, got: {source.group(1)}"
    )
    assert "/archive/refs/tags/" not in source.group(1), (
        "source points at GitHub's generated archive, whose bytes are not "
        "guaranteed stable"
    )


def _latest_version_tag() -> str | None:
    """The highest `vX.Y.Z` tag in the checkout, or None if there is none."""
    result = subprocess.run(
        ["git", "tag", "--list", "v[0-9]*", "--sort=-v:refname"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    for tag in result.stdout.split():
        if re.fullmatch(r"v\d+\.\d+\.\d+", tag):
            return tag
    return None


@pytest.mark.skipif(
    not (ROOT / ".git").exists(),
    reason="not a git checkout (running from a release archive)",
)
def test_recorded_checksum_matches_the_recorded_version():
    """The PKGBUILD checksum must describe the tree its `pkgver` names.

    It is tempting to require the checksum to match a freshly built
    *working tree* on every commit. That is the trap: it forces `master`
    away from the published asset between releases, because every content
    commit changes the tree while `pkgver` (and the asset) stays put. The
    v0.16.0 report came from exactly that: three commits replaced the
    published v0.16.0 checksum with the checksum of an unreleased tree.

    So the checksum is tied to the version, not to the branch tip:

    * `pkgver` already has a tag: the checksum must describe that tag, which
      is immutable, so content commits between releases cannot move it.
    * `pkgver` has no tag yet: a release is being prepared, and the checksum
      must describe the tree about to be tagged.

    Either way the value can be checked before the tag exists, which is what
    makes the pre-tag ordering of `releasing.md` possible.
    """
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from build_release_tarball import build

    pkgver = _pkgver_from_pkgbuild()
    recorded = re.search(r"^sha256sums=\('(.*)'\)$", _pkgbuild_text(), re.M)
    assert recorded, "PKGBUILD records no sha256sums"

    latest = _latest_version_tag()
    rev = latest if latest == f"v{pkgver}" else "WORKTREE"
    _, digest = build(rev, pkgver)
    assert digest == recorded.group(1), (
        f"PKGBUILD records {recorded.group(1)} for {pkgver}, but {rev} "
        f"builds {digest}; run scripts/build_release_tarball.py --rev {rev} "
        f"and update the PKGBUILD in the same commit as the version"
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



