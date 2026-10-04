"""H103: the metadata and the recipe disagree on a security-relevant field.

A stale ``.SRCINFO`` is the ordinary benign shape, so a differing pkgver
alone stays silent; a divergent install hook, checksum array or dependency
list fires.
"""

from trustsight.analysis.crossfile import metadata_recipe_divergence

PKGBUILD = """\
pkgname=demo
pkgver=1.0
install=demo.install
depends=('glibc' 'zlib')
source=('https://example.invalid/demo-1.0.tar.gz')
sha256sums=('aaaa')
"""

SRCINFO = """\
pkgbase = demo
\tpkgver = 1.0
\tinstall = demo.install
\tdepends = glibc
\tdepends = zlib
\tsource = https://example.invalid/demo-1.0.tar.gz
\tsha256sums = aaaa
"""


def test_matching_documents_are_silent():
    assert metadata_recipe_divergence(PKGBUILD, SRCINFO) == []


def test_a_stale_pkgver_alone_is_silent():
    stale = SRCINFO.replace("\tpkgver = 1.0", "\tpkgver = 0.9")
    assert metadata_recipe_divergence(PKGBUILD, stale) == []


def test_a_divergent_checksum_fires():
    changed = SRCINFO.replace("\tsha256sums = aaaa", "\tsha256sums = bbbb")
    assert metadata_recipe_divergence(PKGBUILD, changed) == ["sha256sums"]


def test_a_divergent_install_hook_fires():
    changed = SRCINFO.replace("\tinstall = demo.install", "\tinstall = other.install")
    assert metadata_recipe_divergence(PKGBUILD, changed) == ["install"]


def test_a_divergent_dependency_fires():
    changed = SRCINFO.replace("\tdepends = zlib", "\tdepends = evil-pkg")
    assert metadata_recipe_divergence(PKGBUILD, changed) == ["depends"]


def test_reordering_is_not_divergence():
    reordered = SRCINFO.replace(
        "\tdepends = glibc\n\tdepends = zlib",
        "\tdepends = zlib\n\tdepends = glibc",
    )
    assert metadata_recipe_divergence(PKGBUILD, reordered) == []


def test_unresolved_values_are_not_compared():
    pkgbuild = PKGBUILD.replace(
        "sha256sums=('aaaa')", "sha256sums=(\"${sums[@]}\")"
    )
    changed = SRCINFO.replace("\tsha256sums = aaaa", "\tsha256sums = bbbb")
    assert metadata_recipe_divergence(pkgbuild, changed) == []


def test_absent_metadata_is_silent():
    assert metadata_recipe_divergence(PKGBUILD, None) == []
    assert metadata_recipe_divergence(PKGBUILD, "") == []
