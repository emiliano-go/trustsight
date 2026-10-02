"""Regression tests for v0.17.2 fixes.

Both surfaced in the live AUR watch replay (backfill since 2026-05-01):

- `alacritree-bin` scored 80 on two D001 "novel dependency" hits whose
  names were the package's own `sha256sums_x86_64`/`sha256sums_aarch64`
  values.  A hunk ended with `depends=(` unclosed; the dependency walker's
  array state carried into the next hunk, and since `_closes_array` reads
  a balanced same-line array (`sha256sums=('SKIP' ...)`) as not closing
  anything, the hex sums were collected as dependencies.
- `alpaca-electron-git` reported the added source URL
  `https://registry.npmjs.org}}`: the URL tokeniser kept the closing
  braces of a nested shell default (`${A:-${B:-https://...}}`).
"""

from trustsight.deps import extract_dependency_changes
from trustsight.differ import _clean_url, extract_urls_from_diff


# The shape of the alacritree-bin 0.13.0 -> 0.14.0 diff: one hunk leaves
# `depends=(` open, the next changes only checksum arrays.
_DIFF = """\
--- PKGBUILD
+++ PKGBUILD
@@ -2,11 +2,11 @@

 pkgname=demo-bin
 _pkgname=demo
-pkgver=0.13.0
+pkgver=0.14.0
 pkgrel=1
 arch=('x86_64' 'aarch64')
 license=('Apache-2.0')
 depends=(
   'fontconfig'
@@ -40,8 +40,8 @@

 # checksum comment line one
 # checksum comment line two
 sha256sums=('SKIP' 'SKIP')
-sha256sums_x86_64=('33f855207c36e9dc61c211a09f3ac9df8d614954c778ce77d1dc8dd675dd2c65')
-sha256sums_aarch64=('f028cd86fcbc2e43ea66d05331a2a02bbeec78cab85e7dd4c6d763c7345b0e50')
+sha256sums_x86_64=('21c310af6348eb17fd52ff796605d57d6f3334ef4627d7249c5f2aa36e1e9834')
+sha256sums_aarch64=('a16ec598fe3d9f50eb594a7fed91d7f6052b5996e5521cd3b3bdaca4a74805db')

 package() {
   install -Dm755 demo "$pkgdir/usr/bin/demo"
"""


def test_checksum_values_never_read_as_dependencies():
    added = extract_dependency_changes(_DIFF, "demo-bin")
    for field, names in added.items():
        assert names == set(), f"{field} gained {names}"


def test_an_array_opener_ends_an_array_the_previous_hunk_left_open():
    # The next hunk opens a *tracked* array: the state must switch to it,
    # not read its entries as more of the previous field.
    diff = _DIFF.replace(
        "sha256sums=('SKIP' 'SKIP')", "makedepends=('cmake')"
    ).replace(
        "sha256sums_x86_64=('21c310af6348eb17fd52ff796605d57d6f3334ef4627d7249c5f2aa36e1e9834')",
        "makedepends=('ninja')",
    )
    added = extract_dependency_changes(diff, "demo-bin")
    assert added["makedepends"] == {"ninja"}
    assert added["depends"] == set()


def test_nested_shell_default_braces_do_not_leak_into_urls():
    diff = (
        '--- PKGBUILD\n+++ PKGBUILD\n@@ -1,1 +1,1 @@\n'
        '+ export npm_config_registry='
        '"${NPM_CONFIG_REGISTRY:-${npm_config_registry:-https://registry.npmjs.org}}"\n'
    )
    urls = extract_urls_from_diff(diff)
    assert "https://registry.npmjs.org" in urls.added_urls
    assert all(not u.endswith("}") for u in urls.added_urls)


def test_clean_url_strips_trailing_braces_but_keeps_real_path_braces():
    assert _clean_url("https://registry.npmjs.org}}") == "https://registry.npmjs.org"
    assert _clean_url("https://example.invalid/a}b/c") == "https://example.invalid/a}b/c"
