"""Unit tests for the typed recipe core (recipedoc).

RecipeDoc is the layer-2 surface: a PKGBUILD read once by the tokenizer,
with the refusal list first-class.  These tests pin the shapes the
array/function queries must answer and the parity shapes inherited from
the legacy ``properties._build_function_bodies`` walk.
"""

from trustsight.diffdoc import parse_diff
from trustsight.recipedoc import (
    array_diff,
    parse_recipe,
    recipe_from_post_state,
)

PKGBUILD = """\
pkgname=foo
pkgver=1.2.3
pkgrel=1
arch=('x86_64')
depends=('glibc' 'zlib')
source=("https://example.com/foo-$pkgver.tar.gz"
        'foo.desktop')
sha256sums=('abc123'
            'def456')
validpgpkeys=('0123456789ABCDEF0123456789ABCDEF01234567')
_now=$(date +%s)

build() {
  cd "$pkgname-$pkgver"
  make
}

package() {
  cd "$pkgname-$pkgver"
  make DESTDIR="$pkgdir" install
}
"""


def test_scalars_and_arrays_are_resolved():
    doc = parse_recipe(PKGBUILD)
    assert doc.scalars["pkgname"] == "foo"
    assert doc.scalars["pkgver"] == "1.2.3"
    assert doc.arrays["depends"] == ("glibc", "zlib")
    assert doc.arrays["sha256sums"] == ("abc123", "def456")
    # Array entries keep their literal text (quotes stripped); the table
    # resolves scalar assignments, it does not interpolate into arrays.
    # A rule that needs the interpolation must say so, not assume it.
    assert doc.arrays["source"][0] == "https://example.com/foo-$pkgver.tar.gz"


def test_functions_carry_their_bodies():
    doc = parse_recipe(PKGBUILD)
    assert "make" in doc.functions["build"]
    assert 'DESTDIR' in doc.functions["package"]


def test_unresolved_names_what_the_tokenizer_refused():
    doc = parse_recipe(PKGBUILD)
    assert any("_now" in line for line in doc.unresolved)
    assert "_now" not in doc.scalars


def test_array_diff_sets_and_order():
    delta = array_diff(("a", "b", "c"), ("b", "a", "d"))
    assert delta.gained == frozenset({"d"})
    assert delta.lost == frozenset({"c"})
    assert delta.reordered
    same = array_diff(("a", "b"), ("a", "b"))
    assert not same.gained and not same.lost and not same.reordered


def test_signing_key_change_is_one_query():
    # The H078 shape: no state machine, one array_diff.
    old = parse_recipe("validpgpkeys=('AAAAAAAAAAAAAAAA')\n")
    new = parse_recipe("validpgpkeys=('BBBBBBBBBBBBBBBB')\n")
    delta = array_diff(old.arrays["validpgpkeys"], new.arrays["validpgpkeys"])
    assert delta.gained == frozenset({"BBBBBBBBBBBBBBBB"})
    assert delta.lost == frozenset({"AAAAAAAAAAAAAAAA"})


def test_one_line_body_stays_closed():
    doc = parse_recipe("build() { make; }\npackage() {\n  true\n}\n")
    assert doc.functions["build"] == " make; "
    assert "true" in doc.functions["package"]


def test_brace_on_a_later_line_opens_the_body():
    doc = parse_recipe("build()\n{\n  make\n}\n")
    assert "make" in doc.functions["build"]


def test_redefined_function_keeps_the_last_body():
    doc = parse_recipe("build() { false; }\nbuild() { true; }\n")
    assert doc.functions["build"] == " true; "


def test_recipe_from_post_state():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
        " pkgname=foo\n-pkgver=1.0\n+pkgver=2.0\n"
    )
    doc = recipe_from_post_state(parse_diff(diff))
    assert doc.scalars["pkgver"] == "2.0"


def test_empty_recipe():
    doc = parse_recipe("")
    assert doc.scalars == {}
    assert doc.arrays == {}
    assert doc.functions == {}
    assert doc.unresolved == ()
