"""Unit tests for the typed recipe core (recipedoc).

RecipeDoc is the layer-2 surface: a PKGBUILD read once by the tokenizer,
with the refusal list first-class.  These tests pin the shapes the
array/function queries must answer and the parity shapes inherited from
the legacy ``properties._build_function_bodies`` walk.
"""

from trustsight.diffdoc import parse_diff
from trustsight.recipedoc import (
    array_alignment,
    array_diff,
    parse_recipe,
    recipe_from_post_state,
    recipe_states,
)
from trustsight.tokenizer import variable_table_spans

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


def test_unresolved_assignments_carry_name_line_and_file():
    doc = parse_recipe(PKGBUILD, file="PKGBUILD")
    names = {a.name for a in doc.unresolved_assignments}
    assert "_now" in names
    entry = next(a for a in doc.unresolved_assignments if a.name == "_now")
    assert "_now" in entry.line
    assert entry.file == "PKGBUILD"
    assert entry.to_dict()["name"] == "_now"


def test_a_refused_reassignment_reads_as_not_seen():
    doc = parse_recipe("pkgver=1\npkgver=$(date +%s)\n")
    assert "pkgver" not in doc.scalars
    # The refusal is not reported: the name did resolve earlier, and the
    # X-series rates are adjudicated on that reporting surface.
    assert doc.unresolved == ()


def test_a_later_resolved_assignment_wins():
    doc = parse_recipe("_url=$(curl -s https://x)\n_url=https://ok\n")
    assert doc.scalars["_url"] == "https://ok"
    assert doc.unresolved == ()


def test_a_refused_append_clears_the_previous_value():
    doc = parse_recipe("_flags=-O2\n_flags+=$(echo x)\n")
    assert "_flags" not in doc.scalars
    assert doc.unresolved == ()


def test_an_array_assignment_with_a_substitution_reads_as_not_seen():
    doc = parse_recipe(
        'source=("https://a/b.tar.gz")\nsource=($(curl -s https://x))\n'
    )
    assert "source" not in doc.arrays
    assert doc.unresolved == ()


def test_a_never_resolved_scalar_substitution_is_named():
    doc = parse_recipe("pkgver=$(date +%s)\n")
    assert doc.unresolved == ("pkgver=$(date +%s)",)
    assert [a.name for a in doc.unresolved_assignments] == ["pkgver"]


def test_a_substituted_array_reads_as_not_seen_without_a_new_refusal():
    # The old reader stored the shredded entries, so the name counted as
    # kept and was never reported; the fix hides the value from readers
    # without changing that reporting surface (the X-series rates are
    # adjudicated on it).
    doc = parse_recipe("source=($(curl -s https://x))\n")
    assert "source" not in doc.arrays
    assert doc.unresolved == ()


def test_a_single_quoted_substitution_array_is_kept():
    doc = parse_recipe("source=('$(literal)')\n")
    assert doc.arrays["source"] == ("$(literal)",)
    assert doc.unresolved == ()


def test_an_array_with_a_parameter_expansion_is_kept():
    doc = parse_recipe('pkgver=1\nsource=("https://x/$pkgver.tar.gz")\n')
    assert doc.arrays["source"] == ("https://x/$pkgver.tar.gz",)
    assert doc.unresolved == ()


def test_array_diff_sets_and_order():
    delta = array_diff(("a", "b", "c"), ("b", "a", "d"))
    assert delta.gained == ("d",)
    assert delta.lost == ("c",)
    assert delta.reordered
    same = array_diff(("a", "b"), ("a", "b"))
    assert not same.gained and not same.lost and not same.reordered


def test_array_diff_counts_duplicate_occurrences():
    added = array_diff(("a",), ("a", "a", "a"))
    assert added.gained == ("a", "a")
    assert added.lost == ()
    assert not added.reordered
    removed = array_diff(("a", "a", "b"), ("a", "b"))
    assert removed.gained == ()
    assert removed.lost == ("a",)
    assert not removed.reordered


def test_array_diff_multiplicity_is_not_a_reorder():
    delta = array_diff(("a", "a", "b"), ("a", "b", "b"))
    assert delta.gained == ("b",)
    assert delta.lost == ("a",)
    assert not delta.reordered


def test_array_alignment_pairs_around_a_mid_array_insert():
    alignment = array_alignment(("a", "b", "c"), ("a", "x", "b", "c"))
    assert alignment.pairs == ((0, 0, "a"), (1, 2, "b"), (2, 3, "c"))
    assert alignment.inserted == ((1, "x"),)
    assert alignment.deleted == ()
    assert not alignment.reordered


def test_array_alignment_reports_a_replacement_as_delete_and_insert():
    alignment = array_alignment(("a", "b"), ("a", "d"))
    assert alignment.pairs == ((0, 0, "a"),)
    assert alignment.deleted == ((1, "b"),)
    assert alignment.inserted == ((1, "d"),)
    assert not alignment.reordered


def test_array_alignment_marks_a_move_as_reordered():
    alignment = array_alignment(("a", "b"), ("b", "a"))
    assert alignment.reordered
    assert alignment.inserted and alignment.deleted


def test_signing_key_change_is_one_query():
    # The H078 shape: no state machine, one array_diff.
    old = parse_recipe("validpgpkeys=('AAAAAAAAAAAAAAAA')\n")
    new = parse_recipe("validpgpkeys=('BBBBBBBBBBBBBBBB')\n")
    delta = array_diff(old.arrays["validpgpkeys"], new.arrays["validpgpkeys"])
    assert delta.gained == ("BBBBBBBBBBBBBBBB",)
    assert delta.lost == ("AAAAAAAAAAAAAAAA",)


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


def test_variable_table_spans_name_source_lines():
    variables, arrays, spans = variable_table_spans([
        "x=1",
        "source=('a'",
        "        'b')",
    ])
    assert variables["x"] == "1"
    assert arrays["source"] == ["a", "b"]
    assert spans["scalars"]["x"] == 0
    assert spans["arrays"]["source"] == {"open": 1, "close": 2, "entries": [1, 2]}


def test_recipe_spans_name_the_line_of_each_value():
    doc = parse_recipe(
        "pkgname=foo\n"
        "pkgver=1.0\n"
        "source=('a.tar.gz'\n"
        "        'b.tar.gz')\n"
        "build() {\n"
        "  make\n"
        "}\n"
    )
    assert doc.scalar_spans["pkgver"].line == 2
    assert [span.line for span in doc.array_spans["source"]] == [3, 4]
    assert doc.array_spans["source"][0].side == ""
    assert doc.function_spans["build"].line == 5


def test_recipe_states_spans_carry_file_line_and_side():
    diff = (
        "--- a/PKGBUILD\n"
        "+++ b/PKGBUILD\n"
        "@@ -1,3 +1,4 @@\n"
        " pkgname=foo\n"
        "-source=('https://old.example/a.tar.gz')\n"
        "+source=('https://new.example/a.tar.gz')\n"
        "+install=foo.install\n"
    )
    pre, post = recipe_states(parse_diff(diff))
    added = post.array_spans["source"][0]
    assert (added.file, added.line, added.side) == ("PKGBUILD", 2, "add")
    removed = pre.array_spans["source"][0]
    assert (removed.file, removed.line, removed.side) == ("PKGBUILD", 2, "remove")
    install = post.scalar_spans["install"]
    assert (install.file, install.line, install.side) == ("PKGBUILD", 3, "add")


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


def test_array_alignment_refuses_over_the_cell_cap():
    import pytest

    from trustsight.recipedoc import MAX_ALIGNMENT_CELLS, AlignmentTooLarge

    side = int(MAX_ALIGNMENT_CELLS ** 0.5) + 1
    with pytest.raises(AlignmentTooLarge):
        array_alignment(("a",) * side, ("a",) * side)


def test_continuations_join_and_spans_name_the_first_physical_line():
    text = "pkgver=\\\n1.2.3\nbuild() \\\n{\n  make\n}\n"
    doc = parse_recipe(text)
    assert doc.scalars["pkgver"] == "1.2.3"
    assert doc.scalar_spans["pkgver"].line == 1
    assert "make" in doc.functions["build"]
    assert doc.function_spans["build"].line == 3
