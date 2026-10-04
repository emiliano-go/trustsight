"""Differential oracle: tree-sitter-bash against the typed recipe scanner.

tree-sitter is a real Bash grammar, so where it and
``recipedoc._function_segments`` disagree on a function definition, one of
them is wrong.  Only texts the grammar parses without errors compare, so a
truncated fragment does not turn a parser artifact into a failure.
"""

from pathlib import Path

import pytest

tree_sitter = pytest.importorskip("tree_sitter")
tree_sitter_bash = pytest.importorskip("tree_sitter_bash")

from tree_sitter import Language, Parser  # noqa: E402

from trustsight.recipedoc import _function_segments  # noqa: E402
from trustsight.tokenizer import split_lines  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

_LANGUAGE = Language(tree_sitter_bash.language())

CONSTRUCTS = [
    "build() {\n  make\n}\n",
    "function build {\n  make\n}\n",
    "function build() {\n  make\n}\n",
    "function package-bin {\n  true\n}\n",
    "build() { make; }\n",
    "build() {\n  echo \"}\"\n  make\n}\n",
    "build() {\n  # }\n  make\n}\n",
    "build() {\n  cat <<EOF\n}\nEOF\n  make\n}\n",
    "build() {\n  echo \"{\"\n}\npackage() { true; }\n",
    "build() {\n  make\n}\nbuild() {\n  true\n}\n",
    "pkgver() \\\n{\n  echo 1\n}\n",
]


def _tree_sitter_functions(text: str) -> set[str] | None:
    tree = Parser(_LANGUAGE).parse(text.encode("utf-8"))
    if tree.root_node.has_error:
        return None
    names: set[str] = set()

    def walk(node) -> None:
        if node.type == "function_definition":
            name = node.child_by_field_name("name")
            if name is not None:
                names.add(name.text.decode("utf-8"))
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return names


@pytest.mark.parametrize("text", CONSTRUCTS)
def test_function_definitions_match_tree_sitter(text):
    expected = _tree_sitter_functions(text)
    assert expected is not None, "construct does not parse cleanly"
    found = {name for name, _body, _opener in _function_segments(split_lines(text))}
    assert found == expected


def test_a_corpus_slice_matches_tree_sitter():
    checked = 0
    for path in sorted((FIXTURES / "malicious").rglob("*.diff"))[:40]:
        from trustsight.diffdoc import parse_diff

        post = "\n".join(parse_diff(path.read_text(errors="replace")).post_lines())
        expected = _tree_sitter_functions(post)
        if expected is None:
            continue
        checked += 1
        found = {name for name, _b, _o in _function_segments(split_lines(post))}
        assert found == expected, path
    assert checked, "no malicious fixture parsed cleanly"
