"""The shared lexical scanner behind recipe bodies and rule scopes.

Both readers used to count braces on the raw line.  These tests pin the
constructs that fooled them: quoted braces, comments, heredocs and
escapes, for the scanner itself and for each reader's projection.
"""

from trustsight.line_lex import lex_lines
from trustsight.recipedoc import parse_recipe
from trustsight.rules import _classify_line_context, _enclosing_function_map


def _deltas(lines):
    return [lex.brace_delta for lex in lex_lines(lines)]


def test_braces_in_quotes_are_not_code():
    assert _deltas(['echo "}"', "echo '}'", "echo }"]) == [0, 0, -1]


def test_a_comment_brace_is_not_code():
    assert _deltas(["# }", "  # {", "true # }"]) == [0, 0, 0]


def test_a_heredoc_body_is_not_code():
    assert _deltas(["cat <<EOF", "}", "EOF", "}"]) == [0, 0, 0, -1]


def test_a_substitution_inside_double_quotes_is_code():
    assert _deltas(['echo "$(foo { )"']) == [1]


def test_an_escaped_brace_is_not_code():
    assert _deltas([r"echo \{", r"echo \}"]) == [0, 0]


def test_an_unterminated_quote_carries_across_lines():
    assert _deltas(['echo "start', "}", '"']) == [0, 0, 0]


def test_a_diff_prefixed_terminator_ends_a_heredoc():
    assert _deltas(['+cat <<EOF', "+}", "+EOF", "+}"]) == [0, 0, 0, -1]


def test_a_fragment_ends_a_heredoc_at_a_file_header():
    lines = ["+cat <<EOF", "+}", "diff --git a/PKGBUILD b/PKGBUILD", "+pkgver=2"]
    lexed = lex_lines(lines, fragment=True)
    assert lexed[1].heredoc_body
    assert not lexed[3].heredoc_body


def test_a_fragment_resets_an_unterminated_quote_each_line():
    lines = ['+echo "start', "+}", '+echo "end"']
    lexed = lex_lines(lines, fragment=True)
    # The unterminated quote does not blank the next fragment line.
    assert lexed[1].code.strip() == "+}"
    assert lexed[1].brace_delta == -1
    # And the whole-file read does carry it, as a real file would.
    whole = lex_lines(lines)
    assert whole[1].brace_delta == 0


def test_a_quoted_brace_does_not_close_the_body():
    doc = parse_recipe(
        "build() {\n  echo \"}\"\n  make\n}\npackage() { true; }\n"
    )
    assert "make" in doc.functions["build"]
    assert "package()" not in doc.functions["build"]


def test_a_comment_brace_does_not_close_the_body():
    doc = parse_recipe(
        "build() {\n  # }\n  make\n}\npackage() { true; }\n"
    )
    assert "make" in doc.functions["build"]
    assert "package()" not in doc.functions["build"]


def test_a_heredoc_brace_does_not_close_the_body():
    doc = parse_recipe(
        "build() {\n  cat <<EOF\n}\nEOF\n  make\n}\npackage() { true; }\n"
    )
    assert "make" in doc.functions["build"]
    assert "package()" not in doc.functions["build"]


def test_a_quoted_open_brace_does_not_swallow_the_next_function():
    doc = parse_recipe(
        'build() {\n  echo "{"\n}\npackage() { true; }\n'
    )
    assert "package" in doc.functions
    assert "package()" not in doc.functions["build"]


def test_scope_stays_in_the_body_past_a_quoted_close():
    lines = ['+build() {', '+  echo "}"', "+  make", "+}", "+package() {"]
    contexts = _classify_line_context(lines)
    assert contexts[3] == "function_body"
    assert contexts[4] == "other"


def test_a_quoted_header_string_does_not_open_a_function():
    lines = ['+build() {', '+  echo "package() {"', "+  make", "+}"]
    enclosing = _enclosing_function_map(lines)
    assert enclosing.get(3) == "build"
    assert all(name == "build" for name in enclosing.values() if name)
