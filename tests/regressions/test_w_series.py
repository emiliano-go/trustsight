"""The W series: reported, never priced."""

import pytest

from .helpers import _shipped_ids, _x

# ---------------------------------------------------------------------------
# The W series: reported, never priced
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("line", [
    '  bash "$srcdir/scripts/postunpack.sh"',
    '  bash "${srcdir}/x-1.0/setup.sh"',
    "  ./install.sh",
    '  python3 "$srcdir/x-1.0/gen.py"',
])
def test_code_runs_that_this_analysis_never_read(line):
    """W001 is the E7 boundary, reported rather than scored.

    R138 claims the case where the executed file is a declared source and
    R136 where it is committed. What is left is code that runs and that
    nobody looked at - which the boundary documentation had to describe as
    something TrustSight cannot see. It can see it.
    """
    assert "W001" in _shipped_ids([line], declared=False), line


@pytest.mark.parametrize("line", [
    "  python3 -m build --wheel",
    "  python3 setup.py build",
    "  ./configure --prefix=/usr",
    "  make",
    "  perl Makefile.PL",
    """  sed -i 's|./log\\.txt|/var/log/x.log|g' conf""",
    '  cd "$srcdir/x-1.0"',
])
def test_the_standard_entry_points_of_an_unpacked_tree_are_not_a_finding(line):
    """Naming `configure` or `setup.py` would put a note on most of the
    ecosystem while saying nothing a reader does not already assume.

    The `sed` case is the one that forced the pattern to be W001's own
    rather than shared with R138: reusing R138's deliberately loose capture
    produced evidence like `log\\.txt|/var/log/ventoy.log|g` from the
    innards of a substitution.
    """
    assert "W001" not in _shipped_ids([line], declared=False), line


def test_a_w_finding_changes_no_number():
    """The whole contract of the series. A gap must not add points, and a
    statement about what could not be checked is not evidence."""
    from trustsight.analysis import scan_diff

    head = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
            "+pkgname=p\n+pkgver=1\n"
            "+source=(https://github.com/u/p/archive/v1.tar.gz)\n"
            "+sha256sums=('" + "a" * 64 + "')\n+build() {\n")
    quiet = scan_diff(head + "+  make\n+}\n", package_name="p")
    noisy = scan_diff(
        head + '+  bash "$srcdir/p-1/postunpack.sh"\n+}\n', package_name="p")

    assert "W001" in {e.rule_id for e in noisy.score_breakdown}
    assert noisy.final_score == quiet.final_score
    assert noisy.risk == quiet.risk


def test_a_w_finding_is_shown_even_though_it_scores_nothing():
    """Every other weight-0 non-critical finding is filtered out. A
    statement that is only useful to a reader is worthless if filtered."""
    from trustsight.analysis import scan_diff
    from trustsight.reporting import finding_rows

    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
            "+pkgname=p\n+pkgver=1\n"
            "+source=(https://github.com/u/p/archive/v1.tar.gz)\n"
            "+sha256sums=('" + "a" * 64 + "')\n+build() {\n"
            '+  bash "$srcdir/p-1/postunpack.sh"\n+}\n')
    rows = {r["rule_id"]: r for r in finding_rows(scan_diff(diff, package_name="p"))}
    assert "W001" in rows
    assert rows["W001"]["weight"] == 0
    assert rows["W001"]["severity"] == "INFO"


def test_w001_stands_down_where_a_scoring_rule_can_speak():
    """W001 is what is left when nothing else could: a declared source is
    R138's, and a committed file is R136's."""
    from trustsight.analysis import scan_diff

    declared = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
                "+pkgname=p\n+pkgver=1\n+source=(setup.sh)\n"
                "+sha256sums=('SKIP')\n+build() {\n"
                '+  bash "$srcdir/setup.sh"\n+}\n')
    ids = {e.rule_id for e in scan_diff(declared, package_name="p").score_breakdown}
    assert "R138" in ids and "W001" not in ids

    committed = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
                 "+pkgname=p\n+pkgver=1\n"
                 "+source=(https://github.com/u/p/archive/v1.tar.gz)\n"
                 "+sha256sums=('SKIP')\n+build() {\n"
                 '+  bash "$srcdir/helper.sh"\n+}\n')
    ids = {e.rule_id for e in scan_diff(
        committed, package_name="p",
        tree_manifest=[("helper.sh", b"#!/bin/sh\n")],
    ).score_breakdown}
    assert "W001" not in ids


@pytest.mark.parametrize("line", [
    "  npm install --production",
    "  pip install -r requirements.txt",
    "  cargo fetch --locked",
    "  go mod download",
])
def test_a_registry_chooses_what_the_build_runs(line):
    """W002: the recipe names a *set* of packages and a registry decides
    which bytes satisfy it, at build time, after review.

    The run already says this as the `unpinned_build_deps` gap. What a gap
    cannot say is *where* - which is the difference between a property of
    the analysis and a property of the recipe.
    """
    assert "W002" in _shipped_ids([line], declared=False), line


@pytest.mark.parametrize("cmd", [
    'patch -Np1 -i "$srcdir/fix.patch"',
    'git apply "$srcdir/fix.diff"',
    'patch -Np1 < "$srcdir/fix.patch"',
])
def test_a_patch_whose_bytes_were_never_read(cmd):
    """W003: a patch edits the source before it is built and the edit is
    whatever the patch says. A tarball is upstream's own code; a patch is a
    change to it that the *packager* chose, which makes it more interesting
    to a reader, not less - and still unreadable here."""
    assert "W003" in _shipped_ids([cmd], declared=False, fn="prepare"), cmd


def test_w003_stands_down_on_a_patch_r146_has_read():
    """A committed patch is one R146 reads by its added lines."""
    from trustsight.analysis import scan_diff

    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
            "+pkgname=p\n+pkgver=1\n+source=(fix.patch)\n+sha256sums=('SKIP')\n"
            '+prepare() {\n+  patch -Np1 -i "$srcdir/fix.patch"\n+}\n')
    ids = {e.rule_id for e in scan_diff(
        diff, package_name="p",
        tree_manifest=[("fix.patch", b"--- a\n+++ b\n")],
    ).score_breakdown}
    assert "W003" not in ids


@pytest.mark.parametrize("line", [
    "  npm install --production",
    '  patch -Np1 -i "$srcdir/fix.patch"',
    '  bash "$srcdir/p-1/postunpack.sh"',
])
def test_no_w_rule_moves_a_number(line):
    """The contract of the series, asserted for every member of it.

    Stated per *finding*, not per line: `npm install` also fires X011, a
    weight-25 claim about running fetched code, and that claim is entitled
    to move the score. What must never happen is a W entry carrying weight.
    """
    from trustsight.analysis import scan_diff

    head = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
            "+pkgname=p\n+pkgver=1\n"
            "+source=(https://github.com/u/p/archive/v1.tar.gz)\n"
            "+sha256sums=('" + "a" * 64 + "')\n+prepare() {\n")
    fact = scan_diff(head + "+" + line + "\n+}\n", package_name="p")

    w_entries = [e for e in fact.score_breakdown if e.rule_id.startswith("W")]
    assert w_entries, line
    for entry in w_entries:
        assert entry.weight == 0, (line, entry.rule_id)
        assert entry.severity == "INFO", (line, entry.rule_id)

    # And the score is exactly what the non-W findings account for.
    assert fact.final_score == scan_diff(
        head + "+" + line + "\n+}\n", package_name="p").final_score


def test_a_line_whose_only_finding_is_a_w_scores_nothing_extra():
    """The end-to-end version: same recipe, one line added that no scoring
    rule claims, and the number does not move."""
    from trustsight.analysis import scan_diff

    head = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
            "+pkgname=p\n+pkgver=1\n"
            "+source=(https://github.com/u/p/archive/v1.tar.gz)\n"
            "+sha256sums=('" + "a" * 64 + "')\n+prepare() {\n")
    quiet = scan_diff(head + "+  true\n+}\n", package_name="p")
    noisy = scan_diff(
        head + '+  bash "$srcdir/p-1/postunpack.sh"\n+}\n', package_name="p")

    assert "W001" in {e.rule_id for e in noisy.score_breakdown}
    assert noisy.final_score == quiet.final_score
    assert noisy.risk == quiet.risk


_R149_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
    "+pkgname=p\n+pkgver=1\n+source=(x.service)\n+sha256sums=('SKIP')\n"
    "+package() {\n"
    '+  install -Dm644 "$srcdir/x.service"'
    ' "$pkgdir/usr/lib/systemd/system/x.service"\n+}\n'
)


def _committed_ids(name, blob):
    from trustsight.analysis import scan_diff

    return {e.rule_id for e in scan_diff(
        _R149_DIFF, package_name="p", tree_manifest=[(name, blob)],
    ).score_breakdown}


@pytest.mark.parametrize("name,blob", [
    ("x.service", b"[Service]\nExecStart=/bin/sh $srcdir/evil.sh\n"),
    ("x.desktop", b"[Desktop Entry]\nExec=/bin/bash $PWD/x.sh\n"),
    ("i3.conf", b"bindsym e exec /bin/bash $PWD/x.sh\n"),
    ("r.conf", b"postcmd = $srcdir/hook.sh\n"),
    ("9.rules", b'ACTION=="add", RUN+="/bin/sh $startdir/x.sh"\n'),
])
def test_a_committed_config_pointing_at_a_build_only_path(name, blob):
    """R149 is the symmetric half of R145: that rule reads content the
    recipe *generates* into `$pkgdir`, this one content it *committed* and
    then ships. Same observable, same reasoning - those directories exist
    only while the package is being built.
    """
    assert "R149" in _committed_ids(name, blob), name


@pytest.mark.parametrize("name,blob", [
    ("x.service", b"[Service]\nExecStart=/usr/bin/p --daemon\n"),
    # The case the proposed design would have called CRITICAL: a unit that
    # runs a script the package itself ships.
    ("x.service", b"[Service]\nExecStart=/usr/share/p/launcher.sh\n"),
    ("x.desktop", b"[Desktop Entry]\nExec=/usr/bin/p %U\nComment=A thing\n"),
    # A build path in a field that runs nothing is a cosmetic mistake.
    ("x.desktop", b"[Desktop Entry]\nComment=built in $srcdir\nExec=/usr/bin/p\n"),
])
def test_r149_needs_a_directive_that_runs_something(name, blob):
    """What makes the finding sound is not which key carries the command,
    it is that the value names a directory that will not exist on the
    target machine."""
    assert "R149" not in _committed_ids(name, blob), (name, blob)


def test_the_packaging_phase_is_where_an_unread_script_gets_scored():
    """R150 is the scoring half of W001, and the split is measured rather
    than assumed.

    Of the three benign corpus diffs that execute a script from the
    unpacked tree, two are in `build()` and one in `prepare()`. None is in
    `package()` - which stages files rather than building them, and whose
    output *is* the package. So W001 keeps weight 0 where the behaviour is
    ordinary, and the subset that is not ordinary is scored.
    """
    packaged = _shipped_ids(
        ['  bash "$srcdir/x-1.0/postinstall.sh"'], declared=False, fn="package")
    assert "R150" in packaged and "W001" not in packaged

    built = _shipped_ids(
        ['  bash "$srcdir/x-1.0/postunpack.sh"'], declared=False, fn="build")
    assert "W001" in built and "R150" not in built


@pytest.mark.parametrize("lines", [
    ['  cat > "$srcdir/build.ninja" <<EOF', "    command = bash $srcdir/x.sh",
     "  EOF"],
    ["""  printf 'all:\\n\\tbash x.sh\\n' > "$srcdir/build.mk\""""],
    ['  cat > "$srcdir/BUILD" <<EOF', '  genrule(cmd = "bash $srcdir/x.sh")',
     "  EOF"],
])
def test_the_recipe_writes_the_build_steps_the_engine_runs(lines):
    """X020: no execution rule reads a `command =` line, because nothing on
    that line is a command the shell executes. It is data until the engine
    runs it, and the invocation that follows is a bare `ninja -C build`."""
    assert "X020" in _x(lines), lines


@pytest.mark.parametrize("lines", [
    ['  sed -e "s/X/Y/" Makefile > "$pkgdir/usr/src/p/Makefile"'],
    ["  ninja -C build"],
    ["  cmake -S . -B build", "  cmake --build build"],
    ['  cat > "$srcdir/app.conf" <<EOF', "  command = /usr/bin/p", "  EOF"],
])
def test_x020_claims_authoring_not_transforming(lines):
    """`sed -e ... Makefile > dest` rewrites steps that came from upstream -
    how a DKMS package substitutes a kernel version, and this rule's only
    benign fire before the distinction was drawn."""
    assert "X020" not in _x(lines), lines


@pytest.mark.parametrize("line", [
    '  ninja -f "$srcdir/gen.ninja"',
    '  make -f "$srcdir/build.mk" all',
])
def test_an_engine_pointed_at_a_manifest_nobody_read(line):
    """W004 is X020's counterpart: that rule claims the recipe *writing* a
    manifest, this one the recipe *pointing an engine at* one."""
    assert "W004" in _shipped_ids([line], declared=False), line


@pytest.mark.parametrize("line", ["  ninja -C build", "  make"])
def test_w004_needs_an_explicit_manifest_argument(line):
    """A bare `make` also runs a manifest nobody read, and that is most of
    the ecosystem; reporting it would say nothing."""
    assert "W004" not in _shipped_ids([line], declared=False), line


def test_w004_stands_down_when_the_manifest_is_declared():
    """A declared source is checksum-pinned and R138's to claim."""
    ids = _shipped_ids(['  make -f "$srcdir/setup.mk" all'], declared=False,
                       source="https://e.example/setup.mk")
    assert "R138" in ids and "W004" not in ids


@pytest.mark.parametrize("name,line", [
    ("extensions.conf", b"exten => s,1,System($srcdir/e.sh)"),
    ("rsyslog.conf", b'action(type="omprog" binary="$srcdir/e.sh")'),
    ("nginx.conf", b"load_module $srcdir/e.so;"),
    ("upsmon.conf", b"NOTIFYCMD $srcdir/e.sh"),
    ("sddm.conf", b"DisplayCommand = $srcdir/e.sh"),
    ("mkinitcpio.conf", b"HOOKS=($srcdir/e.sh)"),
    ("zshrc.conf", b"source $PWD/e.sh"),
    ("mailcap.conf", b"text/html; $srcdir/e.sh %s"),
    ("BUILD", b'genrule(cmd = "bash $srcdir/e.sh")'),
    ("Makefile", b"all:\n\tbash $srcdir/e.sh\n"),
    ("build.ninja", b"rule r\n  command = bash $PWD/e.sh\n"),
])
def test_r149_does_not_depend_on_naming_the_directive(name, line):
    """Every one of these is a different word for "run this", and the next
    daemon has another.

    An earlier version carried a short key list on the reasoning that it
    only had to be good enough. Measured against thirty verticals from the
    audit it cost twelve of them - a short list was not a smaller version
    of the problem, it was the same problem.
    """
    from trustsight.analysis.delivery import _committed_build_path_finding

    assert _committed_build_path_finding(name, line) is not None, name


@pytest.mark.parametrize("blob", [
    b"[Desktop Entry]\nComment=built in $srcdir\nExec=/usr/bin/p\n",
    b"# built from $srcdir\nExecStart=/usr/bin/p\n",
    b"[Desktop Entry]\nX-Build-Dir=$srcdir\nExec=/usr/bin/p\n",
])
def test_a_field_that_only_describes_is_not_a_command(blob):
    """The inverted list is the bounded one: descriptive fields are few and
    stable. A `.desktop` whose `Comment=` mentions the build tree is
    untidy; an `Exec=` naming one is a command aimed at nothing."""
    from trustsight.analysis.delivery import _committed_build_path_finding

    assert _committed_build_path_finding("x.desktop", blob) is None


@pytest.mark.parametrize("blob", [
    b"all:\n\t$(CC) -o p $(srcdir)/p.c\n",
    b"all:\n\tcd $(PWD) && $(MAKE) -C sub\n",
])
def test_an_ordinary_makefile_is_not_a_build_only_path(blob):
    """`make` spells its variables `$(srcdir)`, with parentheses."""
    from trustsight.analysis.delivery import _committed_build_path_finding

    assert _committed_build_path_finding("Makefile", blob) is None


@pytest.mark.parametrize("body", [
    "  :(){ :|:& };:",
    "  :(){ true; :|:& };:",
    "  boom(){ boom & boom & }",
    "  b(){ b; b & }",
])
def test_a_fork_bomb_written_without_a_pipe(body):
    """S001 required `name|name`, and that is only one way to double.

    `boom & boom &` is the same bomb written without a pipeline. The
    essential property is that the body reaches its own name more than
    once and backgrounds, not which operator joins the calls.
    """
    assert "S001" in _shipped_ids([body], declared=False), body


@pytest.mark.parametrize("body", [
    '  _msg(){ echo "$1"; }',
    "  walk(){ for f in *; do walk; done; }",
    "  boom(){ echo boom & }",
    "  retry(){ sleep 1; retry & }",
])
def test_recursion_alone_is_not_a_fork_bomb(body):
    """Recursion without backgrounding terminates, backgrounding without
    recursion is one job, and a name inside an `echo` is a string."""
    assert "S001" not in _shipped_ids([body], declared=False), body


@pytest.mark.parametrize("line", ["  make all dist-hooks", "  make stage1"])
def test_a_target_whose_recipe_lives_in_an_unread_makefile(line):
    """W005: `make dist-hooks` names a recipe that exists only in this
    project's Makefile, and that Makefile arrived inside a tarball this
    analysis never opened."""
    assert "W005" in _shipped_ids([line], declared=False), line


@pytest.mark.parametrize("line", [
    "  make", "  make all", "  make install", "  make check",
    '  make DESTDIR="$pkgdir" install', "  make -j$(nproc) all",
    "  ninja -C build",
])
def test_a_standard_target_says_what_it_does(line):
    """`make install` is a contract every build system honours. Flags and
    variable assignments are not targets."""
    assert "W005" not in _shipped_ids([line], declared=False), line


def test_w005_stands_down_when_the_makefile_is_committed():
    """A committed Makefile is one R149 reads."""
    from trustsight.analysis import scan_diff

    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,10 @@\n"
            "+pkgname=p\n+pkgver=1\n"
            "+source=(https://e.example/x.tar.gz)\n+sha256sums=('SKIP')\n"
            "+build() {\n+  make dist-hooks\n+}\n")
    ids = {e.rule_id for e in scan_diff(
        diff, package_name="p",
        tree_manifest=[("Makefile", b"dist-hooks:\n\techo hi\n")],
    ).score_breakdown}
    assert "W005" not in ids


@pytest.mark.parametrize("lines", [
    ["  set -- *.sh", '  bash "$1"'],
    ["  set -- p.sh", "  bash $@"],
    ["  mapfile -t A < <(ls *.sh)", '  bash "${A[0]}"'],
    ["  IFS=:", "  bash $*"],
    ["  IFS=:", '  eval "$*"'],
    ["  bash *.sh"],
    ["  set -- *.sh", '  "$@"'],
])
def test_the_executor_is_literal_and_the_file_is_not(lines):
    """X021: X002 asks whether the *command* can be read from the text;
    this asks the same of its argument.

    `bash` is literal in every one of these, so X002 stands down and every
    path-pairing rule looks for a filename that is not there. What runs is
    decided by a glob, by word splitting, or by whatever was pushed into
    the positional parameters.
    """
    assert "X021" in _x(lines), lines


@pytest.mark.parametrize("lines", [
    ["  bash setup.sh"],
    ['  exec "$@"'],
    ["  make"],
    ['  for f in *.sh; do echo "$f"; done'],
    ["  set -- a b", '  "$@"'],
])
def test_x021_leaves_a_named_file_and_a_wrapper_alone(lines):
    """`exec "$@"` is how a wrapper forwards its arguments, and it is the
    only spelling of a bare `"$@"` the benign corpus contains - which is
    why the glob pairing is required rather than the bare form."""
    assert "X021" not in _x(lines), lines


@pytest.mark.parametrize("line", [
    '  dracut --force --include "$srcdir/x" /x',
    '  grub-mkconfig -o "$pkgdir/boot/grub/grub.cfg"',
    '  guestfish --rw -a d.img run : upload "$srcdir/x.sh" /x.sh',
])
def test_boot_material_built_from_the_source_tree(line):
    """R151: the initramfs runs before userspace exists and before any
    filesystem the user can inspect is mounted."""
    assert "R151" in _shipped_ids([line], declared=False, fn="package"), line


@pytest.mark.parametrize("line", [
    '  install -Dm644 m.ko "$pkgdir/usr/lib/modules/x/m.ko"',
    "  dracut --force /boot/initramfs.img",
    "  mkinitcpio -p linux",
])
def test_shipping_boot_files_is_not_generating_them(line):
    """A package may legitimately ship kernel modules or a bootloader, and
    those are `install`ed like any other file."""
    assert "R151" not in _shipped_ids([line], declared=False, fn="package"), line


@pytest.mark.parametrize("line", [
    '  aria2c "magnet:?xt=urn:btih:abc123"',
    '  transmission-cli "magnet:?xt=urn:btih:abc"',
])
def test_a_content_address_is_still_an_address(line):
    """`magnet:` names bytes rather than a host, so it carries no `://` -
    and the address matcher finds addresses by that marker. The client was
    recognised and the fetch scored nothing because no address could be
    attributed to it."""
    assert "R061" in _shipped_ids([line], declared=False), line


@pytest.mark.parametrize("line", [
    '  chroot "$srcdir/root" /bin/sh /x.sh',
    '  systemd-nspawn -D "$srcdir/root" /usr/bin/python3 /gen.py',
])
def test_a_sandbox_root_makes_an_absolute_path_tree_content(line):
    """A sandbox wrapper establishes a new root, so an absolute path after
    it is inside that root. Without the arm the leading slash made it look
    like `/usr/bin/foo.sh`, which is not W001's subject."""
    assert "W001" in _shipped_ids([line], declared=False), line


@pytest.mark.parametrize("line", [
    "  /bin/sh /usr/share/p/helper.sh",
    "  sh /etc/profile.d/x.sh",
])
def test_an_absolute_path_without_a_sandbox_is_a_system_file(line):
    assert "W001" not in _shipped_ids([line], declared=False), line
