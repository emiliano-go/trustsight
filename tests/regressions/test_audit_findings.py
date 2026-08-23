"""Audit findings 1-4: read bounds, padding gaps, named scopes, silent stages."""

import pytest

# ---------------------------------------------------------------------------
# Audit finding 1 - a committed payload larger than the read bound was invisible
#
# `_collect_tree_files` skipped any blob over 512 KiB, on the reasoning that
# "a committed payload is small".  That is an assumption about the attacker,
# and H066 fires on a committed ELF - which is far more likely to be large
# than small.  Worse, `tree_analyzed` still reported True because some other
# file had been read, so the run presented as complete.
# ---------------------------------------------------------------------------


def test_a_large_blob_is_read_not_skipped():
    """A 1 MiB ELF is still identified by its magic bytes."""
    import pygit2
    import tempfile
    from trustsight.analysis.pipeline import _collect_tree_files

    with tempfile.TemporaryDirectory() as tmp:
        repo = pygit2.init_repository(tmp, bare=True)
        big = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * (1024 * 1024)
        blob = repo.create_blob(big)
        builder = repo.TreeBuilder()
        builder.insert("payload.bin", blob, pygit2.GIT_FILEMODE_BLOB)
        tree = builder.write()
        sig = pygit2.Signature("t", "t@example.invalid")
        commit = repo.create_commit("refs/heads/master", sig, sig, "c", tree, [])

        files, complete = _collect_tree_files(repo, str(commit))

    assert complete, "the walk read everything it was asked for"
    assert dict(files)["payload.bin"].startswith(b"\x7fELF"), (
        "a blob over the read bound must be streamed, not skipped"
    )


def test_a_streamed_blob_read_does_not_deadlock():
    """`BlobIO.close()` waits for its writer thread, which the caller starves.

    pygit2 feeds `BlobIO` from a worker thread through a `Queue(maxsize=1)`,
    and `close()` joins that thread.  Reading only the head of a large blob
    leaves the writer parked on a full queue and `close()` never returns -
    so the fix for the skipped-blob gap first shipped as a hang that any
    committed 1 MiB file would trigger.
    """
    import threading
    import pygit2
    import tempfile
    from trustsight.analysis.pipeline import _collect_tree_files

    result = {}

    def walk():
        with tempfile.TemporaryDirectory() as tmp:
            repo = pygit2.init_repository(tmp, bare=True)
            blob = repo.create_blob(b"\x7fELF" + b"\x00" * (4 * 1024 * 1024))
            builder = repo.TreeBuilder()
            builder.insert("big.bin", blob, pygit2.GIT_FILEMODE_BLOB)
            sig = pygit2.Signature("t", "t@example.invalid")
            commit = repo.create_commit(
                "refs/heads/master", sig, sig, "c", builder.write(), [],
            )
            result["files"], result["complete"] = _collect_tree_files(
                repo, str(commit),
            )

    worker = threading.Thread(target=walk, daemon=True)
    worker.start()
    worker.join(timeout=60)
    assert not worker.is_alive(), "reading a large blob deadlocked"
    assert result["complete"]
    assert dict(result["files"])["big.bin"].startswith(b"\x7fELF")


def test_a_blob_past_the_stream_ceiling_is_reported_unread():
    """Draining costs time linear in the blob, so there is a ceiling on it.

    Past it the member is left unread - which is the old behaviour - but
    the walk says so instead of returning `complete`.
    """
    import pygit2
    import tempfile
    from trustsight.analysis.pipeline import _collect_tree_files

    with tempfile.TemporaryDirectory() as tmp:
        repo = pygit2.init_repository(tmp, bare=True)
        blob = repo.create_blob(b"\x7fELF" + b"\x00" * (1024 * 1024))
        builder = repo.TreeBuilder()
        builder.insert("huge.bin", blob, pygit2.GIT_FILEMODE_BLOB)
        sig = pygit2.Signature("t", "t@example.invalid")
        commit = repo.create_commit(
            "refs/heads/master", sig, sig, "c", builder.write(), [],
        )
        files, complete = _collect_tree_files(
            repo, str(commit), max_stream_bytes=1024,
        )

    assert not complete, "an unread member must not report as a complete walk"
    assert "huge.bin" not in dict(files)


def test_an_unread_tree_is_not_reported_as_analyzed():
    """`tree_analyzed` follows the walk, not merely 'some file was read'."""
    from trustsight.analysis import scan_diff
    from trustsight.coverage import TREE_NOT_ANALYZED

    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n+pkgrel=2\n"
    manifest = [("x.sh", b"echo hi")]
    complete = scan_diff(diff, package_name="p", tree_manifest=manifest)
    partial = scan_diff(
        diff, package_name="p", tree_manifest=manifest, tree_complete=False,
    )
    assert TREE_NOT_ANALYZED not in complete.coverage_gaps
    assert TREE_NOT_ANALYZED in partial.coverage_gaps


# ---------------------------------------------------------------------------
# Audit finding 2 - a bounded gap between pattern pieces is a padding bypass
#
# S001, S002/S003 and crossfire's `home-default` all required their pieces
# within {0,120}, {0,200} and {0,80} characters of each other.  The bound was
# there for backtracking safety, but it is also an instruction: type one more
# character than the bound and a CRITICAL rule goes quiet.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id,short,padded", [
    ("S001", ":(){ :|:& };:", ":(){ " + "true; " * 40 + ":|:& };:"),
    ("S002", "rm -rf --no-preserve-root /",
     "rm -rf " + "--verbose " * 30 + "--no-preserve-root /"),
])
def test_padding_does_not_escape_a_sabotage_rule(rule_id, short, padded):
    from trustsight.analysis import scan_diff

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,9 +1,14 @@\n"

    def fired(command):
        body = f" build() {{\n+  {command}\n }}\n"
        fact = scan_diff(header + body, package_name="p")
        return {e.rule_id for e in fact.score_breakdown}

    assert rule_id in fired(short)
    assert rule_id in fired(padded), f"{rule_id} evaded by padding"


def test_padding_does_not_escape_the_home_default_escape():
    from trustsight.analysis.crossfire import crossfire_techniques

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,9 +1,14 @@\n"
    padded = 'cp payload "${HOME:-' + "/aaaaaaaa" * 12 + '/home/alice}/x"'
    body = f" package() {{\n+  {padded}\n }}\n"
    assert "X005" in crossfire_techniques(header + body)


def test_the_unbounded_sabotage_spans_stay_linear():
    """Removing a bound must not buy back the backtracking it was for."""
    import time
    from trustsight.analysis.sabotage import _FORK_BOMB_DEF_RE

    def cost(n):
        text = ":(){ " + "a" * n
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            _FORK_BOMB_DEF_RE.search(text)
            best = min(best, time.perf_counter() - start)
        return best

    small, large = cost(2000), cost(8000)
    # Linear is 4x for 4x the input; allow generous headroom for a loaded
    # machine, but a quadratic pattern lands at 16x and fails.
    assert large < small * 9, f"growth {large / small:.1f}x over 4x input"


# ---------------------------------------------------------------------------
# Audit finding 3 - a named scope was the reviewed party's to choose
#
# `scope = ["pkgver"]` asks "does this run during pkgver?" but was answered
# with "is this lexically inside a function spelled pkgver?".  Moving the
# fetch into a helper called from pkgver() silenced R051 - a rename as an
# evasion, the same shape as the `package_x-bin` scope hole.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label,body", [
    ("direct", "+pkgver() {\n+  curl -s https://e.invalid/v\n+}\n"),
    ("helper", "+_v() {\n+  curl -s https://e.invalid/v\n+}\n"
               "+pkgver() {\n+  _v\n+}\n"),
    ("substitution", "+_v() {\n+  curl -s https://e.invalid/v\n+}\n"
                     "+pkgver() {\n+  echo \"$(_v)\"\n+}\n"),
    ("two hops", "+_a() {\n+  curl -s https://e.invalid/v\n+}\n"
                 "+_b() {\n+  _a\n+}\n+pkgver() {\n+  _b\n+}\n"),
])
def test_r051_follows_calls_out_of_pkgver(label, body):
    from trustsight.analysis import scan_diff

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,9 +1,20 @@\n"
    fact = scan_diff(header + body, package_name="p")
    assert "R051" in {e.rule_id for e in fact.score_breakdown}, label


def test_r051_does_not_follow_calls_from_an_unscoped_function():
    """The propagation must not turn every scoped rule into an unscoped one."""
    from trustsight.analysis import scan_diff

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,9 +1,20 @@\n"
    body = ("+_v() {\n+  curl -s https://e.invalid/v\n+}\n"
            "+build() {\n+  _v\n+}\n")
    fact = scan_diff(header + body, package_name="p")
    assert "R051" not in {e.rule_id for e in fact.score_breakdown}


# ---------------------------------------------------------------------------
# Audit finding 4 - a stage that failed reported the same thing as one that
# ran and found nothing
#
# Every swallowing handler in analysis/ returned a neutral value, which reads
# as "no finding here".  An unbalanced quote in a source= array, or a blob
# that would not stream, removed a whole check and the verdict still said
# UNFLAGGED - the condition B2 forbids.
# ---------------------------------------------------------------------------


def test_a_failed_stage_is_recorded_as_a_coverage_gap():
    from trustsight import coverage

    coverage.begin_stage_tracking()
    coverage.note_stage_failure("source-parse")
    assert coverage.stage_failures() == ["source-parse"]
    gaps = coverage.gaps_from(degraded_stages=coverage.stage_failures())
    assert coverage.STAGE_DEGRADED in gaps
    assert coverage.describe(gaps)
    assert "Inconclusive" in coverage.inconclusive_label(gaps)


def test_stage_notes_do_not_leak_between_analyses():
    """A note without a run, or from the previous run, must not be counted."""
    from trustsight import coverage
    from trustsight.analysis import scan_diff

    coverage.begin_stage_tracking()
    coverage.note_stage_failure("history-walk")
    fact = scan_diff(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n+pkgrel=2\n",
        package_name="p",
    )
    assert coverage.STAGE_DEGRADED not in fact.coverage_gaps


def test_an_unbalanced_quote_in_a_source_array_is_a_gap():
    from trustsight import coverage
    from trustsight.analysis import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,6 @@\n"
        "+source=(\n"
        "+  \"https://example.invalid/a.tar.gz\n"
        "+)\n"
    )
    fact = scan_diff(diff, package_name="p")
    assert coverage.STAGE_DEGRADED in fact.coverage_gaps


@pytest.mark.parametrize("array", [
    # A backslash continuation, the ordinary multi-line array shape.
    "+source=(https://example.invalid/a.tar.gz \\\n"
    "+        https://example.invalid/b.tar.gz)\n",
    # A whole-line comment with an apostrophe in it.
    "+source=(\n"
    "+  # makepkg doesn't understand SSH signatures\n"
    "+  \"https://example.invalid/a.tar.gz\"\n"
    "+)\n",
])
def test_an_ordinary_source_array_is_not_a_gap(array):
    """The gap must mean something: a routine array may not trip it."""
    from trustsight import coverage
    from trustsight.analysis import scan_diff

    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,8 @@\n" + array
    fact = scan_diff(diff, package_name="p")
    assert coverage.STAGE_DEGRADED not in fact.coverage_gaps
