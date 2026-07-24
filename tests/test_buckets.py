from trustsight.buckets import (
    classify_pinning_level,
    classify_url,
    classify_urls,
    has_homograph,
)

DOMAIN_CONFIG = {
    "trusted_forges": {"domains": ["github.com", "gitlab.com", "codeberg.org", "bitbucket.org"]},
    "official_projects": {"domains": ["python.org", "kernel.org", "nginx.org", "dl.google.com"]},
    "raw_hosting": {"domains": ["raw.githubusercontent.com", "pastebin.com", "gist.github.com"]},
}


def test_trusted_forge_github():
    bucket, matched = classify_url("https://github.com/user/repo.tar.gz", DOMAIN_CONFIG)
    assert bucket == "trusted_forge"


def test_trusted_forge_gitlab():
    bucket, matched = classify_url("https://gitlab.com/project/release.tar.xz", DOMAIN_CONFIG)
    assert bucket == "trusted_forge"


def test_trusted_forge_codeberg():
    bucket, matched = classify_url("https://codeberg.org/user/tool.tar.bz2", DOMAIN_CONFIG)
    assert bucket == "trusted_forge"


def test_trusted_forge_bitbucket():
    bucket, matched = classify_url("https://bitbucket.org/user/repo.zip", DOMAIN_CONFIG)
    assert bucket == "trusted_forge"


def test_trusted_forge_subdomain():
    bucket, matched = classify_url("https://raw.githubusercontent.com/user/script.sh", DOMAIN_CONFIG)
    assert bucket == "raw_hosting"  # raw.githubusercontent.com is raw_hosting, overrides forge


def test_official_python():
    bucket, matched = classify_url("https://www.python.org/ftp/python/3.12.tar.gz", DOMAIN_CONFIG)
    assert bucket == "official"


def test_official_kernel():
    bucket, matched = classify_url("https://kernel.org/pub/linux/kernel/v6.x/linux-6.1.tar.xz", DOMAIN_CONFIG)
    assert bucket == "official"


def test_official_nginx():
    bucket, matched = classify_url("https://nginx.org/download/nginx-1.24.tar.gz", DOMAIN_CONFIG)
    assert bucket == "official"


def test_official_subdomain():
    bucket, matched = classify_url("https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_116.0.5845.110-1_amd64.deb", DOMAIN_CONFIG)
    assert bucket == "official"


def test_raw_hosting_pastebin():
    bucket, matched = classify_url("https://pastebin.com/raw/abc123", DOMAIN_CONFIG)
    assert bucket == "raw_hosting"


def test_raw_hosting_gist():
    bucket, matched = classify_url("https://gist.github.com/user/script.sh", DOMAIN_CONFIG)
    assert bucket == "raw_hosting"


def test_unknown_random():
    bucket, matched = classify_url("https://cdn.evil-site.xyz/payload.tar.gz", DOMAIN_CONFIG)
    assert bucket == "unknown"


def test_unknown_ip():
    bucket, matched = classify_url("http://192.168.1.1/script.sh", DOMAIN_CONFIG)
    assert bucket == "unknown"


def test_unknown_typo_squatted():
    bucket, matched = classify_url("https://githab.com/user/repo.tar.gz", DOMAIN_CONFIG)
    assert bucket == "unknown"


def test_unknown_typo_squatted_gnu():
    bucket, matched = classify_url("https://gnu.organization.org/malicious.tar.gz", DOMAIN_CONFIG)
    assert bucket == "unknown"


def test_unknown_unusual_tld():
    bucket, matched = classify_url("https://downloads.python.xyz/pkg.tar.gz", DOMAIN_CONFIG)
    assert bucket == "unknown"


def test_raw_hosting_priority_over_forge():
    bucket, matched = classify_url("https://raw.githubusercontent.com/org/repo/script.sh", DOMAIN_CONFIG)
    assert bucket == "raw_hosting"


def test_classify_multiple_urls():
    urls = [
        "https://github.com/user/repo.tar.gz",
        "https://evil.com/payload.tar.gz",
        "https://kernel.org/pub/linux.tar.xz",
    ]
    results = classify_urls(urls, DOMAIN_CONFIG)
    assert results["https://github.com/user/repo.tar.gz"] == "trusted_forge"
    assert results["https://evil.com/payload.tar.gz"] == "unknown"
    assert results["https://kernel.org/pub/linux.tar.xz"] == "official"


def test_unknown_fileio():
    bucket, matched = classify_url("https://file.io/abc123", DOMAIN_CONFIG)
    assert bucket == "unknown"


def test_official_via_subdomain():
    bucket, matched = classify_url("https://download.python.org/packages/3.12/pip-23.0.tar.gz", DOMAIN_CONFIG)
    assert bucket == "official"


# --- Pinning level ---

def test_pinning_checksum():
    assert classify_pinning_level("https://example.com/pkg.tar.gz", checksum_present=True) == "checksum_pinned"


def test_pinning_tag_archive():
    assert classify_pinning_level("https://github.com/user/proj/archive/v1.0.0.tar.gz") == "tag_pinned"


def test_pinning_tag_releases():
    assert classify_pinning_level("https://github.com/user/proj/releases/download/v1.0/pkg.tar.gz") == "tag_pinned"


def test_pinning_branch():
    assert classify_pinning_level("https://github.com/user/proj/archive/master.tar.gz") == "branch_pinned"


def test_pinning_branch_path():
    assert classify_pinning_level("https://github.com/user/proj/archive/refs/heads/main.tar.gz") == "branch_pinned"


def test_pinning_unpinned():
    assert classify_pinning_level("https://mirror.example.com/somefile.tar.gz") == "unpinned"


# --- Homograph / confusable domain detection ---

CYRILLIC_O = "о"   # CYRILLIC SMALL LETTER O, confusable with ASCII 'o'
LATIN_B_DOT = "ḅ"  # LATIN SMALL LETTER B WITH DOT BELOW


def test_ascii_domain_is_not_homograph():
    assert has_homograph("github.com") is False


def test_mixed_latin_cyrillic_is_homograph():
    """The confusable that motivated CONFUSABLES: Cyrillic 'o' in a
    Latin label reads as github.com but is a different domain."""
    assert has_homograph(f"github.c{CYRILLIC_O}m") is True


def test_non_ascii_latin_is_homograph():
    """Stays within the Latin script, so mixed-script detection alone
    would miss it."""
    assert has_homograph(f"githu{LATIN_B_DOT}.com") is True


def test_punycode_encoded_confusable_is_homograph():
    """An attacker can write the punycode form directly into source=()."""
    encoded = f"github.c{CYRILLIC_O}m".encode("idna").decode()
    assert encoded.startswith("github.xn--")
    assert has_homograph(encoded) is True


def test_legitimate_cyrillic_idn_is_not_homograph():
    """A domain written wholly in one non-Latin script is a real IDN."""
    assert has_homograph("xn--e1afmkfd.xn--p1ai") is False


def test_legitimate_japanese_idn_is_not_homograph():
    """Japanese legitimately mixes Han with kana."""
    assert has_homograph("例え.jp") is False


def test_legitimate_korean_idn_is_not_homograph():
    assert has_homograph("한국.kr") is False


def test_digits_and_hyphens_are_script_neutral():
    assert has_homograph("sub-1.github.io") is False


def test_domain_with_port_is_not_homograph():
    assert has_homograph("github.com:8080") is False


def test_confusable_domain_classifies_as_homograph_attack():
    bucket, _ = classify_url(
        f"https://github.c{CYRILLIC_O}m/user/repo.tar.gz", DOMAIN_CONFIG
    )
    assert bucket == "homograph_attack"


def test_confusable_domain_does_not_reach_trusted_forge():
    """Regression: a Cyrillic lookalike must never earn the -10 trusted
    forge credit."""
    bucket, _ = classify_url(
        f"https://github.c{CYRILLIC_O}m/user/repo.tar.gz", DOMAIN_CONFIG
    )
    assert bucket != "trusted_forge"
