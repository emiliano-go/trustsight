from trustsight.buckets import (
    classify_pinning_level,
    classify_url,
    classify_urls,
    has_homograph,
    host_is_non_routable,
    url_host_is_non_routable,
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


def test_trusted_forge_copr_download_host():
    """skwd-paper-plasma: a build pulled from Fedora's Copr is a forge
    artifact like a GitHub release, not an unknown-bucket binary."""
    config = {
        "trusted_forges": {"domains": ["github.com", "copr.fedorainfracloud.org"]},
        "official_projects": {"domains": []},
        "raw_hosting": {"domains": []},
    }
    bucket, _ = classify_url(
        "https://download.copr.fedorainfracloud.org/results/p/x/srpm-builds/1/p.src.rpm",
        config)
    assert bucket == "trusted_forge"


def test_trusted_forge_sourceforge_and_freedesktop():
    config = {
        "trusted_forges": {"domains": ["github.com", "sourceforge.net", "freedesktop.org"]},
        "official_projects": {"domains": []},
        "raw_hosting": {"domains": []},
    }
    sf, _ = classify_url(
        "https://downloads.sourceforge.net/project/x/x.tar.gz", config
    )
    fd, _ = classify_url(
        "https://gitlab.freedesktop.org/x/y/-/archive/v1/y-v1.tar.gz", config
    )
    assert sf == "trusted_forge"
    assert fd == "trusted_forge"


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


def test_unparseable_url_is_unknown():
    # urlparse raises ValueError("Invalid IPv6 URL") on unbalanced brackets;
    # the extractor's URL token regex yields such URLs from a source= line.
    bucket, matched = classify_url("https://[::1/evil.tar.gz", DOMAIN_CONFIG)
    assert bucket == "unknown"
    assert matched == ""


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


def test_pinning_commit_fragment_is_its_own_level():
    """A `#commit=` ref is a commit pin, not a checksummed tarball."""
    assert classify_pinning_level(
        "git+https://github.com/user/proj.git#commit=" + "a" * 40
    ) == "commit_pinned"
    # A variable that feeds the commit fragment is still a commit pin.
    assert classify_pinning_level(
        "git+https://github.com/user/proj.git#commit=$_commit"
    ) == "commit_pinned"
    # A checksum does not turn a commit pin into a checksum pin.
    assert classify_pinning_level(
        "git+https://github.com/user/proj.git#commit=" + "a" * 40,
        checksum_present=True,
    ) == "commit_pinned"


def test_pinning_tag_archive():
    assert classify_pinning_level("https://github.com/user/proj/archive/v1.0.0.tar.gz") == "tag_pinned"


def test_pinning_tag_releases():
    assert classify_pinning_level("https://github.com/user/proj/releases/download/v1.0/pkg.tar.gz") == "tag_pinned"


def test_pinning_branch():
    assert classify_pinning_level("https://github.com/user/proj/archive/master.tar.gz") == "branch_pinned"


def test_pinning_branch_path():
    assert classify_pinning_level("https://github.com/user/proj/archive/refs/heads/main.tar.gz") == "branch_pinned"


def test_pinning_tag_fragment():
    """A ``#tag=`` git ref is a tag pin, literal or variable."""
    assert classify_pinning_level(
        "git+https://github.com/user/proj.git#tag=v1.2.3"
    ) == "tag_pinned"
    assert classify_pinning_level(
        "git+https://github.com/user/proj.git#tag=$_tag"
    ) == "tag_pinned"


def test_pinning_branch_fragment():
    """A ``#branch=`` git ref is a branch pin, not unpinned."""
    assert classify_pinning_level(
        "git+https://github.com/user/proj.git#branch=main"
    ) == "branch_pinned"


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


def test_non_ascii_latin_is_not_homograph():
    """Single-script labels (e.g. ``münchen.de``, ``café.fr``) are
    legitimate IDNs, not homograph attacks."""
    assert has_homograph(f"githu{LATIN_B_DOT}.com") is False
    assert has_homograph("münchen.de") is False
    assert has_homograph("café.fr") is False


def test_punycode_encoded_confusable_is_homograph():
    """An attacker can write the punycode form directly into source=()."""
    encoded = f"github.c{CYRILLIC_O}m".encode("idna").decode()
    assert encoded.startswith("github.xn--")
    assert has_homograph(encoded) is True


def test_mixed_script_that_reads_as_no_target_is_not_homograph():
    """R013b requires confusability with a configured target domain: a
    mixed-script label that decodes to something outside the allowlist
    (even one carrying a confusable codepoint) must not fire."""
    assert has_homograph("банk.com") is False
    assert has_homograph(f"githu{CYRILLIC_O}b.com") is False


def test_mixed_script_that_reads_as_configured_target_is_homograph():
    """Cyrillic 'а' decodes to 'a', so pаypal reads as paypal.com (a
    configured target) and must fire; попay (single-script Cyrillic,
    no confusable against any target) stays quiet."""
    assert has_homograph(f"google.c{CYRILLIC_O}m") is True
    assert has_homograph("pаypal.com") is True


def test_confusable_targets_are_taken_from_config():
    """confusable_domains=() turns off the whole bucket; adding a new
    target makes its lookalikes fire."""
    assert has_homograph(f"github.c{CYRILLIC_O}m", confusable_domains=()) is False
    assert has_homograph(
        "cоdeberg.com", confusable_domains={"codeberg.org"}
    ) is False
    assert has_homograph(
        f"githu{CYRILLIC_O}b.com", confusable_domains={"githuob.com"}
    ) is True


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


# --- punycode confusables ---

def test_punycode_combining_mark_is_not_a_homograph():
    """A punycode-encoded combining mark on a Latin letter is still a
    single-script label (Latin + combining mark), not a homograph."""
    from trustsight.buckets import has_homograph
    assert has_homograph("xn--githb-6rd.com") is False
    assert has_homograph("githuḅ.com") is False
    assert has_homograph("caf\u0301.fr") is False


def test_scripts_that_legitimately_use_combining_marks_are_not_flagged():
    """Devanagari, Arabic and Thai need marks; they are not confusables."""
    from trustsight.buckets import has_homograph
    for domain in (
        "उदाहरण.भारत",
        "xn--p1b6ci4b4b3a.xn--h2brj9c",
        "قطر.qa",
        "ไทย.th",
        "日本.jp",
    ):
        assert has_homograph(domain) is False, domain


def test_plain_ascii_domains_are_never_flagged():
    from trustsight.buckets import has_homograph
    for domain in ("github.com", "cdn-1.example.co.uk", "sourceforge.net"):
        assert has_homograph(domain) is False, domain


# --- Non-routable hosts (loopback/private) ---

def test_non_routable_hosts_are_recognised():
    for host in ("127.0.0.1", "127.0.0.1:8787", "10.0.0.1", "192.168.1.1",
                 "172.16.0.1", "172.31.255.255", "169.254.1.1", "0.0.0.0",
                 "localhost", "localhost:8787", "[::1]", "[::1]:8787"):
        assert host_is_non_routable(host) is True, host


def test_routable_hosts_are_not_excluded():
    # 172.15/172.32 sit just outside the RFC1918 172.16/12 block.
    for host in ("8.8.8.8", "1.1.1.1:443", "172.15.0.1", "172.32.0.1",
                 "example.org", "cdn.example.com", "github.com:8443"):
        assert host_is_non_routable(host) is False, host


def test_url_host_non_routable_reads_the_host_only():
    assert url_host_is_non_routable("http://127.0.0.1:8787/admin") is True
    assert url_host_is_non_routable("https://192.168.0.1/x") is True
    assert url_host_is_non_routable("http://8.8.8.8:8787/x") is False
    assert url_host_is_non_routable("not-a-url") is False


# --- Inert URL contexts (printed, not fetched/declared) ---

def test_an_echoed_url_is_inert():
    from trustsight.buckets import url_line_is_inert

    assert url_line_is_inert('echo "see http://8.8.8.8:8787/status"') is True
    assert url_line_is_inert('  printf "see http://8.8.8.8/x\\n"') is True
    assert url_line_is_inert('+  cat "http://8.8.8.8/x"') is True


def test_localhost_does_not_read_as_the_host_dns_client():
    """The `host` arm of the fetch-client vocabulary must not match the
    `host` inside `localhost`, or an echoed localhost URL reads as a fetch
    and the inert-printer stand-down never applies (R047 fired on a printed
    `http://localhost:20128/` dashboard URL)."""
    from trustsight.buckets import url_line_is_inert

    assert url_line_is_inert('echo "dashboard: http://localhost:20128/"') is True
    assert url_line_is_inert("echo see http://127.0.0.1:9090/ui/") is True
    # A real `host` DNS lookup at a command position is still a fetch.
    assert url_line_is_inert("host example.com") is False
    # getent is a resolver, not a fetch client or a printer.
    assert url_line_is_inert("getent hosts example.com") is False


def test_a_declared_or_fetched_url_is_not_inert():
    from trustsight.buckets import url_line_is_inert

    assert url_line_is_inert("source=('http://8.8.8.8/x')") is False
    assert url_line_is_inert("url=http://8.8.8.8/x") is False
    assert url_line_is_inert("curl -O http://8.8.8.8/x") is False
    assert url_line_is_inert('echo ok && curl http://8.8.8.8/x') is False
    # A word that merely contains `echo` is not a printer.
    assert url_line_is_inert("mydata-echo http://8.8.8.8/x") is False


def test_project_owned_and_vendor_cdn_hosts_are_official():
    """The batch-01 MFP hosts: a vendor CDN, PyPI's file host, and two
    project-owned release hosts are not unknown-bucket downloads."""
    from trustsight.buckets import classify_url

    for url in (
        "https://files.pythonhosted.org/packages/source/g/graphifyy/x.tar.gz",
        "https://vscode.download.prss.microsoft.com/dbazure/download/stable/x",
        "https://overte-public.fra1.digitaloceanspaces.com/x",
        "https://git.bnema.dev/x",
    ):
        bucket, _matched = classify_url(url)
        assert bucket in ("official", "trusted_forge"), url
