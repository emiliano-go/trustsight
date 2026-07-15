from trustsight.buckets import classify_url, classify_urls

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
