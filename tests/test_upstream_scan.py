"""The upstream-scan safety core: allowlist, parsing, pinning, checksums."""

from __future__ import annotations

import hashlib

import pytest

from trustsight.upstream_scan import (
    DEFAULT_ALLOWED_HOSTS,
    FetchMode,
    ForgeTarget,
    UpstreamScanError,
    checksum_bits,
    choose_fetch_mode,
    configured_hosts,
    is_routable_address,
    parse_forge_target,
    pin_target,
    verify_archive_checksum,
)

ALLOWED = frozenset(DEFAULT_ALLOWED_HOSTS)


def test_parse_accepts_an_allowlisted_https_repo():
    target = parse_forge_target("https://github.com/owner/repo", allowed_hosts=ALLOWED)
    assert target == ForgeTarget("github.com", "owner", "repo")
    assert target.slug == "github.com/owner/repo"


def test_parse_strips_git_suffix_and_extra_path():
    target = parse_forge_target(
        "https://gitlab.com/owner/repo.git/tree/main", allowed_hosts=ALLOWED)
    assert target.repo == "repo"


@pytest.mark.parametrize("url", [
    "http://github.com/owner/repo",
    "https://user:pass@github.com/owner/repo",
    "https://github.com:8443/owner/repo",
    "https://evil.example/owner/repo",
    "https://github.com/owner",
    "https://github.com/../repo",
    "https://203.0.113.7/owner/repo",
    "git+ssh://github.com/owner/repo",
])
def test_parse_refuses_unsafe_shapes(url):
    with pytest.raises(UpstreamScanError):
        parse_forge_target(url, allowed_hosts=ALLOWED)


def test_configured_hosts_merges_extras_and_ignores_malformed():
    config = {"upstream_scan": {
        "allowed_hosts": ["github.com"],
        "allowed_hosts_extra": ["forge.example.org", "bad/host", "a:b", "", 5],
    }}
    hosts = configured_hosts(config)
    assert "github.com" in hosts
    assert "forge.example.org" in hosts
    assert "bad/host" not in hosts
    assert "a:b" not in hosts


@pytest.mark.parametrize("address,expected", [
    ("93.184.216.34", True),
    ("8.8.8.8", True),
    ("2001:4860:4860::8888", True),
    ("127.0.0.1", False),
    ("10.0.0.1", False),
    ("169.254.169.254", False),
    ("::1", False),
    ("fe80::1", False),
    ("0.0.0.0", False),
    ("not-an-ip", False),
])
def test_routable_address_classification(address, expected):
    assert is_routable_address(address) is expected


def _resolver(*addresses):
    def resolve(host, port):
        return [(2, 1, 6, "", (address, port)) for address in addresses]
    return resolve


def test_pin_target_returns_routable_addresses():
    target = ForgeTarget("github.com", "owner", "repo")
    assert pin_target(target, _resolver("93.184.216.34")) == ("93.184.216.34",)


def test_pin_target_refuses_a_private_answer():
    target = ForgeTarget("github.com", "owner", "repo")
    with pytest.raises(UpstreamScanError):
        pin_target(target, _resolver("127.0.0.1"))


def test_pin_target_refuses_a_split_answer():
    target = ForgeTarget("github.com", "owner", "repo")
    with pytest.raises(UpstreamScanError):
        pin_target(target, _resolver("93.184.216.34", "10.0.0.1"))


def test_checksum_bits_reads_array_names():
    assert checksum_bits("sha256sums") == 256
    assert checksum_bits("sha512sums_x86_64") == 512
    assert checksum_bits("b2sums") == 256
    assert checksum_bits("nonsense") == 0


def test_verify_archive_checksum_accepts_the_matching_digest():
    data = b"archive bytes"
    digest = hashlib.sha256(data).hexdigest()
    assert verify_archive_checksum(data, digest, min_bits=256)


def test_verify_archive_checksum_refuses_mismatch_and_weak_values():
    data = b"archive bytes"
    assert not verify_archive_checksum(data, "00" * 32, min_bits=256)
    sha1_length = "ab" * 20  # 160 bits: below the 256-bit floor
    assert not verify_archive_checksum(data, sha1_length, algorithm="sha1", min_bits=256)
    assert not verify_archive_checksum(data, "not-hex", min_bits=256)


def test_choose_fetch_mode_prefers_clone_unless_archive_is_fully_gated():
    config = {"upstream_scan": {"archive_fetch": False, "min_checksum_bits": 256}}
    assert choose_fetch_mode(config, declared_checksum_bits=512,
                             archive_on_allowlisted_host=True) == FetchMode(
        "clone", "archive fetch is disabled")

    config = {"upstream_scan": {"archive_fetch": True, "min_checksum_bits": 256}}
    assert choose_fetch_mode(config, declared_checksum_bits=128,
                             archive_on_allowlisted_host=True).mode == "clone"
    assert choose_fetch_mode(config, declared_checksum_bits=256,
                             archive_on_allowlisted_host=False).mode == "clone"
    assert choose_fetch_mode(config, declared_checksum_bits=256,
                             archive_on_allowlisted_host=True).mode == "archive"


def test_check_archive_bounds_refuses_an_oversized_shape():
    from trustsight.upstream_scan import ArchiveBounds, check_archive_bounds

    bounds = ArchiveBounds(max_members=2, max_uncompressed_bytes=10)
    check_archive_bounds(2, 10, bounds)
    with pytest.raises(UpstreamScanError):
        check_archive_bounds(3, 10, bounds)
    with pytest.raises(UpstreamScanError):
        check_archive_bounds(2, 11, bounds)


def test_fetch_archive_returns_bytes_only_after_the_checksum_verifies():
    from trustsight.upstream_scan import fetch_archive

    data = b"the archive"
    digest = hashlib.sha256(data).hexdigest()
    seen = {}

    def transport(target, max_bytes, deadline):
        seen["target"] = target
        return data

    result = fetch_archive(
        "https://github.com/owner/repo/releases/download/v1/a.tar.gz",
        expected_hex=digest, algorithm="sha256", transport=transport,
        allowed_hosts=ALLOWED)
    assert result.data == data
    assert seen["target"].slug == "github.com/owner/repo"


def test_fetch_archive_refuses_a_mismatch_or_an_over_cap_body():
    from trustsight.upstream_scan import fetch_archive

    data = b"the archive"
    with pytest.raises(UpstreamScanError):
        fetch_archive(
            "https://github.com/owner/repo/releases/download/v1/a.tar.gz",
            expected_hex="00" * 32, algorithm="sha256",
            transport=lambda target, cap, deadline: data,
            allowed_hosts=ALLOWED)
    with pytest.raises(UpstreamScanError):
        fetch_archive(
            "https://github.com/owner/repo/releases/download/v1/a.tar.gz",
            expected_hex=hashlib.sha256(data).hexdigest(), algorithm="sha256",
            transport=lambda target, cap, deadline: b"x" * 20,
            max_bytes=10, allowed_hosts=ALLOWED)


def test_fetch_archive_refuses_an_off_allowlist_url_before_transport():
    from trustsight.upstream_scan import fetch_archive

    called = []
    with pytest.raises(UpstreamScanError):
        fetch_archive(
            "https://evil.example/owner/repo/a.tar.gz",
            expected_hex="00" * 32, algorithm="sha256",
            transport=lambda *a: called.append(a), allowed_hosts=ALLOWED)
    assert called == []
