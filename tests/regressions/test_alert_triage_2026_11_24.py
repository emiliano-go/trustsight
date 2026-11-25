"""Regressions from the 2026-11-24 triage.

Each assertion is the source host a package actually declares; the bucket
table called all of them unknown, which is what made routine vendor
downloads score as third-party artifacts.
"""

import pytest

from trustsight.buckets import classify_url


@pytest.fixture()
def domains():
    from calibration_gates import shipped_config
    from trustsight.config import load_domains

    with shipped_config():
        yield load_domains()


@pytest.mark.parametrize("url", [
    "https://git.mailliw.org/hummingbird/hummingbird",
    "https://git.sovereign-society.org/prism",
    "https://getharness.app/x.tar.gz",
    "https://swiftpointdrivers.blob.core.windows.net/x.msi",
    "https://cef-builds.spotifycdn.com/cef_binary_154.tar.bz2",
    "https://s3.g.s4.mega.io/jgemkib4a5fte35rktt5wxrwkw4ejk4ybemkf/nui-sftp-releases/x.svg",
])
def test_vendor_hosts_are_official(domains, url):
    assert classify_url(url, domains)[0] == "official"


def test_another_tenant_on_the_same_object_store_stays_unknown(domains):
    """MEGA's S3 endpoint is shared; only the maintainer's bucket is trusted."""
    assert classify_url(
        "https://s3.g.s4.mega.io/someone-else/thing.tar.gz", domains)[0] == "unknown"
