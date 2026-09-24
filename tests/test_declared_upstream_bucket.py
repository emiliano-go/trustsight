"""An unknown source on the package's own declared ``url=`` domain."""

from trustsight.analysis.structural import unchanged_upstream_host
from trustsight.buckets import classify_urls

SOURCE = "https://downloads.example.org/tool-1.0.tar.gz"


def test_source_on_the_declared_domain_is_declared_upstream():
    buckets = classify_urls([SOURCE], upstream_host="tool.example.org")
    assert buckets[SOURCE] == "declared_upstream"


def test_source_on_another_domain_stays_unknown():
    buckets = classify_urls([SOURCE], upstream_host="tool.example.net")
    assert buckets[SOURCE] == "unknown"


def test_without_upstream_nothing_changes():
    assert classify_urls([SOURCE])[SOURCE] == "unknown"


def test_trusted_forge_is_not_downgraded():
    url = "https://github.com/example/tool/archive/v1.tar.gz"
    assert classify_urls([url], upstream_host="github.com")[url] == "trusted_forge"


def test_url_changed_in_the_same_diff_is_ignored():
    head = "pkgname=tool\nurl='https://tool.example.org'\n"
    diff = "-url='https://tool.example.net'\n+url='https://tool.example.org'\n"
    assert unchanged_upstream_host(diff, head) == ""


def test_unchanged_url_is_used():
    head = "pkgname=tool\nurl='https://tool.example.org'\n"
    diff = "-pkgver=1.0\n+pkgver=1.1\n"
    assert unchanged_upstream_host(diff, head) == "tool.example.org"


def test_scan_diff_uses_the_head_url():
    from trustsight.analysis.pipeline import scan_diff

    head = f"pkgname=tool\nurl='https://tool.example.org'\nsource=('{SOURCE}')\n"
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -3 +3 @@\n"
        "-source=('https://downloads.example.org/tool-0.9.tar.gz')\n"
        f"+source=('{SOURCE}')\n"
    )
    fact = scan_diff(diff, package_name="tool", current_text=head)
    assert fact.source_buckets[SOURCE] == "declared_upstream"
