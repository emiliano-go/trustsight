"""The false-positive issue body matches the GitHub issue form."""

from urllib.parse import unquote_plus

from trustsight.fp_issue import issue_body, issue_url


REPORT = {
    "package": "demo",
    "config_fingerprint": "a" * 64,
    "findings": [
        {"rule_id": "R007", "severity": "MEDIUM", "description": "Install File"},
        {"rule_id": "H015", "severity": "HIGH", "description": "Build Function"},
        {"rule_id": "R007", "severity": "MEDIUM", "description": "Install File"},
    ],
}


def test_issue_body_uses_the_form_headings():
    body = issue_body(
        package="demo",
        report=REPORT,
        version="0.22.0",
        alert_url="https://watcher.trustsight.org/2026-10-23/120000/",
    )

    for heading in (
        "What kind of report is this?",
        "TrustSight version",
        "AUR package",
        "Feed alert URL",
        "Rule id",
        "What TrustSight reported",
        "Why this is a bad rule trigger",
        "PKGBUILD or diff",
        "Command or mode",
        "Config fingerprint",
    ):
        assert f"### {heading}" in body
    assert "trustsight 0.22.0" in body
    assert "R007, H015" in body
    assert '"config_fingerprint": "' + ("a" * 64) + '"' in body


def test_issue_body_defaults_to_the_malicious_false_positive_kind():
    body = issue_body(package="demo", report=REPORT, version="0.22.0")

    assert "Bad rule trigger (malicious false positive)" in body


def test_issue_url_prefills_the_package_and_rules():
    url = issue_url("demo", ["R007", "H015"])

    assert url.startswith(
        "https://github.com/emiliano-go/trustsight/issues/new"
        "?template=false_positive.yml")
    title = unquote_plus(url.split("title=", 1)[1])
    assert title.startswith("[False positive]: demo")
    assert "R007" in title and "H015" in title
