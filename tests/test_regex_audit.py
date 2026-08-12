from scripts.regex_audit import audit_patterns


def test_shipped_regex_patterns_pass_the_adversarial_audit():
    audits = audit_patterns()
    assert audits
    failures = [audit for audit in audits if not audit.passed]
    assert failures == [], failures


def test_regex_audit_covers_configured_and_source_patterns():
    sources = {audit.source for audit in audit_patterns()}
    assert any(source.startswith("DEFAULT_RULES:") for source in sources)
    assert any(source.startswith("src/trustsight/") for source in sources)
