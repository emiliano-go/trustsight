import tomllib

from trustsight.config import DEFAULT_RULES
from trustsight.lint import SEVERITY_ERROR, SEVERITY_WARNING, lint_rules


def _rule(**overrides) -> dict:
    base = {
        "id": "R900",
        "name": "Test Rule",
        "pattern": r"\bnever-appears-anywhere\b",
        "severity": "HIGH",
        "category": "test",
        "match_target": "raw_line",
    }
    base.update(overrides)
    return base


def _checks(findings, check: str) -> list:
    return [f for f in findings if f.check == check]


def test_shipped_default_rules_are_clean():
    """The rules we ship must pass their own linter."""
    rules = tomllib.loads(DEFAULT_RULES)["rules"]
    findings = lint_rules(rules)
    errors = [f for f in findings if f.level == SEVERITY_ERROR]
    assert errors == [], f"shipped rules have lint errors: {errors}"


def test_empty_pattern_is_an_error():
    findings = lint_rules([_rule(pattern="", severity="FATAL")])
    empty = _checks(findings, "empty-pattern")
    assert len(empty) == 1
    assert empty[0].level == SEVERITY_ERROR
    assert "every score to 100" in empty[0].message


def test_pattern_matching_empty_string_is_an_error():
    findings = lint_rules([_rule(pattern=r"x*")])
    assert _checks(findings, "matches-everything")


def test_uncompilable_pattern_is_an_error():
    findings = lint_rules([_rule(pattern=r"([unclosed")])
    assert _checks(findings, "compile")[0].level == SEVERITY_ERROR


def test_duplicate_id_is_an_error():
    findings = lint_rules([_rule(id="R900"), _rule(id="R900", name="Other")])
    assert _checks(findings, "duplicate-id")[0].level == SEVERITY_ERROR


def test_programmatic_id_collision_is_an_error():
    findings = lint_rules([_rule(id="R004")])
    assert _checks(findings, "programmatic-id")[0].level == SEVERITY_ERROR


def test_unknown_severity_is_an_error():
    findings = lint_rules([_rule(severity="SEVERE")])
    assert _checks(findings, "severity")[0].level == SEVERITY_ERROR


def test_comment_only_rule_is_unreachable():
    """filter_raw_lines strips comments before matching, so a rule that
    only matches comment text can never fire."""
    findings = lint_rules([_rule(pattern=r"#.*https?://", severity="LOW")])
    shadowed = _checks(findings, "comment-shadowed")
    assert len(shadowed) == 1
    assert shadowed[0].level == SEVERITY_ERROR


def test_function_header_with_function_body_scope_is_contradictory():
    """A function's own header line is classified 'other', so a pattern
    matching the header cannot also require function_body scope."""
    findings = lint_rules([
        _rule(
            pattern=r"pkgver\(\)\s*\{.*\b(?:curl|wget)",
            scope=["function_body"],
        )
    ])
    assert _checks(findings, "scope-contradiction")[0].level == SEVERITY_ERROR


def test_high_severity_rule_firing_on_benign_packaging_warns():
    """chmod 644 on a config file is ordinary packaging, not a setuid bit."""
    findings = lint_rules([
        _rule(pattern=r"chmod\s+[0-7]*[46][0-7]{2}\s", severity="HIGH")
    ])
    hits = _checks(findings, "benign-hit")
    assert len(hits) == 1
    assert hits[0].level == SEVERITY_WARNING
    assert "chmod 644" in hits[0].message


def test_pkgdir_install_to_etc_warns():
    findings = lint_rules([
        _rule(pattern=r"\b(?:install|cp|mv|dd)\s+.*/(etc|boot)/", severity="MEDIUM")
    ])
    assert _checks(findings, "benign-hit")


def test_end_anchor_on_raw_line_warns():
    findings = lint_rules([
        _rule(pattern=r"\.(?:tk|ml|ga|xyz)$", severity="LOW")
    ])
    assert _checks(findings, "end-anchor")[0].level == SEVERITY_WARNING


def test_scope_on_resolved_target_warns():
    findings = lint_rules([
        _rule(match_target="resolved", scope=["function_body"])
    ])
    assert _checks(findings, "scope-ignored")


def test_unknown_scope_value_is_an_error():
    findings = lint_rules([_rule(scope=["build_section"])])
    assert _checks(findings, "scope")[0].level == SEVERITY_ERROR


def test_missing_required_field_is_an_error():
    rule = _rule()
    del rule["severity"]
    findings = lint_rules([rule])
    assert _checks(findings, "required-field")[0].level == SEVERITY_ERROR


def test_catastrophic_backtracking_is_flagged():
    """Measured, not guessed: a static nested-quantifier heuristic
    false-positives on safe patterns like (?:-\\S+\\s+)* where the inner
    and outer character classes are disjoint."""
    findings = lint_rules([_rule(pattern=r"(a+)+$")])
    assert _checks(findings, "backtracking")[0].level == SEVERITY_ERROR


def test_disjoint_nested_quantifier_is_not_flagged():
    findings = lint_rules([
        _rule(pattern=r"\bchmod\s+(?:-\S+\s+)*[2467][0-7]{3}\b")
    ])
    assert not _checks(findings, "backtracking")


def test_function_name_scope_is_valid():
    findings = lint_rules([_rule(scope=["pkgver"])])
    assert not _checks(findings, "scope")


def test_split_package_function_scope_is_valid():
    findings = lint_rules([_rule(scope=["package_foo-docs"])])
    assert not _checks(findings, "scope")


def test_well_formed_rule_produces_no_findings():
    findings = lint_rules([
        _rule(pattern=r"\bsudo\b", severity="CRITICAL", scope=["function_body"])
    ])
    assert findings == []
