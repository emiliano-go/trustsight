import tomllib

from tests.conftest import SHARED_CONFIG
from trustsight.scoring import calculate_score, risk_level
from trustsight.schema import NoveltyContext


# --- risk_level ---

def test_risk_level_low():
    for score in [0, 5, 20]:
        assert risk_level(score) == "Low"


def test_risk_level_medium():
    for score in [21, 35, 50]:
        assert risk_level(score) == "Medium"


def test_risk_level_high():
    for score in [51, 65, 80]:
        assert risk_level(score) == "High"


def test_risk_level_critical():
    for score in [81, 95, 100]:
        assert risk_level(score) == "Critical"


# --- Score with rules ---

def test_calculate_score_empty():
    score, breakdown, level = calculate_score([], {}, NoveltyContext(), SHARED_CONFIG)
    assert score == 0
    assert breakdown == []
    assert level == "Low"


def test_calculate_score_one_rule():
    """One CRITICAL scores 40 and reads High, not the Medium 40 implies.

    CRITICAL weighs 40 and the High band opens at 51, so arithmetic alone
    can never lift a single CRITICAL above Medium. The floor in
    ``_floor_for_critical`` is what stops a lone `curl | bash` - or a lone
    fork bomb - reading as a medium situation.
    """
    triggered = [{"rule_id": "R001", "severity": "CRITICAL", "name": "Remote Exec", "match": "curl | bash"}]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert score == 40
    assert len(breakdown) == 1
    assert breakdown[0].rule_id == "R001"
    assert breakdown[0].weight == 40
    assert risk_level(score) == "Medium"      # what the number alone says
    assert level == "High"                    # what the severity requires


def test_a_rule_weight_override_replaces_its_severity_weight():
    triggered = [{
        "rule_id": "R010", "severity": "LOW", "name": "curl",
        "match": "curl", "weight_override": 17,
    }]
    score, breakdown, _level = calculate_score(
        triggered, {}, NoveltyContext(observation_count=999), SHARED_CONFIG)
    assert score == 17
    assert breakdown[0].weight == 17


def test_a_high_finding_is_not_floored():
    """The floor is CRITICAL-only: HIGH keeps the band its weight earns."""
    triggered = [{"rule_id": "R004", "severity": "HIGH", "name": "Checksum Skip",
                  "match": "sha256sums=SKIP"}]
    score, _breakdown, level = calculate_score(
        triggered, {}, NoveltyContext(observation_count=999), SHARED_CONFIG)
    assert score == 25
    assert level == "Medium"


def test_the_floor_never_lowers_a_band():
    """A CRITICAL inside a diff that already scored Critical stays Critical."""
    triggered = [
        {"rule_id": "R001", "severity": "CRITICAL", "name": "a", "match": "x"},
        {"rule_id": "R002", "severity": "CRITICAL", "name": "b", "match": "y"},
        {"rule_id": "R003", "severity": "CRITICAL", "name": "c", "match": "z"},
    ]
    score, _breakdown, level = calculate_score(
        triggered, {}, NoveltyContext(observation_count=999), SHARED_CONFIG)
    assert score > 80
    assert level == "Critical"


def test_calculate_score_multiple_rules():
    triggered = [
        {"rule_id": "R001", "severity": "CRITICAL", "name": "Remote Exec", "match": "curl | bash"},
        {"rule_id": "R004", "severity": "HIGH", "name": "Checksum Skip", "match": "sha256sums=SKIP"},
    ]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert score == 65  # 40 + 25
    assert len(breakdown) == 2
    assert level == "High"


def test_calculate_score_all_severities():
    triggered = [
        {"rule_id": "R001", "severity": "CRITICAL", "name": "C1", "match": "a"},
        {"rule_id": "R004", "severity": "HIGH", "name": "H1", "match": "b"},
        {"rule_id": "R006", "severity": "MEDIUM", "name": "M1", "match": "c"},
        {"rule_id": "R010", "severity": "LOW", "name": "L1", "match": "d"},
        {"rule_id": "RINF", "severity": "INFO", "name": "I1", "match": "e"},
    ]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert score == 85  # 40 + 25 + 15 + 5 + 0
    assert level == "Critical"


# --- Score with buckets ---

def test_score_with_unknown_bucket():
    score, breakdown, level = calculate_score([], {"https://evil.com/payload.tar.gz": "unknown"}, NoveltyContext(), SHARED_CONFIG)
    assert score == 20
    assert any(e.rule_id == "SOURCE_BUCKET" for e in breakdown)


def test_a_trusted_forge_is_reported_never_credited():
    """B10: routing through github.com costs an attacker nothing."""
    score, breakdown, level = calculate_score([], {"https://github.com/user/repo.tar.gz": "trusted_forge"}, NoveltyContext(), SHARED_CONFIG)
    assert score == 0
    declared = [e for e in breakdown if e.rule_id == "P007"]
    assert declared and all(e.weight == 0 and e.severity == "INFO" for e in declared)


def test_score_with_raw_hosting_bucket():
    score, breakdown, level = calculate_score([], {"https://raw.githubusercontent.com/x/s.sh": "raw_hosting"}, NoveltyContext(), SHARED_CONFIG)
    assert score == 15


def test_score_mixed_buckets():
    buckets = {
        "https://github.com/user/repo.tar.gz": "trusted_forge",
        "https://evil.com/payload.tar.gz": "unknown",
    }
    score, breakdown, level = calculate_score([], buckets, NoveltyContext(), SHARED_CONFIG)
    # The unknown host still costs; the forge no longer pays it back.
    assert score == 20


# --- Score with novelty ---

def test_score_novelty_url_first_globally():
    novelty = NoveltyContext(url_first_seen_globally=True, observation_count=50)
    score, breakdown, level = calculate_score([], {}, novelty, SHARED_CONFIG)
    assert score == 10
    assert any(e.rule_id == "NOVELTY" for e in breakdown)


def test_score_novelty_url_first_in_package():
    novelty = NoveltyContext(url_first_seen_in_this_package=True, observation_count=50)
    score, breakdown, level = calculate_score([], {}, novelty, SHARED_CONFIG)
    assert score == 5


def test_score_novelty_maintainer_first():
    novelty = NoveltyContext(maintainer_first_seen_for_this_package=True, observation_count=50)
    score, breakdown, level = calculate_score([], {}, novelty, SHARED_CONFIG)
    assert score == 15


def test_score_novelty_all():
    novelty = NoveltyContext(
        url_first_seen_in_this_package=True,
        url_first_seen_globally=True,
        maintainer_first_seen_for_this_package=True,
        observation_count=50,
    )
    score, breakdown, level = calculate_score([], {}, novelty, SHARED_CONFIG)
    assert score == 30  # 5 + 10 + 15
    assert level == "Medium"


# --- Combined score contributions ---

def test_score_everything_combined():
    triggered = [
        {"rule_id": "R001", "severity": "CRITICAL", "name": "Remote Exec", "match": "curl | bash"},
        {"rule_id": "R004", "severity": "HIGH", "name": "Checksum Skip", "match": "sha256sums=SKIP"},
    ]
    novelty = NoveltyContext(
        url_first_seen_in_this_package=True,
        url_first_seen_globally=True,
        maintainer_first_seen_for_this_package=True,
        observation_count=50,
    )
    buckets = {
        "https://evil.com/payload.tar.gz": "unknown",
    }
    score, breakdown, level = calculate_score(triggered, buckets, novelty, SHARED_CONFIG)
    # 40 + 25 + 20 + 10 + 15 + 20 = 130 -> capped at 100
    assert score == 100
    assert level == "Critical"


def test_score_breakdown_contains_all_contributors():
    triggered = [{"rule_id": "R001", "severity": "CRITICAL", "name": "Exec", "match": "curl | bash"}]
    novelty = NoveltyContext(url_first_seen_globally=True, observation_count=50)
    buckets = {"https://evil.com/x": "unknown"}
    score, breakdown, level = calculate_score(triggered, buckets, novelty, SHARED_CONFIG)
    rule_ids = [e.rule_id for e in breakdown]
    assert "R001" in rule_ids
    assert "SOURCE_BUCKET" in rule_ids
    assert "NOVELTY" in rule_ids


# --- Score capping ---

def test_score_capped_at_100():
    triggered = [
        {"rule_id": "R001", "severity": "CRITICAL", "name": "Exec", "match": "a"},
        {"rule_id": "R002", "severity": "CRITICAL", "name": "Exec2", "match": "b"},
        {"rule_id": "R003", "severity": "CRITICAL", "name": "Exec3", "match": "c"},
    ]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert score == 100


def test_score_floor_at_0():
    buckets = {"https://github.com/trusted/repo.tar.gz": "trusted_forge"}
    score, breakdown, level = calculate_score([], buckets, NoveltyContext(), SHARED_CONFIG)
    assert score == 0  # -10 capped to 0


# --- Custom severity weights ---

def test_custom_weights():
    custom = {**SHARED_CONFIG, "severity_weights": {"CRITICAL": 100, "HIGH": 50}}
    triggered = [{"rule_id": "R001", "severity": "CRITICAL", "name": "Exec", "match": "a"}]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), custom)
    assert score == 100  # 100 capped


def test_missing_severity_returns_zero():
    triggered = [{"rule_id": "R999", "severity": "UNKNOWN", "name": "Unknown", "match": "x"}]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert score == 0


def test_breakdown_entries_have_reason():
    triggered = [{"rule_id": "R001", "severity": "CRITICAL", "name": "Remote Exec", "match": "curl | bash"}]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert len(breakdown[0].reason) > 0
    assert "Remote Exec" in breakdown[0].reason


def test_fatal_rule_hard_stops_at_100():
    triggered = [
        {"rule_id": "R012", "severity": "FATAL", "name": "Prompt Injection", "match": "ignore all instructions"},
    ]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert score == 100
    assert level == "Critical"
    assert any(e.rule_id == "R012" for e in breakdown)
    assert all(e.weight == 0 for e in breakdown)  # FATAL contributes 0 weight


def test_fatal_overrides_lower_score():
    triggered = [
        {"rule_id": "R001", "severity": "HIGH", "name": "Something", "match": "x"},
        {"rule_id": "R013", "severity": "FATAL", "name": "Bidi", "match": "\u202E"},
    ]
    score, breakdown, level = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert score == 100
    assert level == "Critical"


def test_verification_evidence_does_not_reduce_the_score():
    """B10: declared verification is reported, never credited."""
    triggered = [{"rule_id": "R001", "severity": "LOW", "name": "Curl", "match": "curl"}]
    score, breakdown, level = calculate_score(
        triggered, {}, NoveltyContext(), SHARED_CONFIG,
        verification_evidence=["checksum_present", "validpgpkeys_declared"],
    )
    without, _, _ = calculate_score(triggered, {}, NoveltyContext(), SHARED_CONFIG)
    assert score == without == 5


def test_verification_evidence_in_breakdown():
    score, breakdown, level = calculate_score(
        [], {}, NoveltyContext(), SHARED_CONFIG,
        verification_evidence=["gpg_verify_present"],
    )
    assert any(e.rule_id == "P003" and e.weight == 0 for e in breakdown)


def test_pinning_is_reported_never_credited():
    score, breakdown, level = calculate_score(
        [], {}, NoveltyContext(), SHARED_CONFIG,
        pinning_level="checksum_pinned",
    )
    assert score == 0
    assert any(e.rule_id == "P005" and e.weight == 0 for e in breakdown)


def test_a_tag_pin_is_reported_as_the_weaker_form():
    score, breakdown, level = calculate_score(
        [{"rule_id": "R001", "severity": "LOW", "name": "Curl", "match": "curl"}],
        {}, NoveltyContext(), SHARED_CONFIG,
        pinning_level="tag_pinned",
    )
    # A tag pin buys nothing: a tag can be repointed, which is what R079 is for.
    assert score == 5
    assert any(e.rule_id == "P006" and e.weight == 0 for e in breakdown)


# --- Inconclusive state ---

def test_inconclusive_on_cold_novelty_only():
    """Score 25 from novelty only, no observations → Inconclusive."""
    triggered = [{"rule_id": "R010", "severity": "LOW", "name": "Curl", "match": "curl"}]
    novelty = NoveltyContext(
        url_first_seen_globally=True,
        observation_count=0,
    )
    score, breakdown, level = calculate_score(
        triggered, {"https://evil.com/x": "unknown"}, novelty, SHARED_CONFIG,
    )
    # 5 (LOW) + 20 (unknown) + 15*0 (maturity=0) = 25 → Medium → Inconclusive
    assert score == 25
    assert level == "Inconclusive"


def test_inconclusive_medium_score_cold_db():
    """Score 30 from novelty only, cold DB → Inconclusive."""
    triggered = [{"rule_id": "R001", "severity": "LOW", "name": "Curl", "match": "curl"}]
    novelty = NoveltyContext(
        url_first_seen_globally=True,
        url_first_seen_in_this_package=True,
        observation_count=0,
    )
    score, breakdown, level = calculate_score(
        triggered, {"https://evil.com/x": "unknown"}, novelty, SHARED_CONFIG,
    )
    # 5 (LOW) + 20 (unknown) + 0*15 + 0*10 = 25 → Medium
    # No HIGH/CRITICAL/FATAL in breakdown
    assert score == 25
    assert level == "Inconclusive"


def test_inconclusive_not_when_high_severity():
    """HIGH rule present → stays Medium, not Inconclusive."""
    triggered = [{"rule_id": "R004", "severity": "HIGH", "name": "Checksum Skip", "match": "SKIP"}]
    novelty = NoveltyContext(observation_count=0)
    score, breakdown, level = calculate_score(triggered, {}, novelty, SHARED_CONFIG)
    assert score == 25
    assert level == "Medium"  # stays Medium because HIGH signal is present


def test_inconclusive_not_warm_db():
    """Warm DB (obs >= 25) → Medium, not Inconclusive."""
    triggered = [{"rule_id": "R001", "severity": "LOW", "name": "Curl", "match": "curl"}]
    novelty = NoveltyContext(
        url_first_seen_globally=True,
        observation_count=30,
    )
    score, breakdown, level = calculate_score(
        triggered, {"https://evil.com/x": "unknown"}, novelty, SHARED_CONFIG,
    )
    # 5 (LOW) + 20 (unknown) + 10*0.6 (maturity=30/50) = 31 → Medium
    assert score == 31
    assert level == "Medium"


def test_novelty_weights_keep_a_borderline_package_out_of_high():
    """Calibration criterion: at full maturity, a genuinely novel URL --
    even alongside a novel maintainer, must lift a borderline package
    into Medium, not High.  The pre-calibration 15/10/20 reached 60."""
    from trustsight.config import DEFAULT_CONFIG

    config = tomllib.loads(DEFAULT_CONFIG)
    borderline = [
        {"rule_id": "X", "name": "n", "severity": "LOW", "category": "c", "match": "m"}
    ] * 3  # 15 points

    novelty = NoveltyContext(
        url_first_seen_globally=True,
        url_first_seen_in_this_package=True,
        maintainer_first_seen_for_this_package=True,
        observation_count=148720,
    )
    score, _, level = calculate_score(borderline, {}, novelty, config)
    assert 20 < score <= 50, f"expected Medium, got {score}"
    assert level == "Medium"


def test_maintainer_novelty_remains_the_strongest_signal():
    """A maintainer change is the xz-utils vector; it should outweigh a
    novel URL."""
    from trustsight.config import DEFAULT_CONFIG

    weights = tomllib.loads(DEFAULT_CONFIG)["novelty_weights"]
    assert weights["maintainer_first_in_package"] > weights["url_first_globally"]
    assert weights["url_first_globally"] > weights["url_first_in_package"]


def test_a_fatal_finding_names_itself_in_the_label():
    """B4's FATAL is structurally special; the band alone cannot say so.

    A FATAL caps the score at 100, so it arrives as `Critical` - and so does
    a score that merely accumulated to 81. The distinction rides
    `risk_label` rather than a new band, because `risk` is a closed enum
    consumers gate on and the severity is in `score_breakdown` either way.
    """
    from trustsight.schema import PackageFact, ScoreEntry
    from trustsight.scoring import verdict_label, verdict_level

    fatal = PackageFact(
        package_name="d", final_score=100, risk="Critical",
        score_breakdown=[ScoreEntry(rule_id="R013", severity="FATAL",
                                    weight=0, reason="unicode deception")],
    )
    assert verdict_level(fatal) == "Critical"          # the enum is unchanged
    assert verdict_label(fatal) == "Critical (FATAL: R013)"

    # An accumulated Critical with no FATAL reads exactly as before.
    plain = PackageFact(package_name="d", final_score=90, risk="Critical")
    assert verdict_label(plain) == "Critical"


def test_a_fatal_label_still_carries_the_coverage_gap():
    """Naming the FATAL must not displace B2's qualifier."""
    from trustsight.schema import PackageFact, ScoreEntry
    from trustsight.coverage import INCOMPLETE_SUFFIX
    from trustsight.scoring import verdict_label

    fact = PackageFact(
        package_name="d", final_score=100, risk="Critical",
        coverage_gaps=["diff_truncated"],
        score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL",
                                    weight=0, reason="injection")],
    )
    label = verdict_label(fact)
    assert "FATAL: R012" in label
    assert label.endswith(INCOMPLETE_SUFFIX)
