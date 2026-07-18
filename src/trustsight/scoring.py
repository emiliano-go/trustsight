from .config import load_config
from .schema import NoveltyContext, ScoreEntry

_MATURITY_THRESHOLD = 50

_DEFAULT_VERIFICATION_EVIDENCE = {
    "checksum_present": -5,
    "validpgpkeys_declared": -15,
    "gpg_verify_present": -20,
}

_DEFAULT_PINNING_WEIGHTS = {
    "checksum_pinned": -10,
    "tag_pinned": -5,
    "branch_pinned": 0,
    "unpinned": 0,
}


def maturity(n_obs: int) -> float:
    """Tier C maturity multiplier, 0.0 (cold) to 1.0 (warm).

    A package must be observed _MATURITY_THRESHOLD times before novelty
    signals are trusted at full weight.  Below that the multiplier ramps
    linearly so that a cold DB never fires high false-positive rates.
    """
    if n_obs <= 0:
        return 0.0
    if n_obs >= _MATURITY_THRESHOLD:
        return 1.0
    return n_obs / _MATURITY_THRESHOLD


def risk_level(score: int) -> str:
    if score <= 20:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 80:
        return "High"
    else:
        return "Critical"


_PINNING_ORDER = ["checksum_pinned", "tag_pinned", "branch_pinned", "unpinned"]


def calculate_score(
    triggered_rules: list[dict],
    source_buckets: dict[str, str],
    novelty: NoveltyContext,
    config: dict | None = None,
    verification_evidence: list[str] | None = None,
    pinning_level: str = "unpinned",
) -> tuple[int, list[ScoreEntry], str]:
    if config is None:
        config = load_config()

    base = 0
    breakdown: list[ScoreEntry] = []
    has_fatal = False

    severity_weights = config.get("severity_weights", {})
    for rule in triggered_rules:
        if rule["severity"] == "FATAL":
            has_fatal = True
            breakdown.append(
                ScoreEntry(
                    rule_id=rule["rule_id"],
                    severity="FATAL",
                    weight=0,
                    reason=f"{rule['name']}: {rule.get('match', '')}",
                )
            )
            continue
        weight = severity_weights.get(rule["severity"], 0)
        base += weight
        breakdown.append(
            ScoreEntry(
                rule_id=rule["rule_id"],
                severity=rule["severity"],
                weight=weight,
                reason=f"{rule['name']}: {rule.get('match', '')}",
            )
        )

    if has_fatal:
        return 100, breakdown, "Critical"

    bucket_weights = config.get("source_bucket_weights", {})
    total_forge_modifier = 0
    for url, bucket in source_buckets.items():
        modifier = bucket_weights.get(bucket, 0)
        if modifier < 0:
            total_forge_modifier += modifier
            continue
        base += modifier
        severity = "INFO" if modifier <= 0 else "MEDIUM"
        weight_display = modifier
        breakdown.append(
            ScoreEntry(
                rule_id="SOURCE_BUCKET",
                severity=severity,
                weight=weight_display,
                reason=f"Source URL classified as {bucket} ({url})",
            )
        )
    if total_forge_modifier < 0:
        capped = max(total_forge_modifier, -20)
        base += capped
        breakdown.append(
            ScoreEntry(
                rule_id="SOURCE_BUCKET",
                severity="INFO",
                weight=capped,
                reason="Trusted forge modifier (capped at -20)",
            )
        )

    novelty_weights = config.get("novelty_weights", {})
    m = maturity(novelty.observation_count)
    if novelty.url_first_seen_globally:
        raw_w = novelty_weights.get("url_first_globally", 15)
        w = int(raw_w * m)
        if w > 0:
            base += w
            breakdown.append(
                ScoreEntry(
                    rule_id="NOVELTY",
                    severity="HIGH" if raw_w > 10 else "MEDIUM",
                    weight=w,
                    reason=f"Source URL first seen globally (maturity={m:.2f})",
                )
            )
    if novelty.url_first_seen_in_this_package:
        raw_w = novelty_weights.get("url_first_in_package", 10)
        w = int(raw_w * m)
        if w > 0:
            base += w
            breakdown.append(
                ScoreEntry(
                    rule_id="NOVELTY",
                    severity="MEDIUM",
                    weight=w,
                    reason=f"Source URL first seen in this package (maturity={m:.2f})",
                )
            )
    if novelty.maintainer_first_seen_for_this_package:
        raw_w = novelty_weights.get("maintainer_first_in_package", 20)
        w = int(raw_w * m)
        if w > 0:
            base += w
            breakdown.append(
                ScoreEntry(
                    rule_id="NOVELTY",
                    severity="HIGH",
                    weight=w,
                    reason=f"Maintainer first seen for this package (maturity={m:.2f})",
                )
            )

    pinning_weights = config.get("pinning_weights", _DEFAULT_PINNING_WEIGHTS)
    pin_modifier = pinning_weights.get(pinning_level, 0)
    if pin_modifier < 0:
        base += pin_modifier
        breakdown.append(
            ScoreEntry(
                rule_id="PINNING",
                severity="INFO",
                weight=pin_modifier,
                reason=f"Source pinning: {pinning_level} ({pin_modifier})",
            )
        )

    evidence_weights = config.get("verification_evidence", _DEFAULT_VERIFICATION_EVIDENCE)
    for evidence in (verification_evidence or []):
        modifier = evidence_weights.get(evidence, 0)
        if modifier == 0:
            continue
        base += modifier
        breakdown.append(
            ScoreEntry(
                rule_id="VERIFICATION",
                severity="INFO",
                weight=modifier,
                reason=f"Verification evidence: {evidence} ({modifier})",
            )
        )

    final = max(0, min(100, base))
    level = risk_level(final)
    if level == "Medium" and maturity(novelty.observation_count) < 0.5:
        has_strong_signal = any(
            e.severity in ("HIGH", "CRITICAL", "FATAL") for e in breakdown
        )
        if not has_strong_signal:
            level = "Inconclusive"
    return final, breakdown, level
