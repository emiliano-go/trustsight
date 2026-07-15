from .config import load_config
from .schema import NoveltyContext, ScoreEntry


def risk_level(score: int) -> str:
    if score <= 20:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 80:
        return "High"
    else:
        return "Critical"


def calculate_score(
    triggered_rules: list[dict],
    source_buckets: dict[str, str],
    novelty: NoveltyContext,
    config: dict | None = None,
) -> tuple[int, list[ScoreEntry], str]:
    if config is None:
        config = load_config()

    base = 0
    breakdown: list[ScoreEntry] = []

    severity_weights = config.get("severity_weights", {})
    for rule in triggered_rules:
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
    if novelty.url_first_seen_globally:
        w = novelty_weights.get("url_first_globally", 15)
        base += w
        breakdown.append(
            ScoreEntry(
                rule_id="NOVELTY",
                severity="HIGH" if w > 10 else "MEDIUM",
                weight=w,
                reason="Source URL first seen globally",
            )
        )
    if novelty.url_first_seen_in_this_package:
        w = novelty_weights.get("url_first_in_package", 10)
        base += w
        breakdown.append(
            ScoreEntry(
                rule_id="NOVELTY",
                severity="MEDIUM",
                weight=w,
                reason="Source URL first seen in this package",
            )
        )
    if novelty.maintainer_first_seen_for_this_package:
        w = novelty_weights.get("maintainer_first_in_package", 20)
        base += w
        breakdown.append(
            ScoreEntry(
                rule_id="NOVELTY",
                severity="HIGH",
                weight=w,
                reason="Maintainer first seen for this package",
            )
        )

    final = max(0, min(100, base))
    level = risk_level(final)
    return final, breakdown, level
