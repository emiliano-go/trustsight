from .config import load_config
from .coverage import GAP_REASONS, fail_closed, qualified_band
from .schema import NoveltyContext, ScoreEntry

_MATURITY_THRESHOLD = 50

_DEFAULT_VERIFICATION_EVIDENCE = {
    "checksum_present": -10,
    "validpgpkeys_declared": -10,
    "gpg_verify_present": -5,
}

_DEFAULT_PINNING_WEIGHTS = {
    "checksum_pinned": -5,
    "tag_pinned": -3,
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
    """Return the risk level label for a numeric score."""
    if score <= 20:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 80:
        return "High"
    else:
        return "Critical"


def verdict_level(fact) -> str:
    """The band for *fact*, as a bare value.

    ``risk_level(final_score)`` is the band the number alone implies.  It
    is not always the verdict: a cold database or an incomplete analysis
    downgrades the result to "Inconclusive", and that decision is made
    once, in :func:`calculate_score`, and carried on the fact.  Re-deriving
    it from the score throws the downgrade away, which is how "Inconclusive"
    used to be computed and then never displayed.
    """
    stored = getattr(fact, "risk", "")
    return stored or risk_level(getattr(fact, "final_score", 0))


def verdict_label(fact) -> str:
    """The band for *fact* as it must be shown to a person.

    Same value as :func:`verdict_level`, qualified when the run did not
    see the whole change.  Every human-facing render uses this; machine
    output uses ``verdict_level`` plus ``coverage_gaps``, so a consumer
    gets the two facts separately instead of parsing a sentence.
    """
    return qualified_band(verdict_level(fact), getattr(fact, "coverage_gaps", []))


def calculate_score(
    triggered_rules: list[dict],
    source_buckets: dict[str, str],
    novelty: NoveltyContext,
    config: dict | None = None,
    verification_evidence: list[str] | None = None,
    pinning_level: str = "unpinned",
    coverage_gaps: list[str] | None = None,
) -> tuple[int, list[ScoreEntry], str]:
    """Calculate the final trust score from triggered rules and context.

    *coverage_gaps* names what this run could not examine (see
    :mod:`trustsight.coverage`).  Gaps never move the score - they are not
    evidence about the package - but they do prevent the result from being
    labelled clean.
    """
    if config is None:
        config = load_config()

    base = 0
    breakdown: list[ScoreEntry] = []
    has_fatal = False

    severity_weights = config.get("severity_weights", {})
    for rule in triggered_rules:
        params = rule.get("params", {})
        file = rule.get("file", "")
        line = rule.get("line")
        template = rule.get("template", "")
        evidence = rule.get("evidence", params)
        if rule["severity"] == "FATAL":
            has_fatal = True
            breakdown.append(
                ScoreEntry(
                    rule_id=rule["rule_id"],
                    severity="FATAL",
                    weight=0,
                    reason=f"{rule['name']}: {rule.get('match', '')}",
                    params=params,
                    template=template,
                    evidence=evidence,
                    file=file,
                    line=line,
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
                params=params,
                template=template,
                evidence=evidence,
                file=file,
                line=line,
            )
        )

    # Recorded before the FATAL short-circuit so that "what was examined"
    # is on the record even for a capped score: a truncated diff that
    # already scored 100 still has an unexamined tail.
    for gap in (coverage_gaps or ()):
        breakdown.append(
            ScoreEntry(
                rule_id="COVERAGE",
                severity="INFO",
                weight=0,
                reason=f"Coverage gap: {GAP_REASONS.get(gap, gap)}",
                params={"gap": gap},
                evidence={"gap": gap},
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
    level = fail_closed(level, coverage_gaps or [], breakdown)
    return final, breakdown, level
