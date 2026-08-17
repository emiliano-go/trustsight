from .config import load_config
from .coverage import GAP_REASONS, fail_closed, inconclusive_label, qualified_band
from .schema import NoveltyContext, ScoreEntry

_MATURITY_THRESHOLD = 50

# The UNFLAGGED ceiling.  Measured, not chosen: it is the 95th percentile of
# the benign corpus.  risk_level() and every consumer read this rather than
# repeating 20.
FLAG_THRESHOLD = 20

# B10.  Verification and hardening signals are *declared* by the recipe and
# never confirmed by this tool: TrustSight does not fetch, so it never learns
# that a declared key signs anything or that a pinned commit holds what it
# claims.  Adding ``validpgpkeys=(...)``, pinning a ``#commit=``, or routing
# through github.com costs an attacker nothing.  A signal an attacker can
# assert for free must not be able to lower a score, because the only
# reliable effect of such a mechanism is buying points back for whoever
# bothers to read the rules.  So these are emitted at weight 0 and reported
# to the person, who can check them in ways the tool cannot.  That is the
# division of labour the whole model rests on.
#
# This replaces subtractive weights (checksum_present -10,
# validpgpkeys_declared -10, gpg_verify_present -5, checksum_pinned -5,
# tag_pinned -3, and a trusted-forge credit capped at -20).  The calibration
# problem they existed to solve, a package doing GPG verification scoring
# worse than one doing nothing because SKIP on a .asc file added points, is
# fixed at source instead: R004 does not fire on a SKIP that is mandatory
# for a VCS source, structurally uncheckable for a signature file, or
# covered by declared PGP keys (``is_skip_justified``).  Stopping the false
# positive was the right fix; paying it back was not.
# The P namespace: declared-practice findings.  Deliberately not "benign
# rules": they do not establish that anything is benign, they report that
# the recipe *declares* a verification or hardening practice.  A distinct
# prefix means a reader seeing P0xx in the output knows immediately that it
# is not a risk finding.  Every one is INFO, weight 0, and checkable by the
# reader against the file.
P_CHECKSUMS = "P001"
P_VALIDPGPKEYS = "P002"
P_SIGNATURE_SOURCE = "P003"
P_COMMIT_PINNED = "P005"
P_TAG_PINNED = "P006"
P_TRUSTED_FORGE = "P007"

# Buckets whose membership is itself the declared fact.  Kept beside the
# weights so that changing a weight cannot change which findings exist.
DECLARED_BUCKETS = frozenset({"trusted_forge"})

_PINNED_LEVELS = {"checksum_pinned": P_COMMIT_PINNED, "tag_pinned": P_TAG_PINNED}

_EVIDENCE_IDS = {
    "checksum_present": P_CHECKSUMS,
    "validpgpkeys_declared": P_VALIDPGPKEYS,
    "gpg_verify_present": P_SIGNATURE_SOURCE,
}

DECLARED_REASONS = {
    P_CHECKSUMS: "checksums declared for all non-VCS sources",
    P_VALIDPGPKEYS: "validpgpkeys declared",
    P_SIGNATURE_SOURCE: "a signature source accompanies a source, with PGP keys declared",
    P_COMMIT_PINNED: "source pinned to a full commit hash",
    # Phrased so it cannot be read as reassurance: the tag pin is the weaker
    # form, and R079 exists precisely because a tag can be moved.
    P_TAG_PINNED: "source pinned to a tag (tags can be repointed; commit pins cannot)",
    P_TRUSTED_FORGE: "source hosted on a trusted forge over HTTPS",
}

# Which declared practices are worth stating unprompted.  Seventeen INFO
# lines on every package buries the risk findings, which is the opposite of
# what the group is for, so the default set is the ones a reader would find
# *surprising by their absence*.  The rest render under --verbose.
DECLARED_DEFAULT = frozenset({P_VALIDPGPKEYS, P_COMMIT_PINNED, P_SIGNATURE_SOURCE})

# What the group must say wherever it is rendered.  Not a disclaimer: it is
# the finding's actual content.  Without it the group reads as a safety
# certificate, which is the failure this model exists to prevent.
DECLARED_CAVEAT = (
    "TrustSight does not verify these claims. It reports that the recipe "
    "makes them."
)


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
    if score <= FLAG_THRESHOLD:
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


def _cold_start_remaining(fact) -> int | None:
    """Analyses still needed before the cold-start downgrade lifts.

    The downgrade stops applying when :func:`maturity` reaches 0.5, which
    is half of ``_MATURITY_THRESHOLD`` observations.  Both numbers are
    derived here from the constant rather than restated, so the count in
    the label cannot drift from the predicate it describes.  ``None``
    when the fact's package is already past the half point.
    """
    half = -(-_MATURITY_THRESHOLD // 2)
    obs = getattr(getattr(fact, "novelty_context", None), "observation_count", 0) or 0
    if obs >= half:
        return None
    return half - obs


def verdict_label(fact) -> str:
    """The band for *fact* as it must be shown to a person.

    Same value as :func:`verdict_level`, qualified when the run did not
    see the whole change, and - for Inconclusive - naming its cause: a
    coverage gap reads as the urgent case ("payload may be hidden"), a
    cold database as the routine one, with the analyses still needed
    (see :func:`coverage.inconclusive_label`).  Every human-facing
    render uses this; machine output uses ``verdict_level`` plus
    ``coverage_gaps``, so a consumer gets the two facts separately
    instead of parsing a sentence.
    """
    level = verdict_level(fact)
    gaps = getattr(fact, "coverage_gaps", [])
    if level == "Inconclusive":
        return inconclusive_label(gaps, _cold_start_remaining(fact))
    return qualified_band(_fatal_label(level, fact), gaps)


def _fatal_label(level: str, fact) -> str:
    """Name the FATAL rule behind a band, when one fired.

    A FATAL caps the score at 100, so it always arrives as ``Critical`` -
    and so does a score that merely accumulated to 81. Those are different
    claims: a FATAL rule is unsuppressible by construction (B4) and the two
    shipped ones target the *reviewer* rather than the machine, which is a
    different threat class from a package that scored badly.

    The distinction rides ``risk_label`` rather than a new band, because
    ``risk`` is a closed enum consumers gate on and no information is lost
    without it: the severity is in ``score_breakdown`` either way. This is
    the same "band plus its cause" shape ``inconclusive_label`` uses.
    """
    fatal = [
        e for e in getattr(fact, "score_breakdown", ()) or ()
        if getattr(e, "severity", "") == "FATAL"
    ]
    if not fatal:
        return level
    names = ", ".join(dict.fromkeys(e.rule_id for e in fatal if e.rule_id))
    return f"{level} (FATAL: {names})" if names else level


#: The band a confirmed CRITICAL finding may not read below.
CRITICAL_BAND_FLOOR = "High"

_BAND_ORDER = ("Low", "Medium", "High", "Critical")


def _floor_for_critical(level: str, breakdown) -> str:
    """Raise *level* to :data:`CRITICAL_BAND_FLOOR` when a CRITICAL fired.

    CRITICAL weighs 40 and the High band opens at 51, so arithmetic alone
    can never put a *single* CRITICAL finding above Medium - a lone fork
    bomb or `rm -rf /` reads "Medium" while a `curl | bash` reads High only
    because it happens to trip three rules at once. One confirmed CRITICAL
    finding is not a medium situation whatever the sum says.

    Severity overriding arithmetic is the existing shape rather than a new
    one: B4 already lets a FATAL cap the score at 100 regardless of the
    total. This is the same mechanism one notch weaker, and it moves the
    *band* only - no score changes, so the calibrated separation between
    the benign and malicious score populations is untouched.
    """
    if level not in _BAND_ORDER:
        return level
    if not any(getattr(e, "severity", "") == "CRITICAL" for e in breakdown or ()):
        return level
    if _BAND_ORDER.index(level) >= _BAND_ORDER.index(CRITICAL_BAND_FLOOR):
        return level
    return CRITICAL_BAND_FLOOR


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
        weight = rule.get("weight_override", severity_weights.get(rule["severity"], 0))
        if not isinstance(weight, int):
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
    forge_urls: list[str] = []
    # The source-bucket prior is a property of the source *list*, not of
    # each URL in it: a package that adds thirty unknown-host URLs is one
    # diff whose provenance is unknown, not thirty separate facts.  Under
    # per-URL summation a legitimate multi-source package (electron,
    # fonts) scored like a CRITICAL finding, which the §10 separation gate
    # (benign_p95 < malicious_p5) caught.  The modifier of the least-trusted
    # single added URL is the whole contribution; the homograph penalty
    # (+30) still outranks the unknown one (+20) when both appear.
    bucket_modifier = 0
    bucket_url: str | None = None
    bucket_name: str | None = None
    for url, bucket in source_buckets.items():
        modifier = bucket_weights.get(bucket, 0)
        if bucket in DECLARED_BUCKETS:
            # Identity, not weight.  This used to test `modifier < 0`, so
            # when trusted_forge went to 0 under B10 the branch became
            # unreachable and P007 stopped existing in production while
            # still firing in tests, whose config still carried -10.
            forge_urls.append(url)
            continue
        if modifier > bucket_modifier:
            bucket_modifier = modifier
            bucket_url, bucket_name = url, bucket
    if bucket_url is not None:
        base += bucket_modifier
        severity = "INFO" if bucket_modifier <= 0 else "MEDIUM"
        breakdown.append(
            ScoreEntry(
                rule_id="SOURCE_BUCKET",
                severity=severity,
                weight=bucket_modifier,
                reason=f"Source URL classified as {bucket_name} ({bucket_url})",
            )
        )
    if forge_urls:
        breakdown.append(
            ScoreEntry(
                rule_id=P_TRUSTED_FORGE,
                severity="INFO",
                weight=0,
                reason=DECLARED_REASONS[P_TRUSTED_FORGE],
                params={"count": len(forge_urls)},
                evidence={"count": len(forge_urls)},
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

    pin_id = _PINNED_LEVELS.get(pinning_level)
    if pin_id:
        breakdown.append(
            ScoreEntry(
                rule_id=pin_id, severity="INFO", weight=0,
                reason=DECLARED_REASONS[pin_id],
            )
        )

    for evidence in (verification_evidence or []):
        evidence_id = _EVIDENCE_IDS.get(evidence)
        if evidence_id is None:
            continue
        breakdown.append(
            ScoreEntry(
                rule_id=evidence_id, severity="INFO", weight=0,
                reason=DECLARED_REASONS[evidence_id],
            )
        )

    final = max(0, min(100, base))
    level = _floor_for_critical(risk_level(final), breakdown)
    if level == "Medium" and maturity(novelty.observation_count) < 0.5:
        has_strong_signal = any(
            e.severity in ("HIGH", "CRITICAL", "FATAL") for e in breakdown
        )
        if not has_strong_signal:
            level = "Inconclusive"
    level = fail_closed(level, coverage_gaps or [], breakdown)
    return final, breakdown, level


def stored_band(row: dict | None, score: int | None = None) -> tuple[str, bool]:
    """The band for a *stored* analysis row, and whether it was complete.

    ``history`` and ``list`` used to re-derive the band from the saved
    score with :func:`risk_level`, which cannot express "Inconclusive" and
    knows nothing about coverage.  A run reported as incomplete by
    ``review`` therefore displayed a bare "Low" or "Medium" the next time
    it was listed, which is precisely what B2 forbids.

    The band and the gaps are already in the row's ``fact_json``, so no
    schema change is needed.  Rows written before that field existed fall
    back to the derived band and are reported as complete, which is the
    only thing that can be said about them honestly.
    """
    import json

    if not row:
        return "", True
    raw = row.get("fact_json")
    if raw:
        try:
            fact = json.loads(raw)
        except (ValueError, TypeError):
            fact = {}
        band = fact.get("risk") or ""
        gaps = fact.get("coverage_gaps") or []
        if band == "Inconclusive":
            if gaps:
                return inconclusive_label(gaps), False
            # The stored row has no observation count, so the cold-start
            # cause is named without the remaining-analyses count that a
            # live fact can show.
            return "Inconclusive (cold start)", True
        if band:
            return qualified_band(band, gaps), not gaps
    if score is None:
        score = row.get("final_score", 0) or 0
    return risk_level(score), True
