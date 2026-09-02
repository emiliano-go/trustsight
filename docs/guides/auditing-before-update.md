<!-- description: The everyday TrustSight workflow: run a review before yay -Syu or pacman -Syu to catch structural risk and careless malice in PKGBUILD diffs before they land. -->

# Auditing Before Update

The everyday workflow. Run `trustsight review` before `yay -Syu` or `pacman -Syu` to catch structural risk and careless malice in PKGBUILD diffs before they land on disk.

```bash
trustsight review
```

## What a normal update looks like

Most packages score **0**. A clean version bump, checksums updated, no structural changes, known domains, produces no risk signals.

Some packages may score **5-15** from novelty. This includes a source URL first observed globally. The [maturity gate](../explanation/cold-start-and-maturity.md) uses the database-wide effective observation count and scales this contribution up to full weight over 50 observations.

A table of 20 packages where 18 score 0, 2 score 8-12, and the verdict reads **UNFLAGGED** on every row; that is normal. Proceed with your update.

## What anomalies look like

| Score range | What it means |
|-------------|---------------|
| **25-40** | One or more risk signals fired. A checksum was removed, a new source domain appeared, or an [R-series or H-series rule](../reference/rules/index.md) matched. |
| **41-80** | Multiple signals or a HIGH-severity finding. Do not update without inspecting. |
| **81-100** | CRITICAL or FATAL signals present. [R012/R013](../reference/rules/system.md#fatal-rules) (the FATAL rules) set score to 100 unconditionally. |
| **INCONCLUSIVE** | Either the score landed in the Medium range with nothing HIGH or worse behind it and the database-wide maturity is below 0.5 (fewer than 25 effective observations), or the analysis had a coverage gap and could not examine the whole change (see [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)). |

> **Practical threshold:** score **25+** warrants attention. **40+** means skip the update and inspect first.

## When to dig deeper

Run `trustsight inspect <package>` whenever:

- The **score exceeds 20** (the verdict is FLAGGED).
- The **verdict is INCONCLUSIVE**: even if the numeric score looks moderate.
- A FATAL rule (R012/R013) fires: score becomes 100 regardless of other signals.

The inspect command shows the raw diff summary, every rule that fired, and the resolved commands and source URLs. See [acting on a flag](acting-on-a-flag.md) for the full decision framework.

## The scoring model in brief

TrustSight scores are deterministic; the same inputs always produce the same score. See the [scoring philosophy](../explanation/scoring-philosophy.md) for details.

The final score is the weighted sum of all triggered rules across four [evidence tiers](../reference/evidence-tiers.md):

| Tier | Category | Examples |
|------|----------|----------|
| **A** | Structural | Checksum disabled, source URL changed, new dependency added |
| **B** | Priors / context | Domain trust buckets, prior package history |
| **C** | History / novelty | First-seen URLs, maturity-gated weight |
| **D** | Verification | Declared checksums, `validpgpkeys`, GPG source, source pinning: reported as `P001`-`P008` at weight 0 |

Tier D never moves the score. Those are claims the recipe makes and TrustSight
cannot confirm, so they are reported for you to check rather than credited; see
[B10](../security.md#b10-positive-evidence-is-reported-never-credited).

Three verdict states are possible:

| Verdict | Score | Meaning |
|---------|-------|---------|
| **UNFLAGGED** | ≤20 | No significant risk signals |
| **FLAGGED** | >20 | One or more signals fired; investigate |
| **INCONCLUSIVE** | 21-50, or any | Medium score with nothing strong behind it and a cold database, or an analysis with a coverage gap at any score |

See the [report schema](../reference/report-schema.md) for the full scoring breakdown.

## Exit codes

- **0**: analysis completed. This says nothing about whether a package was flagged.
- **2**: analysis could not run or complete, such as a network failure or malformed config.
- **130**: interrupted with `Ctrl+C`.

A FLAGGED or INCONCLUSIVE result still exits `0`: the exit code answers whether the tool ran, not whether a package is safe. When scripting, run `trustsight review --score --json` and gate on scores plus `coverage_gaps`; do not gate on the TrustSight exit code. See [exit codes](../reference/exit-codes.md) and [using TrustSight in CI](using-in-ci.md).
