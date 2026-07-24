---
description: The core TrustSight workflow : run a review before updating AUR packages.
---

# Auditing Before Update

The everyday workflow. Run `trustsight review` before `yay -Syu` or `pacman -Syu` to catch structural risk and careless malice in PKGBUILD diffs before they land on disk.

```bash
trustsight review
```

## What a normal update looks like

Most packages score **0**. A clean version bump, checksums updated, no structural changes, known domains, produces no risk signals.

Some packages may score **5-15** on their first few appearances. This is novelty weight: the first time a source URL is observed globally, the [novelty evidence tier](../reference/evidence-tiers.md) (tier C) contributes a small score. The [maturity gate](../explanation/cold-start-and-maturity.md) scales this contribution up to full weight over 50 observations.

A table of 20 packages where 18 score 0, 2 score 8-12, and the verdict reads **CLEAN** on every row; that is normal. Proceed with your update.

## What anomalies look like

| Score range | What it means |
|-------------|---------------|
| **25-40** | One or more risk signals fired. A checksum was removed, a new source domain appeared, or a rule in the [R-series](../reference/rules.md) matched. |
| **41-80** | Multiple signals or a HIGH-severity finding. Do not update without inspecting. |
| **81-100** | CRITICAL or FATAL signals present. [R012/R013](../reference/rules.md#fatal-rules) (the FATAL rules) set score to 100 unconditionally. |
| **INCONCLUSIVE** | Score landed in the Medium range but only novelty (tier C) fired, and the database has fewer than 50 observations. The tool cannot form a confident picture; see [cold start](../explanation/cold-start-and-maturity.md). |

> **Practical threshold:** score **25+** warrants attention. **40+** means skip the update and inspect first.

## When to dig deeper

Run `trustsight inspect <package>` whenever:

- The **score exceeds 20** (the verdict is FLAGGED).
- The **verdict is INCONCLUSIVE**: even if the numeric score looks moderate.
- A FATAL rule (R012/R013) fires: score becomes 100 regardless of other signals.

The inspect command shows the raw diff summary, every rule that fired, and the resolved commands and source URLs. See [acting on a flag](acting-on-a-flag.md) for the full decision framework.

## The scoring model in brief

TrustSight scores are deterministic; the same inputs always produce the same score. The LLM is optional and only affects the verdict text, never the score. See the [scoring philosophy](../explanation/scoring-philosophy.md) for details.

The final score is the weighted sum of all triggered rules across four [evidence tiers](../reference/evidence-tiers.md):

| Tier | Category | Examples |
|------|----------|----------|
| **A** | Structural | Checksum disabled, source URL changed, new dependency added |
| **B** | Priors / context | Domain trust buckets, prior package history |
| **C** | History / novelty | First-seen URLs, maturity-gated weight |
| **D** | Verification | `checksum_present -10`, `validpgpkeys -10`, `gpg -5` |

Pinning modifiers also apply: `checksum_pinned -5`, `tag_pinned -3`.

Three verdict states are possible:

| Verdict | Score | Meaning |
|---------|-------|---------|
| **CLEAN** | ≤20 | No significant risk signals |
| **FLAGGED** | >20 | One or more signals fired; investigate |
| **INCONCLUSIVE** | 25-50 | Medium score, but only novelty signals and a cold database |

See the [report schema](../reference/report-schema.md) for the full scoring breakdown.

## Exit codes

- **0**: all packages CLEAN
- **1**: one or more packages FLAGGED
- **2**: error (e.g. network failure, malformed config)

When scripting, check the exit code to decide whether to proceed with `yay -Syu`. For finer-grained control, parse the score table or use the future JSON output mode. See [using TrustSight in CI](using-in-ci.md).
