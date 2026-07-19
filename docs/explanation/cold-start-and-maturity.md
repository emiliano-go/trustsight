# Cold Start and Maturity

TrustSight operates in two regimes: **cold DB** (first run, no history) and **warm DB** (established observation history). The behaviour is different by design.

## The two-regime problem

Novelty signals (tier C) depend on observation counts. On first run:

- Every URL is first-seen.
- Every maintainer is first-seen.
- Novelty fires on 100% of packages, which means it carries zero bits of information.

This is a cold-start problem. If novelty contributed at full weight from run one, every package audited on the first day would score higher than it should. Worse, the signal would be inversely useful: it would flag the most common, most well-known URLs (because they have not been seen in this specific database) while missing genuinely novel ones.

### A concrete example

You install TrustSight for the first time and run `trustsight review`. Your package set includes `linux-lts` (a well-known kernel package), `firefox-bin` (a well-known browser), and `some-obscure-forum-package` that you installed years ago.

Without a maturity gate, all three would get novelty penalties for their source URLs being "first-seen". The kernel package's kernel.org URLs would be flagged as novel, even though they are among the most well-established sources in the AUR. The obscure package's unknown-domain URLs would receive the same weight as the kernel's. The novelty signal would be noise.

With the maturity gate, none of these novelty signals contribute until the database accumulates observations. The first-run score is computed from structural rules (tier A) and domain classification (tier B) only, which correctly flags the obscure package's unknown domain without penalizing the kernel's trusted forge sources.

## Maturity gate

Novelty weights are scaled by a maturity factor:

```text
effective_weight = base_weight * min(1, observation_count / 50)
```

| Observations | Novelty weight contribution |
|-------------|---------------------------|
| 0 | 0 (inactive) |
| 25 | 50% of base weight |
| 50 | 100% of base weight |
| 100+ | 100% of base weight (capped) |

### Why 50 observations

The 50-observation threshold is a heuristic derived from the cold-start dynamics of the AUR corpus. At 50 observations, the database has seen enough package updates to establish a baseline of common URLs. A URL that has not appeared in any of those 50 observations is legitimately unusual.

The linear ramp from 0 to 50 avoids a sharp cutoff. A threshold like "novelty activates at 50 observations" would produce a discontinuous jump: a package reviewed at 49 observations would score differently from one reviewed at 50, even though the database state is nearly identical. The linear ramp smooths the transition.

Below 50 observations, the novelty weight is linearly scaled. At 0 observations, novelty contributes 0.

## Novelty weight structure

| Novelty signal | Full weight (at maturity) | Why this weight |
|----------------|---------------------------|-----------------|
| `url_first_globally` | 15 | A URL never seen in any package is genuinely unusual. This is the strongest novelty signal. |
| `url_first_in_package` | 10 | A URL new to this specific package but seen elsewhere. Weaker because it may just reflect a new package in your set. |
| `maintainer_first` | 20 | A maintainer never recorded for this package is a significant flag. Maintainer changes are a known attack vector (xz utils). The highest novelty weight reflects this. |

The maintainer-first weight is highest because a maintainer change without a corresponding announcement or discussion is a social-engineering red flag. Unlike URLs, which change routinely with version bumps, maintainer changes are rare and structurally significant.

## How novelty interacts with other evidence tiers

Novelty signals do not fire in isolation. They are evaluated alongside:

- **Structural signals (tier A)**: a novel URL from a trusted forge with a valid checksum is less concerning than a novel URL from an unknown domain with checksums disabled.
- **Context signals (tier B)**: novelty on a `trusted_forge` domain is discounted by the source bucket modifier. Novelty on an `unknown` or `homograph` domain compounds with the bucket weight.
- **Verification signals (tier D)**: a novel URL with a checksum and PGP signature is less concerning than one without.

The interaction is additive, not multiplicative. Each signal contributes independently, so a package with a novel URL on an unknown domain with no checksum accumulates contributions from all three.

## The INCONCLUSIVE downgrade

When the final score is in the Medium range (21 to 50) and all contributing signals are Tier C novelty and maturity is below 0.5 (fewer than approximately 25 observations), the verdict is downgraded from FLAGGED to INCONCLUSIVE.

The logic:
1. Compute the score normally.
2. If score > 20 (Medium or higher) and maturity < 0.5, check whether the score is driven entirely by novelty signals.
3. If no structural rules (tier A) fired and no source bucket penalties (tier B) contributed, the score is from novelty alone.
4. Downgrade to INCONCLUSIVE: *"Score is Medium but all signals are from novelty, and the database is too cold for novelty to be reliable."*

This prevents the tool from flagging packages based on weak signals. INCONCLUSIVE is not a pass or a fail; it is a signal that the tool cannot be confident in its assessment.

## Maturity and maintainer tracking

Maintainer novelty follows the same maturity curve as URL novelty. On first run, every maintainer change is recorded but contributes 0 to the score. As observations accumulate, maintainer novelty ramps in: a new maintainer for a well-established package at 50+ observations is flagged at full weight.

Maintainer tracking is per-package: a maintainer who maintains 100 packages will be "known" for each package individually as they are observed. A maintainer change on a package that has been observed 50 times is weighted fully, even if the same maintainer is new to that specific package.

## What the user sees

On first run, the verdict includes the notice: *"novelty inactive"*. First-run scores are computed from structural signals (A) and priors (B) only. History signals (C) contribute nothing until the corpus matures.

This means first-run scores are conservative; they catch structural threats (curl|bash, homograph domains) but will not flag a package solely because it has never been seen before. As the corpus accumulates observations, novelty signals phase in automatically.

The database warms up as you run `trustsight review`. Each run records the current state of every outdated package. After approximately 50 total observations across all packages, novelty reaches full weight.
