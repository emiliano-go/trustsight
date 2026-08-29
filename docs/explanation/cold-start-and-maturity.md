<!-- description: Why novelty signals are meaningless on the first run, how maturity gating withholds them until the database has seen enough, and what a cold run reports. -->

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

With the maturity gate, none of these novelty signals contribute until the
effective observation count is positive. Without an imported seed, the first
run is computed from structural rules (tier A) and domain classification (tier
B) only, which correctly flags the obscure package's unknown domain without
penalizing the kernel's trusted forge sources.

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
| `url_first_globally` | 10 | A URL never seen in any package is genuinely unusual. This is the strongest novelty signal. |
| `url_first_in_package` | 5 | A URL new to this specific package but seen elsewhere. Weaker because it may just reflect a new package in your set. |
| `maintainer_first` | 15 | A maintainer never recorded for this package is a significant flag. Maintainer changes are a known attack vector (xz utils). The highest novelty weight reflects this. |

The maintainer-first weight is highest because a maintainer change without a corresponding announcement or discussion is a social-engineering red flag. Unlike URLs, which change routinely with version bumps, maintainer changes are rare and structurally significant.

## How novelty interacts with other evidence tiers

Novelty signals do not fire in isolation. They are evaluated alongside:

- **Structural signals (tier A)**: a novel URL from a trusted forge with a valid checksum is less concerning than a novel URL from an unknown domain with checksums disabled.
- **Context signals (tier B)**: a `trusted_forge` domain adds nothing of its own (its bucket modifier is 0). Novelty on an `unknown` or `homograph` domain compounds with the bucket weight.
- **Verification signals (tier D)**: a novel URL with a checksum and PGP signature is less concerning than one without.

The interaction is additive, not multiplicative. Each signal contributes independently, so a package with a novel URL on an unknown domain with no checksum accumulates contributions from all three.

## The seed database

A cold database is not the usual state. TrustSight fetches and imports a
verified novelty seed on first run. The seed records 179,956 normalized
source URLs, about 35,903 maintainers, and 209,909 dependency names, plus a bootstrap
observation count. Maturity uses the greater of that seed count and the local
analysis count, not a per-package count. See [`trustsight seed-db`](../reference/cli.md#trustsight-seed-db).

Measured against the AUR mirror, the seed recognises **86%** of the source URLs in a package's most recent update. That figure falls off for older updates (62% mid-history, 20% for the oldest commit in a 30-commit window) because the seed is a snapshot of current `.SRCINFO` state, and historical versions used paths that no longer exist. Since a review always concerns the newest update, 86% is the number that matters in practice; corpus replays over deep history understate it.

The weights only have an effect where `observation_count` is populated. With no
observations the maturity multiplier is 0, and every novelty weight resolves to
zero whatever its configured value.

## The INCONCLUSIVE downgrade

When the final score is in the Medium range (21 to 50), maturity is below 0.5 (fewer than 25 recorded analyses, half of the 50 at which novelty reaches full weight), and nothing in the breakdown is HIGH, CRITICAL or FATAL, the verdict is downgraded from FLAGGED to INCONCLUSIVE. A single HIGH finding blocks the downgrade: the score is then held up by evidence, not by novelty.

The logic:
1. Compute the score normally.
2. If the score lands in the Medium band (21 to 50) and maturity is below 0.5, look at the severity of every entry in the breakdown.
3. If none of them is HIGH, CRITICAL or FATAL, nothing but weak signals is holding the score up.
4. Downgrade to INCONCLUSIVE: *"Score is Medium but nothing strong fired, and the database is too cold for novelty to be reliable."*

This prevents the tool from flagging packages based on weak signals. INCONCLUSIVE is not a pass or a fail; it is a signal that the tool cannot be confident in its assessment.

A coverage gap produces the same downgrade at any maturity, for a different reason: the run did not see the whole change. See [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

## Maturity and maintainer tracking

Maintainer novelty follows the same maturity curve as URL novelty. On first run, every maintainer change is recorded but contributes 0 to the score. As observations accumulate, maintainer novelty ramps in: a new maintainer for a well-established package at 50+ observations is flagged at full weight.

Maintainer tracking is per-package: a maintainer who maintains 100 packages will be "known" for each package individually as they are observed. A maintainer change on a package that has been observed 50 times is weighted fully, even if the same maintainer is new to that specific package.

## What the user sees

Without a seed, first-run scores are computed from structural signals (A) and
priors (B) only. History signals (C) contribute nothing until the effective
observation count rises. With a verified seed, Tier C may already be mature on
the first local run.

This means first-run scores are conservative; they catch structural threats (curl|bash, homograph domains) but will not flag a package solely because it has never been seen before. As the corpus accumulates observations, novelty signals phase in automatically.

The database warms up as you run `trustsight review`. Each run records the
current state of every outdated package. Novelty reaches full weight once the
effective observation count reaches 50.
