# Cold Start and Maturity

TrustSight operates in two regimes: **cold DB** (first run, no history) and **warm DB** (established observation history). The behaviour is different by design.

## The two-regime problem

Novelty signals (tier C) depend on observation counts. On first run:

- Every URL is first-seen.
- Every maintainer is first-seen.
- Novelty fires on 100% of packages → zero bits of information.

This is a cold-start problem. If novelty contributed at full weight from run one, every package audited on the first day would score higher than it should.

## Maturity gate

Novelty weights are scaled by a maturity factor:

```text
effective_weight = base_weight × min(1, observation_count / 50)
```

| Observations | Novelty weight contribution |
|-------------|---------------------------|
| 0 | 0 (inactive) |
| 25 | 50% of base weight |
| 50 | 100% of base weight |
| 100+ | 100% of base weight (capped) |

Below 50 observations, the novelty weight is linearly scaled. At 0 observations, novelty contributes 0.

## Novelty weight structure

| Novelty signal | Full weight (at maturity) |
|----------------|--------------------------|
| `url_first_globally` | 15 |
| `url_first_in_package` | 10 |
| `maintainer_first` | 20 |

## What the user sees

On first run, the verdict includes the notice: *"novelty inactive"*. First-run scores are computed from structural signals (A) and priors (B) only. History signals (C) contribute nothing until the corpus matures.

This means first-run scores are conservative; they catch structural threats (curl|bash, homograph domains) but won't flag a package solely because it's never been seen before. As the corpus accumulates observations, novelty signals phase in automatically.

## Linking

This page is directly reachable from [quickstart](../getting-started/quickstart.md) and [reading a report](../getting-started/reading-a-report.md).
