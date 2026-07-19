# Benchmarks and Methodology

## How separation is measured: per-class, not pooled

The lesson that made the evaluation converge.

Early benchmarks pooled all malicious-class packages together and compared the pooled mean/median against the benign mean/median. This produced a misleading picture: the gap appeared to be ~5 points, which was not useful for decision-making.

The fix was to split by class. When CRITICAL-only packages were isolated from the rest, the separation became meaningful:

- **CRITICAL** p5 = 40
- **Benign** p95 = 20
- Gap = +20 points

Pooling was hiding the separation. Advisory-level and low-severity malware dragged the malicious-class average down, while the benign tail dragged the benign average up. Per-class measurement revealed that the tool cleanly separates the threats that matter.

## Why benign-p95-vs-malicious-p5 is the number that matters

Absolute p95 on either class is not useful in isolation. A tool that scores everything 50 would have a benign p95 of 50 and a malicious p95 of 50; no separation. The gap between the bottom 5th percentile of malicious scores and the top 95th percentile of benign scores is the operational separation: how much room is there to set a threshold that catches real threats without false-positive burden.

## Per-class CI gates

The benchmark enforces three gates:

| Gate | Requirement |
|------|-------------|
| CRITICAL-class recall | 100% (all CRITICAL samples detected) |
| CRITICAL-class p5 > benign p95 | Separation gate: the worst CRITICAL scores must exceed the best benign scores |
| Benign zero-rate ≥ 80% | Drift detection: prevents weight inflation that would catch benign packages |

**Current numbers:**

| Metric | Value |
|--------|-------|
| Benign zero-rate | 81.5% |
| CRITICAL recall | 100% (12/12) |
| CRITICAL p5 | 40 |
| Benign p95 | 20 |
| Tests | 267 |

## Reproducible methodology

- **Corpus pinned** via `corpus.lock`: the AUR snapshot is versioned and reproducible.
- **Baseline committed** as `baseline.json`: benchmark results are checked into the repository.
- **Regeneration** is weekly, with pinned snapshots kept for reproducibility.

## Per-stratum evaluation

The test set is divided into 8 strata. Each stratum has a per-stratum 70% recall target:

| Strata result | Count |
|---------------|-------|
| Strata clear | 6/8 |
| Target | 70% per stratum |

The per-stratum requirement prevents the benchmark from optimizing for easy classes while ignoring hard ones.

## The methodology habit

1. Pool results → get suspicious.
2. Split by class → find the truth.
3. Measure the gap, not the absolute.
