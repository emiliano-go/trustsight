# Benchmarks and Methodology

## How separation is measured: per-class, not pooled

The lesson that made the evaluation converge.

Early benchmarks pooled all malicious-class packages together and compared the pooled mean and median against the benign mean and median. This produced a misleading picture: the gap appeared to be approximately 5 points, which was not useful for decision-making.

### Why pooling hid the separation

The malicious test corpus includes packages at multiple severity levels: CRITICAL (clear malicious patterns like curl pipe bash), HIGH (checksum manipulation), MEDIUM (unusual sources), and LOW (minor anomalies). Pooling them together averaged the high scores from CRITICAL packages with the lower scores from MEDIUM and LOW packages. The average was dominated by the low-severity tail, making it look like the tool did not separate malicious from benign.

The benign corpus includes package updates that are not perfectly clean: routine dependency changes, source URL format changes, and maintainer updates. The tail of the benign distribution (packages that score 5 to 20) pulled the benign average up. The pooled comparison compared the middle of both distributions, which overlapped significantly.

The fix was to split by class. When CRITICAL-only packages were isolated from the rest, the separation became meaningful:

- **CRITICAL** p5 = 40
- **Benign** p95 = 20
- Gap = +20 points

Pooling was hiding the separation. Advisory-level and low-severity malware dragged the malicious-class average down, while the benign tail dragged the benign average up. Per-class measurement revealed that the tool cleanly separates the threats that matter.

## Why benign-p95-versus-malicious-p5 is the number that matters

Absolute p95 on either class is not useful in isolation. A tool that scores everything 50 would have a benign p95 of 50 and a malicious p95 of 50, showing zero separation.

The gap between the bottom 5th percentile of malicious scores and the top 95th percentile of benign scores is the operational separation. It answers the question: how much room is there to set a threshold that catches real threats without false-positive burden?

If the CRITICAL p5 is 40 and the benign p95 is 20, a threshold set at 20 catches every CRITICAL-class sample in the benchmark set while labeling only 5% of benign packages as FLAGGED. The 20-point gap provides margin for error: if the threshold is set at 21 instead of 20, the false-positive rate drops further while still catching all CRITICAL samples.

The gap is measured as p5 of the worst class (CRITICAL) versus p95 of the benign class because these are the tails that matter for threshold setting. The center of the distribution is irrelevant for operational decision-making.

## Per-class CI gates

The benchmark enforces three gates:

| Gate | Requirement | What it prevents |
|------|-------------|------------------|
| CRITICAL-class recall | 100% (all CRITICAL samples detected) | A change that causes any CRITICAL sample to score 0 (missed detection) is rejected. Every CRITICAL pattern in the corpus must fire the expected rules. |
| CRITICAL-class p5 > benign p95 | Separation gate: the worst CRITICAL scores must exceed the best benign scores | A change that narrows the gap (by reducing CRITICAL scores or inflating benign scores) is rejected. The gap must stay at least 20 points. |
| Benign zero-rate >= 80% | Drift detection: prevents weight inflation that would catch benign packages | A change that increases benign scores (causing more false positives) is rejected if zero-rate drops below 80%. |

### Why three gates and not one

A single gate (for example, "CRITICAL recall >= 100%") would allow weight inflation: making all rules fire harder would increase CRITICAL scores but would also increase benign scores. The separation gate (p5 > p95) prevents this by requiring the gap to stay positive. The zero-rate gate prevents score drift that degrades the user experience for benign packages.

The three gates together enforce three distinct properties: detection (no missed threats), separation (meaningful threshold gap), and baseline (low false-positive rate). Each gate independently blocks regressions in its dimension.

### Current numbers

| Metric | Value | Benchmark target |
|--------|-------|------------------|
| Benign zero-rate | 81.5% | >= 80% |
| CRITICAL recall | 100% (12/12) | 100% |
| CRITICAL p5 | 40 | > benign p95 |
| Benign p95 | 20 | < CRITICAL p5 |
| Tests | 267 | n/a |

The numbers are not aspirational; they are the measured state of the current rule set and scoring model. A change that moves any metric past its gate is rejected in CI.

## Reproducible methodology

- **Corpus pinned** via `corpus.lock`: the AUR snapshot is versioned and reproducible. Two runs on different machines with the same lock file produce identical results.
- **Baseline committed** as `baseline.json`: benchmark results are checked into the repository. Every commit can be compared against the baseline to detect regressions.
- **Regeneration** is weekly, with pinned snapshots kept for reproducibility. The previous snapshot is archived so that past benchmarks remain reproducible.

The pinned corpus prevents a common failure mode in security tooling: benchmarks that improve over time because the corpus drifted toward easier samples. Pinning freezes the corpus, so any improvement or regression is from the tool, not the data.

## Per-stratum evaluation

The test set is divided into 8 strata. Each stratum has a per-stratum 70% recall target:

| Strata result | Count |
|---------------|-------|
| Strata clear | 6/8 |
| Target | 70% per stratum |

The per-stratum requirement prevents the benchmark from optimizing for easy classes while ignoring hard ones. A benchmark that measures only aggregate recall can achieve high numbers by detecting all easy samples while missing every sample in a difficult stratum. Per-stratum evaluation catches this: a stratum that cannot reach 70% recall indicates a blind spot in that class of attack.

Two strata currently fall below the 70% target. These are documented in the benchmark output and represent known difficult classes (unicode bidi variants and non-standard prompt-injection patterns). Improving these strata is an active area of work, and progress is measured by the per-stratum recall numbers.

## The methodology habit

1. Pool results, get suspicious. If pooled numbers look good, they are hiding a problem.
2. Split by class, find the truth. The real separation is in the tails, not the center.
3. Measure the gap, not the absolute. The gap between classes is the operational metric; absolute scores are meaningless in isolation.
4. Enforce per-stratum, not aggregate. Aggregate recall hides blind spots.

This methodology generalizes beyond TrustSight. Any security tool that claims a recall number should be asked: recall on what class, against what corpus, pinned at what version, and measured against which tail of the benign distribution?
