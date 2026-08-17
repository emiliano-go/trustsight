# Benchmarks and Methodology

## Scope of this evaluation

These results are regression measurements, not an independent efficacy study.
The malicious side consists of **self-authored, labelled fixtures**: historical
cases represented as fixtures plus holdout, evasion, synthetic, and campaign
fixtures maintained in this repository. Labels express what each fixture is
intended to exercise; they do not establish prevalence, real-world recall, or
adversarially independent performance. The benign side is a locked,
point-in-time AUR-derived corpus. Its measurements describe that snapshot and
the shipped configuration, not all AUR updates or future traffic.

An external blinded evaluation is the route for evidence beyond this internal
regression suite; see [Blinded Evaluation](../contributing/blinded-evaluation.md).

## How separation is measured: per-class, not pooled

The lesson that made the evaluation converge.

Early benchmarks pooled all malicious-class packages together and compared the pooled mean and median against the benign mean and median. This produced a misleading picture: the gap appeared to be approximately 5 points, which was not useful for decision-making.

### Why pooling hid the separation

The malicious test corpus includes packages at multiple severity levels: CRITICAL (clear malicious patterns like curl pipe bash), HIGH (checksum manipulation), MEDIUM (unusual sources), and LOW (minor anomalies). Pooling them together averaged the high scores from CRITICAL packages with the lower scores from MEDIUM and LOW packages. The average was dominated by the low-severity tail, making it look like the tool did not separate malicious from benign.

The benign corpus includes package updates that are not perfectly clean: routine dependency changes, source URL format changes, and maintainer updates. The tail of the benign distribution (packages that score 5 to 20) pulled the benign average up. The pooled comparison compared the middle of both distributions, which overlapped significantly.

The fix was to split by class. When CRITICAL-only packages were isolated from the rest, the separation became meaningful:

- **CRITICAL** p5 = 60
- **Benign** p95 = 35
- Gap = +25 points

Pooling was hiding the separation. Advisory-level and low-severity malware dragged the malicious-class average down, while the benign tail dragged the benign average up. Per-class measurement revealed that the tool cleanly separates the threats that matter.

## Why benign-p95-versus-malicious-p5 is the number that matters

Absolute p95 on either class is not useful in isolation. A tool that scores everything 50 would have a benign p95 of 50 and a malicious p95 of 50, showing zero separation.

The gap between the bottom 5th percentile of malicious scores and the top 95th percentile of benign scores is the operational separation. It answers the question: how much room is there to set a threshold that catches real threats without false-positive burden?

If the CRITICAL p5 is 60 and the benign p95 is 35, a threshold set inside the gap catches every CRITICAL-class sample in the benchmark set while labeling only 5% of benign packages as FLAGGED. The 25-point gap provides margin for error: moving the threshold within it trades false-positive rate against headroom while still catching all CRITICAL samples.

The gap is measured as p5 of the worst class (CRITICAL) versus p95 of the benign class because these are the tails that matter for threshold setting. The center of the distribution is irrelevant for operational decision-making.

## Per-class CI gates

The benchmark enforces three gates:

| Gate | Requirement | What it prevents |
|------|-------------|------------------|
| Malicious fixture coverage | Every labelled malicious fixture still detects what it is labelled for (skips known_gap) | A change that weakens detection of a labelled fixture is rejected. The committed corpus is 175 self-authored fixtures across historical, holdout, evasion, synthetic and campaign groups; `scripts/verify_fixtures.py` enforces record-to-diff completeness. This is not independently sampled recall. |
| Separation | benign p95 stays below malicious p5 (strict) | A change that narrows the gap (by reducing malicious scores or inflating benign scores) is rejected. |
| Benign fire rates | No scoring rule fires on >= 30% of benign diffs | Prevents weight inflation: a rule that becomes a census on benign packages is rejected. |
| Score-not-size + weight-zero annotations | \|Pearson(score, diff_lines)\| < 0.30; weight-0 rules move the score by exactly 0 | Prevents measuring activity instead of risk. |

A known-gaps gate additionally requires each `known_gap` fixture to *still*
fail its label, so closing a gap forces an explicit relabel.

### Why several gates and not one

A single gate (for example, "CRITICAL recall >= 100%") would allow weight inflation: making all rules fire harder would increase malicious scores but would also increase benign scores. The separation gate (benign p95 < malicious p5) prevents this by requiring the gap to stay positive. The fire-rate cap prevents any single rule from becoming a false-positive census on the benign corpus.

The gates together enforce three distinct properties: detection (no missed labelled attacks), separation (meaningful threshold gap), and baseline (low false-positive rate). Each gate independently blocks regressions in its dimension.

### Current numbers

Measured against the 3,739-diff locked corpus (a point-in-time snapshot; re-derive with `scripts/rebaseline.py` when scoring changes):

| Metric | Value | Benchmark target |
|--------|-------|------------------|
| Benign zero-rate | 68.3% | no minimum; fire-rate cap controls FPs |
| Ruleset trigger rate | 31.7% | benign diffs that fire at least one non-INFO rule |
| Benign flag rate | 13.1% | about **1 in 8** benign corpus diffs exceed the 20-point threshold |
| Labelled-fixture detection | 100% | 100% of labelled fixtures; not independent recall |
| CRITICAL p5 | 60 | > benign p95 |
| Benign p95 | 35 | < CRITICAL p5 (margin: 25) |
| Tests | Run `uv run pytest` for the current checkout | n/a |

The numbers are not aspirational; they are the measured state of the current rule set and scoring model on this corpus and fixture set. CI rejects gate regressions, not changes to an external performance claim.

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

Per-rule fire rates (false-positive rate of each rule on the benign corpus) are tracked separately in [Fire Rates](fire-rates.md). The 68.3% zero-rate means 68.3% of benign diffs score 0, while **13.1% exceed the 20-point threshold**: roughly one reviewer workload item per eight benign corpus diffs. A score of 0 and a clean fire record are not the same thing: the largest contributors to the remaining fires are R060 (Build Function Modified, INFO/weight 0, fires on 21.4% of diffs but never moves a score) and R010/R011 (curl/wget in PKGBUILD, LOW, fire on <2%).

## The methodology habit

1. Pool results, get suspicious. If pooled numbers look good, they are hiding a problem.
2. Split by class, find the truth. The real separation is in the tails, not the center.
3. Measure the gap, not the absolute. The gap between classes is the operational metric; absolute scores are meaningless in isolation.
4. Enforce per-stratum, not aggregate. Aggregate recall hides blind spots.

This methodology generalizes beyond TrustSight. Any security tool that claims a recall number should be asked: recall on what class, against what corpus, pinned at what version, and measured against which tail of the benign distribution?
