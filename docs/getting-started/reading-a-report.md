# Reading a Report

A misread verdict is worse than no verdict. This page explains exactly what every part of a TrustSight report means : and what it does not.

---

## What a score is and is not

A **score** is a measurement of how many risk signals fired during analysis and how much those signals weigh. It is **not** a probability of malice, and it is **not** a guarantee of safety.

- A package scoring **0** has no detectable risk signals. That does not mean it is safe: only that nothing in the diff triggered a rule. Attackers can use subtle techniques that leave no trace in PKGBUILD structure. See [what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md).
- A package scoring **100** has one or more FATAL signals (R012 prompt injection or R013 unicode bidi override) that hard-stop at maximum severity. The score floors at 0 and caps at 100.

The scoring is **deterministic**: same diff, same config, same database state → same score, every time.

---

## The three verdict states

### CLEAN (score ≤ 20)

No significant risk signals. Routine version bumps with checksum updates, trusted forge sources, and unchanged build logic land here.

A CLEAN verdict does not mean "safe." It means "no detectable risk signals in this diff."

**81.5 % of diffs score 0** (zero-rate). At the 95th percentile, benign packages score **20**: exactly the CLEAN boundary. At the 5th percentile, CRITICAL-classified packages score **40**. The boundary is calibrated to separate these distributions. The test suite covers **267 tests** across all modules.

### FLAGGED (score > 20)

One or more risk signals fired. The severity category (Medium / High / Critical) tells you the strongest signal's tier:

| Range | Label | Interpretation |
|-------|-------|----------------|
| 21-50 | Medium | Novelty, unknown domains, or single moderate signals |
| 51-80 | High | Multiple signals or strong structural changes |
| 81-100 | Critical | Strong evidence, or FATAL rules (R012/R013) |

#### How to use FLAGGED

- Score 21-34: inspect with `trustsight inspect <name>` to understand context.
- Score 35-50: manual review recommended before `yay -Syu`.
- Score 51+: treat as suspicious. Investigate fully before updating.
- Score 100: a FATAL rule fired. **Do not install** without understanding why.

### INCONCLUSIVE

The score is in the Medium range (21-50), but **every contributing signal came from novelty** and the **observation database is cold** (shallower than 50 prior runs). The tool is telling you it does not have enough data.

INCONCLUSIVE is **not** CLEAN. It is the tool saying "this might be fine, but I can't be sure yet." Treat it as a manual-review prompt.

The maturity gate scales novelty weights by `observation_count / 50`. At zero observations, novelty contributes zero weight. At 49, it contributes ~98 %. After 50, all novelty signals are at full weight. See [cold start and maturity](../explanation/cold-start-and-maturity.md).

---

## Evidence tiers

The score breakdown in `trustsight inspect` groups signals into four evidence tiers. Each tier represents a fundamentally different kind of information:

### Tier A : Structural (rules R001-R013 + R039-R059 + C001-C007)

Pattern-matched from the PKGBUILD diff. These are direct, observable facts about what the build script does:

- `curl ... | bash` (R001, CRITICAL)
- checksum set to `SKIP` (R004, HIGH or INFO)
- `sudo` inside a function body (R009, CRITICAL)
- unicode bidi override characters (R013, FATAL)

Tier A signals are the strongest evidence. CRITICAL recall is **100 %**: every CRITICAL-class sample in the benchmark corpus is detected.

**Rule recall for FATAL rules:**

| Rule | Recall | Notes |
|------|--------|-------|
| R013 (unicode bidi override) | **88 %** | Detects invisible reordering characters that alter perceived source code |
| R012 (prompt injection) | **17 %** | Tripwire rule : catches obvious injection patterns but not subtle variants |

R012's low recall is intentional. It is a tripwire: when it fires, you know something is almost certainly malicious. When it does not, nothing can be concluded. Attackers have too many ways to rephrase injection payloads.

Rules span **R001-R013** and **R039-R059** (detection rules) and **C001-C007** (context rules for checksum and source-integrity heuristics). C-rules range from INFO to CRITICAL severity depending on the specific finding.

### Tier B : Priors / Context (source bucket classification)

Every new source URL in the diff is classified into a domain bucket. These are priors based on domain reputation:

| Bucket | Modifier | Examples |
|--------|----------|---------|
| Trusted forge | -10 | github.com, gitlab.com, codeberg.org, bitbucket.org |
| Official | 0 | python.org, kernel.org, nginx.org, archlinux.org |
| Self-hosted | +10 | Custom domains under the maintainer's control |
| Raw hosting | +15 | raw.githubusercontent.com, pastebin.com, gist.github.com |
| Unknown | +20 | Any domain not in the allowlist |
| Homograph attack | +30 | Visually confusable characters (githab.com with Cyrillic letters) |

The trusted forge modifier is capped at -20 total across all URLs.

Tier B signals are weaker than Tier A. An unknown domain alone does not prove malice : many legitimate projects self-host.

### Tier C : History / Novelty (first-seen tracking)

Tracks whether URLs and maintainers have been seen before, both globally and per-package:

| Signal | Raw weight | Maturity scaling |
|--------|-----------|-----------------|
| URL first seen globally | +10 | × maturity multiplier |
| URL first seen in this package | +5 | × maturity multiplier |
| Maintainer first seen for this package | +15 | × maturity multiplier |

All novelty signals are **maturity-gated** by the number of prior observations of this package. A completely fresh database produces zero novelty weight. This prevents false-positive floods on first run.

### Tier D : Verification (evidence that subtracts from score)

When the post-diff PKGBUILD contains structural integrity protections, they reduce the score. These are **subtractions**: they can never increase the score:

| Evidence | Modifier |
|----------|----------|
| checksum_present | -10 |
| validpgpkeys_declared | -10 |
| gpg_verify_present | -5 |

Verification evidence is computed over the resolved end-state of the PKGBUILD, not over the diff delta. A checksum that was already present and unchanged still counts.

---

## How to read a breakdown line

Example from `trustsight inspect`:

```
+25 HIGH R004 Checksum Disabled: sha256sums=SKIP
```

Break this down left to right:

| Part | Meaning |
|------|---------|
| `+25` | Weight contributed to the total score. Positive = risk increase. Negative = risk decrease (verification, trusted forges). |
| `HIGH` | Severity tier. Determines the weight magnitude. Order: INFO (0) < LOW (5) < MEDIUM (15) < HIGH (25) < CRITICAL (40) < FATAL (hard-stop at 100). |
| `R004` | Rule identifier. R001-R013 are detection rules; C001-C003 are context rules; SOURCE_BUCKET, NOVELTY, PINNING, VERIFICATION are structural categories. |
| `Checksum Disabled` | Rule name. |
| `sha256sums=SKIP` | Match reason : the exact text or summary that triggered the rule. |

Verification evidence lines appear as negative weights:

```
 -10 INFO VERIFICATION Verification evidence: checksum_present (-10)
```

---

## What partial coverage looks like

When the tokenizer cannot resolve a variable : for example, a URL stored in `$_target` and constructed via string interpolation : the unresolved source produces an **INCONCLUSIVE** outcome rather than scoring 0. This is intentional: the tool would rather tell you "I could not finish analyzing this" than silently give false confidence.

Unresolved patterns are listed in the inspect output under "Unresolved Patterns." See [what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md) for the full list of analysis blind spots.

---

## Putting it together: a worked example

```bash
trustsight inspect sketchy-package
```

Output:

```
TrustSight Inspect: sketchy-package
  Version: 1.0 → 1.1
  Score: 55/100 (Medium)

  Diff Summary
  Files changed: PKGBUILD
  Lines: +12/-6

  Checksum behavior: changed_from_sha256_to_skip

  Source URLs Added
    https://sketchy-cdn.example.com/payload.tar.gz (unknown)

  Score Breakdown
  +25 HIGH   R004  Checksum Disabled: sha256sums=SKIP (no justification found)
  +20 MEDIUM SOURCE_BUCKET  Source URL classified as unknown
  +15 HIGH   NOVELTY  Source URL first seen globally (maturity=0.80)
  -10 INFO   VERIFICATION  Verification evidence: validpgpkeys_declared (-10)

  Verdict
  Checksum set to SKIP without VCS/signature justification. New download
  URL from sketchy-cdn.example.com : domain not seen before.
```

**Interpretation**: The total is 25 + 20 + 15 - 10 = **50**, floored to max with the R004 weight. The checksum was disabled (Tier A, strong signal) without justification. The new source URL comes from an unknown domain (Tier B, moderate) and has never been seen before (Tier C, moderate : maturity at 80 % so near full weight). There is PGP key evidence (Tier D, -10). The verdict is FLAGGED at Medium severity. This package warrants manual inspection before update.

---

## Next steps

- [Guides: real workflows](../guides/index.md): CI integration, batch review, alert thresholds.
- [Explanation: what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md): analysis blind spots.
- [Explanation: cold start and maturity](../explanation/cold-start-and-maturity.md): how the novelty gate works.
- [Reference: rule catalog](../reference/rules.md): every rule with patterns and examples.
- [Reference: report schema](../reference/report-schema.md): score formula and evidence structure.
