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

### UNFLAGGED (score ≤ 20)

No significant risk signals. Routine version bumps with checksum updates, trusted forge sources, and unchanged build logic land here.

An UNFLAGGED verdict does not mean "safe." It means "no detectable risk signals in this diff."

**69.1 % of diffs score 0** (zero-rate) across the 3,246-diff benign corpus. At the 95th percentile benign packages score **45**; the CRITICAL-class corpus has a 5th percentile of **60** and a minimum of **40**. The calibration gates re-measure both distributions against the shipped configuration on every push and fail the build if they overlap (see [using TrustSight in CI](../guides/using-in-ci.md)). The test suite covers **1,377 tests** across all modules.

The 20-point threshold is therefore **not** the benign 95th percentile: it sits at the 83.7th, so about **16 %** of benign diffs land above it. That is a deliberate consequence of [B10](../security.md#b10-positive-evidence-is-reported-never-credited), which stopped crediting declared verification; the separation that matters, benign p95 below malicious p5, is what the gate enforces.

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

INCONCLUSIVE is **not** UNFLAGGED. It is the tool saying "this might be fine, but I can't be sure yet." Treat it as a manual-review prompt.

The maturity gate scales novelty weights by `observation_count / 50`. At zero observations, novelty contributes zero weight. At 49, it contributes ~98 %. After 50, all novelty signals are at full weight. See [cold start and maturity](../explanation/cold-start-and-maturity.md).

---

## Evidence tiers

The score breakdown in `trustsight inspect` groups signals into four evidence tiers. Each tier represents a fundamentally different kind of information:

### Tier A : Structural (rules R001-R131 + C001-C007)

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

Rules span **R001-R131** (detection rules) and **C001-C007** (context rules for checksum and source-integrity heuristics). C-rules range from INFO to CRITICAL severity depending on the specific finding.

### Tier B : Priors / Context (source bucket classification)

Every new source URL in the diff is classified into a domain bucket. These are priors based on domain reputation:

| Bucket | Modifier | Examples |
|--------|----------|---------|
| Trusted forge | 0 | github.com, gitlab.com, codeberg.org, bitbucket.org |
| Official | 0 | python.org, kernel.org, nginx.org, archlinux.org |
| Self-hosted | +10 | Custom domains under the maintainer's control |
| Raw hosting | +15 | raw.githubusercontent.com, pastebin.com, gist.github.com |
| Unknown | +20 | Any domain not in the allowlist |
| Homograph attack | +30 | Visually confusable characters (githab.com with Cyrillic letters) |

A trusted forge adds nothing and subtracts nothing. It is reported separately as the declared-practice finding `P007`.

Tier B signals are weaker than Tier A. An unknown domain alone does not prove malice : many legitimate projects self-host.

### Tier C : History / Novelty (first-seen tracking)

Tracks whether URLs and maintainers have been seen before, both globally and per-package:

| Signal | Raw weight | Maturity scaling |
|--------|-----------|-----------------|
| URL first seen globally | +10 | × maturity multiplier |
| URL first seen in this package | +5 | × maturity multiplier |
| Maintainer first seen for this package | +15 | × maturity multiplier |

All novelty signals are **maturity-gated** by the number of prior observations of this package. A completely fresh database produces zero novelty weight. This prevents false-positive floods on first run.

### Tier D : Verification (declared, never scored)

When the post-diff PKGBUILD declares structural integrity protections, they are reported as weight-0 findings in the `P` namespace. They do not move the score in either direction:

| Evidence | Finding | Weight |
|----------|---------|--------|
| checksums declared | `P001` | 0 |
| `validpgpkeys` declared | `P002` | 0 |
| signature source declared | `P003` | 0 |
| pinned to a commit / tag | `P005` / `P006` | 0 |

TrustSight never fetches, so it cannot confirm that a declared key signs anything or that a pinned commit holds what it claims, and adding any of these costs an attacker nothing. They are reported so *you* can check them, which is something you can do and the tool cannot. See [B10](../security.md#b10-positive-evidence-is-reported-never-credited).

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
| `+25` | Weight contributed to the total score. Never negative: nothing lowers a score. `0` marks an annotation, a coverage gap, or a declared-practice `P` finding. |
| `HIGH` | Severity tier. Determines the weight magnitude. Order: INFO (0) < LOW (5) < MEDIUM (15) < HIGH (25) < CRITICAL (40) < FATAL (hard-stop at 100). |
| `R004` | Rule identifier. R001-R131 are detection rules; C001-C007 are context rules; P001-P007 are declared-practice findings; SOURCE_BUCKET, NOVELTY and COVERAGE are structural categories. |
| `Checksum Disabled` | Rule name. |
| `sha256sums=SKIP` | Match reason : the exact text or summary that triggered the rule. |

Declared-practice lines appear at weight 0, in their own group:

```
Declared verification
  P001  checksums declared for all non-VCS sources
  P002  validpgpkeys declared

  TrustSight does not verify these claims. It reports that the recipe makes them.
```

---

## What partial coverage looks like

When a `source=` entry is computed at build time, for example `_url="$(curl -sIL -o /dev/null -w '%{url_effective}' "$_redirect")"`, the URL the build will fetch is not in the text being analysed. TrustSight records this as the `unresolved_source` coverage gap and reports **INCONCLUSIVE** rather than an UNFLAGGED score. The same happens when the diff was truncated at the size cap, or when the repository tree was unavailable. This is intentional: the tool would rather tell you "I could not finish analyzing this" than silently give false confidence. See [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

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
    0 INFO   P002  validpgpkeys declared

  Verdict
  Checksum set to SKIP without VCS/signature justification. New download
  URL from sketchy-cdn.example.com : domain not seen before.
```

**Interpretation**: The total is 25 + 20 + 15 = **60**. The checksum was disabled (Tier A, strong signal) without justification. The new source URL comes from an unknown domain (Tier B, moderate) and has never been seen before (Tier C, moderate : maturity at 80 % so near full weight). The recipe also declares PGP keys, reported as `P002` at weight 0: it does not reduce the 60, because anyone can write a `validpgpkeys` line. The verdict is FLAGGED at High severity. This package warrants manual inspection before update.

---

## Next steps

- [Guides: real workflows](../guides/index.md): CI integration, batch review, alert thresholds.
- [Explanation: what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md): analysis blind spots.
- [Explanation: cold start and maturity](../explanation/cold-start-and-maturity.md): how the novelty gate works.
- [Reference: rule catalog](../reference/rules.md): every rule with patterns and examples.
- [Reference: report schema](../reference/report-schema.md): score formula and evidence structure.
