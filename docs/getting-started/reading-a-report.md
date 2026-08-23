# Reading a Report

A misread verdict is worse than no verdict. This page explains exactly what every part of a TrustSight report means : and what it does not.

---

## What a score is and is not

A **score** is a measurement of how many risk signals fired during analysis and how much those signals weigh. It is **not** a probability of malice, and it is **not** a guarantee of safety.

- A package scoring **0** has no detectable risk signals. That does not mean it is safe: only that nothing in the diff triggered a rule. Attackers can use subtle techniques that leave no trace in PKGBUILD structure. See [what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md).
- A package scoring **100** has one or more FATAL signals (R012 prompt injection, R013 unicode bidi override, or a confirmed IOC match) that hard-stop at maximum severity. The score floors at 0 and caps at 100.

The scoring is **deterministic**: same diff, same config, same database state → same score, every time.

---

## The three verdict states

### UNFLAGGED (score ≤ 20)

No significant risk signals. Routine version bumps with checksum updates, trusted forge sources, and unchanged build logic land here.

An UNFLAGGED verdict does not mean "safe." It means "no detectable risk signals in this diff."

**68.4 % of diffs score 0** (zero-rate) across the 3,246-diff benign corpus. At the 95th percentile benign packages score **35**; the CRITICAL-class corpus has a 5th percentile of **60** and a minimum of **40**. The calibration gates re-measure both distributions against the shipped configuration on every push and fail the build if they overlap (see [using TrustSight in CI](../guides/using-in-ci.md)). Run `uv run pytest` for the current test count.

The 20-point threshold is therefore **not** the benign 95th percentile: it sits at the 86.9th, so about **13 %** of benign diffs land above it. That is a deliberate consequence of [B10](../security.md#b10-positive-evidence-is-reported-never-credited), which stopped crediting declared verification; the separation that matters, benign p95 below malicious p5, is what the gate enforces.

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

The score is in the Medium range (21-50), maturity is below 0.5 (fewer than 25 effective observations), and no HIGH, CRITICAL, or FATAL finding fired. The tool is telling you that weak signals, including novelty, are not yet mature enough to support that band. Any coverage gap can also produce INCONCLUSIVE unless a HIGH-or-worse finding stands on its own.

INCONCLUSIVE is **not** UNFLAGGED. It is the tool saying "this might be fine, but I can't be sure yet." Treat it as a manual-review prompt.

The maturity gate scales novelty weights by the database-wide effective observation count divided by 50. At zero observations, novelty contributes zero weight. At 49, it contributes ~98 %. After 50, all novelty signals are at full weight. A signed seed can supply the bootstrap count, and analyses of any packages increase the same global history. See [cold start and maturity](../explanation/cold-start-and-maturity.md).

---

## Evidence tiers

The score breakdown in `trustsight inspect` groups signals into four evidence tiers. Each tier represents a fundamentally different kind of information:

### Tier A : Structural (R/C/D/S/X rules)

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

Rules span the R-series detection rules, C-series structural rules, D-series dependency rules, S-series sabotage rules, and X-series crossfire rules. The complete inventory, including reserved gaps and declared-practice P-series findings, is maintained in the [rules reference](../reference/rules/index.md).

### Tier B : Priors / Context (source bucket classification)

Every new source URL in the diff is classified from its host into a bucket. These are priors based on host/domain reputation:

| Bucket | Modifier | Examples |
|--------|----------|---------|
| Trusted forge | 0 | github.com, gitlab.com, codeberg.org, bitbucket.org |
| Official | 0 | python.org, kernel.org, nginx.org, archlinux.org |
| Raw hosting | +15 | raw.githubusercontent.com, pastebin.com, gist.github.com |
| Unknown | +20 | Any domain not in the allowlist |
| Homograph attack | +30 | Visually confusable characters (githab.com with Cyrillic letters) |

A trusted forge adds nothing and subtracts nothing. It is reported separately as the declared-practice finding `P007`.

Tier B signals are weaker than Tier A. Classification uses static configured lists and a homograph check, not a corpus reputation model. An unknown domain alone does not prove malice : many legitimate projects use domains outside the lists.

### Tier C : History / Novelty (first-seen tracking)

Tracks whether URLs and maintainers have been seen before, both globally and per-package:

| Signal | Raw weight | Maturity scaling |
|--------|-----------|-----------------|
| URL first seen globally | +10 | × maturity multiplier |
| URL first seen in this package | +5 | × maturity multiplier |
| Maintainer first seen for this package | +15 | × maturity multiplier |

All novelty signals are **maturity-gated** by the database-wide effective observation count, not a package-specific history. A completely fresh database produces zero novelty weight. This prevents false-positive floods on a cold start.

### Tier D : Verification (declared, never scored)

When the statically visible post-diff PKGBUILD text declares structural integrity protections, they are reported as weight-0 findings in the `P` namespace. They do not move the score in either direction:

| Evidence | Finding | Weight |
|----------|---------|--------|
| checksums declared | `P001` | 0 |
| `validpgpkeys` declared | `P002` | 0 |
| signature source declared | `P003` | 0 |
| pinned to a commit / tag | `P005` / `P006` | 0 |
| source on a trusted forge over HTTPS | `P007` | 0 |
| source tracks a branch or unpinned ref | `P008` | 0 |

TrustSight never fetches, so it cannot confirm that a declared key signs anything or that a pinned commit holds what it claims, and adding any of these costs an attacker nothing. They are reported so *you* can check them, which is something you can do and the tool cannot. See [B10](../security.md#b10-positive-evidence-is-reported-never-credited).

Verification evidence is computed from the static post-diff text available to the analysis, not from database history or a fetched artifact. It records a declaration only; it does not establish that an unchanged checksum, key, signature, or pin is valid.

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
| `R004` | Rule identifier from the published R/C/D/S/X catalog; P001-P008 are declared-practice findings and W001-W006 are unverifiable findings; SOURCE_BUCKET, NOVELTY and COVERAGE are structural categories. |
| `Checksum Disabled` | Rule name. |
| `sha256sums=SKIP` | Match reason : the exact text or summary that triggered the rule. |

Declared-practice lines appear at weight 0, in their own group:

```
Declared verification
  P001  checksums declared for all non-VCS sources
  P002  validpgpkeys declared
  P007  source on a trusted forge over HTTPS
  P008  source tracks a branch or unpinned ref

  TrustSight does not verify these claims. It reports that the recipe makes them.
```

---

## What partial coverage looks like

When a `source=` entry is computed at build time, for example `_url="$(curl -sIL -o /dev/null -w '%{url_effective}' "$_redirect")"`, the URL the build will fetch is not in the text being analysed. TrustSight records this as the `unresolved_source` coverage gap and reports **INCONCLUSIVE** rather than an UNFLAGGED score. The same happens when the diff was truncated at the size cap, or when the repository tree was unavailable. This is intentional: the tool would rather tell you "I could not finish analyzing this" than silently give false confidence. See [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

Unresolved patterns are listed in the inspect output under "Unresolved Patterns." See [what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md) for the full list of analysis blind spots.

### W findings: a gap attached to a line

A coverage gap describes the whole run. The **W series** (`W001` to `W006`)
says the same thing about one line: this line runs something, and nothing has
read it.

```
  0  INFO  W001  Executes Code This Analysis Did Not Read
              build() runs "$srcdir/scripts/postunpack.sh", which is neither
              declared in source=() nor committed to this repository
```

W findings are weight 0 and never change the score, the risk band, or the
verdict. They are shown even so, unlike other weight-0 findings, because a
statement whose only value is to a reader is worthless if filtered. A W
finding is not evidence of wrongdoing: a recipe running a script from inside
a checksummed archive is following the packaging format. What it tells you is
where to look if you decide to look. The full series is in the
[unverifiable rules reference](../reference/rules/unverifiable.md).

---

## Putting it together: a worked example

```bash
trustsight inspect sketchy-package --score --risk
```

Output:

```
╭─────────────────── TrustSight Inspect: sketchy-package ────────────────────╮
│               Version  1.0-1 -> 1.1-2                                      │
│                 Lines  +12 -6                                              │
│              Checksum  changed_from_sha256_to_skip                         │
│                                                                            │
│          What changed                                                      │
│                          pkgver 1.0-1 -> 1.1-2                             │
│                          checksums changed from sha256 to SKIP             │
│                          source host added: sketchy-cdn.example.com        │
│                          build() runs npm install                          │
│                                                                            │
│ Declared verification                                                      │
│                          P001  checksums declared for all non-VCS sources  │
│                          P002  validpgpkeys declared                       │
│                          TrustSight does not verify these claims. It       │
│                        reports that the recipe makes them.                 │
│                                                                            │
│         Files changed                                                      │
│                          ~ PKGBUILD                                        │
│                                                                            │
│     Source URLs added                                                      │
│                          [unknown]                                         │
│                        https://sketchy-cdn.example.com/payload.tar.gz      │
│                                                                            │
│       Rules Triggered                                                      │
│                        R004 +25 HIGH Checksum Disabled:                    │
│                        sha256sums=('SKIP')                                 │
│                        SOURCE_BUCKET +20 MEDIUM Source URL classified as   │
│                        unknown                                             │
│                        (https://sketchy-cdn.example.com/payload.tar.gz)    │
│                        NOVELTY +8 HIGH Source URL first seen globally      │
│                        (maturity 0.80)                                     │
│                                                                            │
│    Unverifiable findings                                                   │
│                        W001  Executes Code This Analysis Did Not Read      │
│                              build() runs "$srcdir/scripts/postunpack.sh"  │
│                        W002  Build Resolves Dependencies From A Registry   │
│                              npm install in build()                        │
│                                                                            │
│                 Score  53/100  (High)                                      │
│                        sum: +53, clamped to 53/100                         │
│                                                                            │
│                Status  The update is not trivial. Review it.               │
╰────────────────────────────────────────────────────────────────────────────╯
```

**Interpretation**: The total is 25 + 20 + 8 = **53**, and the panel shows the
arithmetic under the score rather than asking you to trust it. The checksum was disabled (Tier A, strong signal) without justification. The new source URL uses an unknown host (Tier B, moderate) and the exact URL has not been observed before (Tier C, weighted at 80 %). The recipe also declares checksums and PGP keys, reported as `P001` and `P002` at weight 0: they do not reduce the 53, because anyone can write those lines. Two `W` findings are shown because the analysis could not read everything the build will run: a script invoked from inside the source tree (`W001`) and `npm install` resolving dependencies from a registry (`W002`). They do not change the score; they mark boundaries you may want to look past. The verdict is FLAGGED at High severity. This package warrants manual inspection before update.

The weights and severities above appear because this run passed `--score` and
`--risk`. Without them the same panel shows the findings and the verdict and no
band at all.

---

## Next steps

- [Guides: real workflows](../guides/index.md): CI integration, batch review, alert thresholds.
- [Explanation: what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md): analysis blind spots.
- [Explanation: cold start and maturity](../explanation/cold-start-and-maturity.md): how the novelty gate works.
- [Reference: rule catalog](../reference/rules/index.md): every rule with patterns and examples.
- [Reference: report schema](../reference/report-schema.md): score formula and evidence structure.
