# How TrustSight Works

TrustSight is a deterministic AUR PKGBUILD audit tool. It computes a score from 0 to 100 over the **end-state** of a diff: the post-patch PKGBUILD, not the delta. Every decision is reproducible: same input always produces the same score and the same evidence record.

These explanation pages describe *why* the tool makes the decisions it does. If you are looking for how to use it, start with the getting-started guide. If you want the reference, see the reference section.

## The pipeline

The analysis runs in five sequential stages. Each stage has its own failure mode and its own integrity guarantee.

### 1. Parse

The PKGBUILD is a shell script with named variables, arrays, function calls, and conditional expressions. The parser resolves variable references in `source`, `sha256sums`, `pkgver`, `pkgrel`, and the `package()` function to produce a structured representation.

Resolution is partial by design. PKGBUILDs are not executed, so the parser can only resolve what is statically determinable:

- Simple variable references (`$pkgname`, `${pkgver}`) are resolved.
- Function calls (`pkgver() { ... }`) are parsed for structure but not executed.
- Conditional branches (`if [[ ... ]]`) are noted but not taken.
- Dynamically constructed strings (command substitution, arithmetic expansion) are marked as unresolvable.

When a critical field like `source` contains an unresolvable reference, the parser sets the diff's `source_resolution` to `"partial"` or `"unresolvable"`. This propagates through the pipeline and produces an `INCONCLUSIVE` verdict. The rationale: a package whose source URL cannot be determined statically cannot be audited with confidence. Reporting "could not verify" is more honest than guessing and potentially missing a swapped URL.

This is the same principle that drives the rest of the scoring system: **when the signal is uncertain, surface the uncertainty; do not hide it with a default.**

### 2. Analyze

The analysis stage extracts four categories of signal from the parsed PKGBUILD:

**Structural signals (Tier A)** come from rule matching. Two match targets exist because PKGBUILDs have two surfaces:

- **Resolved strings** are the post-resolution values of variables and function bodies. Rules matched against resolved strings (R001, R002, R003, R006, R008, R012) catch patterns that survive variable resolution. For example, `curl $url | bash` is detected in the resolved string after `$url` is expanded, not in the raw diff line where the actual URL is hidden behind a variable.
- **Raw diff lines** are the literal lines changed in the diff, with the `+`/`-` prefix stripped. Rules matched against raw lines (R004, R005, R007, R009, R010, R011, R013) catch patterns in the PKGBUILD text itself: a `sha256sums=('SKIP')` declaration, a `sudo` command, a unicode bidi override character.

Scope constraints further refine matching. Rules R009 (sudo), R010 (curl), and R011 (wget) are restricted to `function_body` context to avoid firing on top-level variable assignments or informational messages. This was a direct result of corpus analysis: these patterns in comments or messages were high-frequency false positives; actual malicious uses occur inside build functions.

**Context signals (Tier B)** classify every new source URL by domain. Classification is deterministic: a bundled domain list assigns each URL to a bucket (trusted_forge, official, self_hosted, raw_hosting, unknown, or homograph). No network calls are made at analysis time; the domain list is pre-computed from the corpus.

**History signals (Tier C)** compare new URLs and maintainers against the local database. A URL that has never been observed before in any package is globally novel; one never seen for this specific package is locally novel. Novelty is definitionally meaningless on first run, so its contribution is maturity-gated (see step 3).

**Verification signals (Tier D)** inspect the end-state PKGBUILD for cryptographic metadata: checksum arrays, PGP key declarations, and GPG verify calls. These are computed over the resolved end-state, not the diff delta, because what matters is the protection in place when the package is installed, not whether that protection was added or removed in this particular update.

### 3. Score

The score is a single integer from 0 to 100 computed from all signals. The calculation is purely additive and subtractive:

**Base score** = sum of severity weights of all fired rules, minus verification evidence, adjusted by source bucket modifiers and pinning discounts.

Each severity level carries a weight that reflects its information value:

| Severity | Weight | Meaning |
|----------|--------|---------|
| CRITICAL | 40 | Almost certainly malicious if triggered |
| HIGH | 25 | Strong signal |
| MEDIUM | 15 | Notable but not definitive |
| LOW | 5 | Weak signal; context-dependent |
| INFO | 0 | Recorded for audit only |

FATAL rules (R012, R013) short-circuit scoring. When a FATAL rule fires, the score is immediately set to 100 regardless of any other signals or subtractions. FATAL rules contribute 0 to the additive sum because their weight would be irrelevant; the hard stop at 100 is their entire effect.

**Verification evidence subtracts** from the base score:

| Evidence | Subtraction | Why |
|----------|-------------|-----|
| `checksum_present` | 5 | Integrity verification of the downloaded artifact |
| `validpgpkeys_declared` | 10 | Declared PGP key fingerprints narrow trust to specific signers |
| `gpg_verify_present` | 5 | Runtime signature verification |

Verification presence is risk mitigation, not risk evidence. A package with checksums is safer than one without, all else being equal. The naive design (which scored checksum-missing packages higher) was inverted; TrustSight fixes this by making verification subtractive.

**Source bucket modifiers** adjust for the trustworthiness of the domain:

| Bucket | Modifier | Rationale |
|--------|----------|-----------|
| `trusted_forge` | 5 | GitHub, GitLab, Codeberg provide platform integrity |
| `official` | 0 | Known upstream domains are neutral |
| `unknown` | +20 | Never-before-seen domain requires scrutiny |
| `homograph` | +30 | Visually confusable domain is high risk |

The trusted_forge discount is capped at a total of 20 across all URLs. This prevents a package with dozens of GitHub sources from accumulating an arbitrarily large discount.

**Novelty weights** add to the score when maturity allows:

| Signal | Full weight | Scaled by maturity |
|--------|-------------|-------------------|
| `url_first_globally` | 15 | x min(1, observations/50) |
| `url_first_in_package` | 10 | x min(1, observations/50) |
| `maintainer_first` | 20 | x min(1, observations/50) |

The maturity gate exists because novelty is meaningless in a cold database. On first run, every URL is first-seen, every maintainer is first-seen. Full-weight novelty from a cold DB would flag every package, producing zero information. The gate phases in novelty weight linearly as observations accumulate, reaching full weight at 50 observations.

**Pinning discounts** subtract for source pinning:

| Pinning | Discount |
|---------|----------|
| `checksum_pinned` | 5 |
| `tag_pinned` | 3 |

The final score is clamped to 0 to 100. A package with checksums, a trusted forge source, and no rule firings starts at 15 (5 for checksum + 10 for trusted forge) and will score 0 after the floor clamp.

### 4. Classify

The score maps to a verdict class:

| Score range | Verdict | Meaning |
|-------------|---------|---------|
| 0 to 20 | CLEAN | No actionable signals detected |
| 21+ | FLAGGED | Signals warrant review before updating |
| Variable | INCONCLUSIVE | Analysis could not complete; requires manual review |

The 20-point threshold is derived from corpus benchmarks. The benign p95 (95th percentile of benign package scores) is 20; the CRITICAL p5 (5th percentile of CRITICAL-class malicious packages) is 40. The 20-point gap between these two distributions is the operational separation: a threshold at 20 catches every CRITICAL-class threat in the benchmark set with zero false positives at the benign median.

INCONCLUSIVE is not a score range but a state triggered by unresolvable parsing, a cold database combined with Medium-range scores from novelty alone, or other conditions that prevent a confident classification. It signals that the tool cannot complete its analysis, not that the package is clean or dirty.

The INCONCLUSIVE logic checks whether all contributing signals are Tier C (novelty) and whether maturity is below 0.5 (fewer than approximately 25 observations). If so, novelty-driven Medium scores are downgraded to INCONCLUSIVE because the signal source is too weak to justify a FLAGGED verdict.

### 5. Translate

The LLM receives the score, evidence breakdown, and PKGBUILD context and produces a two-sentence English explanation. The key architectural property: **the LLM receives the score; it does not compute it, and it cannot change it.**

The separation of scoring from explanation is load-bearing:

- **Reproducibility and falsifiability**: two reviewers running the same package get the same score. Policy can gate on it. A CI pipeline can reject a PR based on the numeric score without ever calling an LLM.
- **No prompt-injection surface for the score**: an injected instruction in the PKGBUILD or verdict prompt cannot reach the scoring step. The score is already calculated before the LLM is called.
- **Deterministic auditing**: the numeric score is auditable, falsifiable, and permanent. Verdict text is ephemeral explanation.

Before the LLM verdict is displayed, it passes through verdict-integrity assertions:

| Check | What it catches |
|-------|-----------------|
| Minimum length | Empty or truncated responses |
| No score leakage | The numeric score must not appear in the verdict text. Prevents naive score extraction and embedding |
| FATAL content requirement | If FATAL rules fired, the verdict must mention them. Prevents downplaying a critical finding |
| Alarmist word suppression | Low-score packages (10 or below) must not be called "malicious" or "dangerous" |

If any assertion fails, the LLM output is discarded and a fallback template is used. The score and evidence record are preserved regardless.

The LLM is entirely optional. The score, evidence breakdown, and verdict classification are all computed before the LLM is called. A user who runs with `llm.enabled = false` or without a configured provider sees the same score and the same evidence record; only the English translation is missing.

## Key numbers

- **267 tests**, **81.5% zero-rate** on benign corpus, **100% CRITICAL recall** (12/12).
- **CRITICAL p5 = 40**, **benign p95 = 20**: the gap that matters.
- **R013 recall 88%**, **R012 recall 17%** (R012 is a tripwire; primary defence is verdict assertions).

## Start here

| Page | What it covers |
|------|----------------|
| [Trust Model](trust-model.md) | Why deterministic core + LLM-as-translator, not LLM-as-judge; verdict integrity |
| [Scoring Philosophy](scoring-philosophy.md) | Evidence tiers, verification subtraction, corpus-derived weights |
| [Rules Reference](../reference/rules.md) | Complete rule catalog with severity, weight, target, and scoring formula |
| [Cold Start and Maturity](cold-start-and-maturity.md) | Why novelty is meaningless on run one; maturity gating |
| [Corpus and Priors](corpus-and-priors.md) | AUR-wide snapshot, global priors, local novelty weighting |
| [What TrustSight Cannot See](what-trustsight-cannot-see.md) | The reasoned ceiling of the tool |
| [Benchmarks and Methodology](benchmarks-and-methodology.md) | Per-class separation, CI gates, reproducible eval |
