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

When a `source=` entry is computed at build time (a command substitution, not a variable the tokenizer can expand), the URL the build will actually fetch is not in the analysed text. The pipeline records this as the `unresolved_source` coverage gap, and a coverage gap forbids a clean verdict: the result is reported as `Inconclusive` unless a HIGH or worse finding already stands on its own. The rationale: a package whose source URL cannot be determined statically cannot be audited with confidence. Reporting "could not verify" is more honest than guessing and potentially missing a swapped URL. See [the security model](../security.md#b2-a-clean-verdict-is-never-issued-for-an-analysis-that-was-incomplete) for the other gaps and how they are enforced.

This is the same principle that drives the rest of the scoring system: **when the signal is uncertain, surface the uncertainty; do not hide it with a default.**

### 2. Analyze

The analysis stage extracts four categories of signal from the parsed PKGBUILD:

**Structural signals (Tier A)** come from rule matching. Two match targets exist because PKGBUILDs have two surfaces:

- **Resolved strings** are the post-resolution values of variables and function bodies. Rules matched against resolved strings (R001, R002, R003, R006, R008, R012) catch patterns that survive variable resolution. For example, `curl $url | bash` is detected in the resolved string after `$url` is expanded, not in the raw diff line where the actual URL is hidden behind a variable.
- **Raw diff lines** are the literal lines changed in the diff, with the `+`/`-` prefix stripped. Rules matched against raw lines (R004, R005, R007, R009, R010, R011, R013) catch patterns in the PKGBUILD text itself: a `sha256sums=('SKIP')` declaration, a `sudo` command, a unicode bidi override character.

Scope constraints further refine matching. R010 (curl) and R011 (wget) are restricted to `function_body` context to avoid firing on top-level variable assignments or informational messages. This was a direct result of corpus analysis: these patterns in comments or messages were high-frequency false positives, while the uses worth reporting occur inside build functions. R009 (sudo) was later moved out of the TOML ruleset entirely, because "inside a function body" still admitted `optdepends` names and `echo` strings; it is now a code rule that requires `sudo` at a command position.

The top-level position is not ignored, it is a separate claim: [R129](../reference/rules.md#r129) reports a network client invoked outside every function, because that line runs when makepkg merely sources the recipe rather than when it builds.

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
| `checksum_present` | −10 | Integrity verification of the downloaded artifact |
| `validpgpkeys_declared` | −10 | Declared PGP key fingerprints narrow trust to specific signers |
| `gpg_verify_present` | −5 | Runtime signature verification |

Verification presence is risk mitigation, not risk evidence. A package with checksums is safer than one without, all else being equal. The naive design (which scored checksum-missing packages higher) was inverted; TrustSight fixes this by making verification subtractive.

**Source bucket modifiers** adjust for the trustworthiness of the domain:

| Bucket | Modifier | Rationale |
|--------|----------|-----------|
| `trusted_forge` | −10 | GitHub, GitLab, Codeberg provide platform integrity |
| `official` | 0 | Known upstream domains are neutral |
| `unknown` | +20 | Never-before-seen domain requires scrutiny |
| `homograph` | +30 | Visually confusable domain is high risk |

The trusted_forge discount is capped at a total of 20 across all URLs. This prevents a package with dozens of GitHub sources from accumulating an arbitrarily large discount.

**Novelty weights** add to the score when maturity allows:

| Signal | Full weight | Scaled by maturity |
|--------|-------------|-------------------|
| `url_first_globally` | 10 | x min(1, observations/50) |
| `url_first_in_package` | 5 | x min(1, observations/50) |
| `maintainer_first` | 15 | x min(1, observations/50) |

The maturity gate exists because novelty is meaningless in a cold database. On first run, every URL is first-seen, every maintainer is first-seen. Full-weight novelty from a cold DB would flag every package, producing zero information. The gate phases in novelty weight linearly as observations accumulate, reaching full weight at 50 observations.

**Pinning discounts** subtract for source pinning:

| Pinning | Discount |
|---------|----------|
| `checksum_pinned` | −5 |
| `tag_pinned` | −3 |

The final score is clamped to 0 to 100. A package with checksums, a trusted forge source, and no rule firings starts at 15 (5 for checksum + 10 for trusted forge) and will score 0 after the floor clamp.

### 4. Classify

The score maps to a verdict class:

| Score range | Verdict | Meaning |
|-------------|---------|---------|
| 0 to 20 | CLEAN | No actionable signals detected, and the analysis was complete |
| 21+ | FLAGGED | Signals warrant review before updating |
| Any | INCONCLUSIVE | A cold database, or an analysis that could not examine the whole change; requires manual review |

The 20-point threshold is derived from corpus benchmarks. The benign p95 (95th percentile of benign package scores) is 20; the CRITICAL p5 (5th percentile of CRITICAL-class malicious packages) is 40. The 20-point gap between these two distributions is the operational separation: a threshold at 20 catches every CRITICAL-class threat in the benchmark set with zero false positives at the benign median.

INCONCLUSIVE is not a score range but a state. It signals that the tool could not complete its analysis, not that the package is clean or dirty, and it is produced in exactly two situations:

1. **Cold database.** The score is in the Medium band (21 to 50), maturity is below 0.5 (fewer than 25 recorded analyses; novelty reaches full weight at 50), and no HIGH, CRITICAL or FATAL finding fired. Novelty is the only thing holding the score up, and novelty is not trustworthy on a cold database.
2. **Incomplete coverage.** The run recorded a coverage gap (`diff_truncated`, `line_truncated`, `tree_not_analyzed` or `unresolved_source`) and no HIGH or worse finding fired. When a HIGH or worse *did* fire, the band survives but is shown qualified, as `High (incomplete analysis)`.

In both cases a HIGH, CRITICAL or FATAL finding keeps its own band: an analysis that found something does not get to hide it behind "inconclusive".

### 5. Translate

The score, evidence breakdown, and verification metadata are rendered into a structured report. All output is deterministic and generated locally from the computed data.

## Key numbers

- **689 tests**, **82.0% zero-rate** on a rebuilt 3,322-diff stratified benign corpus, **100% CRITICAL recall** (12/12).
- **CRITICAL p5 = 40**, **benign p95 = 25**: the gap that matters.
- Enabling the full R039 to R059 set costs **0.5 percentage points** of zero-rate and leaves p95 unchanged; 16 of 21 fire on zero benign diffs.
- **R013 recall 88%**, **R012 recall 17%** (R012 is a tripwire).

## Start here

| Page | What it covers |
|------|----------------|
| [Trust Model](trust-model.md) | Why the score is deterministic and reproducible; the trust model |
| [Scoring Philosophy](scoring-philosophy.md) | Evidence tiers, verification subtraction, corpus-derived weights |
| [Rules Reference](../reference/rules.md) | Complete rule catalog with severity, weight, target, and scoring formula |
| [Cold Start and Maturity](cold-start-and-maturity.md) | Why novelty is meaningless on run one; maturity gating |
| [Corpus and Priors](corpus-and-priors.md) | AUR-wide snapshot, global priors, local novelty weighting |
| [Fire Rates](fire-rates.md) | Per-rule false-positive rates on the benign corpus and the 30 % gate |
| [What TrustSight Cannot See](what-trustsight-cannot-see.md) | The reasoned ceiling of the tool |
| [Benchmarks and Methodology](benchmarks-and-methodology.md) | Per-class separation, CI gates, reproducible eval |
