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

When a `source=` entry is computed at build time (a command substitution, not a variable the tokenizer can expand), the URL the build will actually fetch is not in the analysed text. The pipeline records this as the `unresolved_source` coverage gap, and a coverage gap forbids an UNFLAGGED verdict: the result is reported as `Inconclusive` unless a HIGH or worse finding already stands on its own. The rationale: a package whose source URL cannot be determined statically cannot be audited with confidence. Reporting "could not verify" is more honest than guessing and potentially missing a swapped URL. See [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete) for the other gaps and how they are enforced.

This is the same principle that drives the rest of the scoring system: **when the signal is uncertain, surface the uncertainty; do not hide it with a default.**

### 2. Analyze

The analysis stage extracts four categories of signal from the parsed PKGBUILD:

**Structural signals (Tier A)** come from rule matching. Two match targets exist because PKGBUILDs have two surfaces:

- **Resolved strings** are the post-resolution values of variables and function bodies. Rules matched against resolved strings (R001, R002, R003, R008, R012) catch patterns that survive variable resolution. For example, `curl $url | bash` is detected in the resolved string after `$url` is expanded, not in the raw diff line where the actual URL is hidden behind a variable.
- **Raw diff lines** are the literal lines changed in the diff, with the `+`/`-` prefix stripped. Rules matched against raw lines (R004, R005, R007, R009, R010, R011, R013) catch patterns in the PKGBUILD text itself: a `sha256sums=('SKIP')` declaration, a `sudo` command, a unicode bidi override character.

Scope constraints further refine matching. R010 (curl) and R011 (wget) are restricted to `function_body` context to avoid firing on top-level variable assignments or informational messages. This was a direct result of corpus analysis: these patterns in comments or messages were high-frequency false positives, while the uses worth reporting occur inside build functions. R009 (sudo) was later moved out of the TOML ruleset entirely, because "inside a function body" still admitted `optdepends` names and `echo` strings; it is now a code rule that requires `sudo` at a command position.

The top-level position is not ignored, it is a separate claim: [R129](../reference/rules/fetch-and-execution.md#r129) reports a network client invoked outside every function, because that line runs when makepkg merely sources the recipe rather than when it builds.

**Context signals (Tier B)** classify every new source URL by domain. Classification is deterministic: static configured lists and the homograph check assign each URL to `trusted_forge`, `official`, `raw_hosting`, `unknown`, or `homograph_attack`. There is no `self_hosted` bucket or corpus-frequency classifier. No network calls are made at analysis time.

**History signals (Tier C)** compare new URLs and maintainers against the local database. A URL that has never been observed before in any package is globally novel; one never seen for this specific package is locally novel. Novelty is definitionally meaningless on first run, so its contribution is maturity-gated (see step 3).

**Verification signals (Tier D)** inspect the statically visible post-diff PKGBUILD text for cryptographic metadata: checksum arrays, PGP key declarations, and GPG verify calls. They are declarations, not database-backed or remote verification: TrustSight does not establish that the declared protection is valid.

### 3. Score

The score is a single integer from 0 to 100 computed from all signals. The
calculation is **purely additive**: nothing lowers a score.

**Base score** = sum of severity weights of all fired rules, plus source bucket
modifiers, plus novelty weights scaled by maturity.

Each severity level carries a weight that reflects its information value:

| Severity | Weight | Meaning |
|----------|--------|---------|
| CRITICAL | 40 | Almost certainly malicious if triggered |
| HIGH | 25 | Strong signal |
| MEDIUM | 15 | Notable but not definitive |
| LOW | 5 | Weak signal; context-dependent |
| INFO | 0 | Recorded for audit only |

FATAL rules (R012, R013) short-circuit scoring. When a FATAL rule fires, the
score is immediately set to 100 regardless of any other signal. FATAL rules
contribute 0 to the additive sum because their weight would be irrelevant; the
hard stop at 100 is their entire effect.

**Declared verification is reported, never credited.** Checksums, PGP keys, GPG
verification and source pinning are emitted as weight-0 findings in the `P`
namespace and shown to the reader:

| Evidence | Finding | Weight |
|----------|---------|--------|
| checksums declared | `P001` | 0 |
| `validpgpkeys` declared | `P002` | 0 |
| signature source declared | `P003` | 0 |
| pinned to a commit | `P005` | 0 |
| pinned to a tag | `P006` | 0 |
| trusted-forge source | `P007` | 0 |

Earlier versions subtracted for these. They no longer do. Everything TrustSight
sees is attacker-declared, and TrustSight never fetches, so it never confirms
that a declared key signs anything or that a pinned commit holds what it claims.
Adding `validpgpkeys=(...)` costs an attacker nothing, so a credit for it is a
mechanism whose only reliable effect is buying points back for whoever reads the
rules. The reader can check these claims in ways the tool cannot, which is why
they are still reported. See
[B10](../security.md#b10-positive-evidence-is-reported-never-credited).

The calibration problem the subtractions solved, a package doing GPG
verification scoring *worse* than one doing nothing because a `SKIP` on a `.asc`
file added points, is fixed at source instead: R004 does not fire on a `SKIP`
that is mandatory, structurally uncheckable, or covered by declared PGP keys.

**Source bucket modifiers** adjust for the trustworthiness of the domain:

| Bucket | Modifier | Rationale |
|--------|----------|-----------|
| `trusted_forge` | 0 | A forge is neutral: reported as `P007`, never credited |
| `official` | 0 | Known upstream domains are neutral |
| `unknown` | +20 | Never-before-seen domain requires scrutiny |
| `homograph` | +30 | Visually confusable domain is high risk |

**Novelty weights** add to the score when maturity allows:

| Signal | Full weight | Scaled by maturity |
|--------|-------------|-------------------|
| `url_first_globally` | 10 | x min(1, observations/50) |
| `url_first_in_package` | 5 | x min(1, observations/50) |
| `maintainer_first` | 15 | x min(1, observations/50) |

The maturity gate exists because novelty is meaningless in a cold database. On
first run, every URL is first-seen, every maintainer is first-seen. Full-weight
novelty from a cold DB would flag every package, producing zero information. The
gate phases in novelty weight linearly as observations accumulate, reaching full
weight at 50 observations.

The final score is clamped to 0 to 100. A package with checksums, a trusted
forge source and no rule firings scores 0, and its three declared practices are
reported beside that 0 rather than folded into it.

### 4. Classify

The score maps to a verdict class:

| Score range | Verdict | Meaning |
|-------------|---------|---------|
| 0 to 20 | UNFLAGGED | No actionable signals detected, and the analysis was complete |
| 21+ | FLAGGED | Signals warrant review before updating |
| Any | INCONCLUSIVE | A cold database, or an analysis that could not examine the whole change; requires manual review |

The 20-point threshold is calibrated against corpus benchmarks. The benign p95 (95th percentile of benign package scores) is 35; the CRITICAL p5 (5th percentile of CRITICAL-class malicious packages) is 60. The 25-point gap between these two distributions is the operational separation, and the published threshold stays at 20: moving it is a calibration decision with its own evidence, not a bookkeeping fix.

INCONCLUSIVE is not a score range but a state. It signals that the tool could not complete its analysis, not that the package is clean or dirty, and it is produced in exactly two situations:

1. **Cold database.** The score is in the Medium band (21 to 50), maturity is below 0.5 (fewer than 25 recorded analyses; novelty reaches full weight at 50), and no HIGH, CRITICAL or FATAL finding fired. Novelty is the only thing holding the score up, and novelty is not trustworthy on a cold database.
2. **Incomplete coverage.** The run recorded any coverage gap: `diff_truncated`, `scan_truncated`, `line_truncated`, `tree_not_analyzed`, `unresolved_source`, `unresolved_parse_time`, `snapshot_refused`, `unpinned_build_deps`, or `deps_not_scanned`. When a HIGH or worse *did* fire, the band survives but is shown qualified, as `High (incomplete analysis)`.

In both cases a HIGH, CRITICAL or FATAL finding keeps its own band: an analysis that found something does not get to hide it behind "inconclusive".

### 5. Translate

The score, evidence breakdown, and verification metadata are rendered into a structured report. All output is deterministic and generated locally from the computed data.

## Key numbers

- The current test suite, **68.3% zero-rate** on the 3,739-diff locked corpus, and **100% malicious recall** (all labelled fixtures).
- **CRITICAL p5 = 60**, **benign p95 = 35**: the gap that matters.
- Enabling the full R039 to R059 set costs **0.5 percentage points** of zero-rate and leaves p95 unchanged; 14 of 21 fire on zero benign diffs.
- **R013 recall 88%**, **R012 recall 17%** (R012 is a tripwire).

## Start here

| Page | What it covers |
|------|----------------|
| [Security Model](../security.md) | Why the score is deterministic and reproducible; the security model |
| [Scoring Philosophy](scoring-philosophy.md) | Evidence tiers, why verification is declared rather than scored, corpus-derived weights |
| [Rules Reference](../reference/rules/index.md) | Complete rule catalog with severity, weight, target, and scoring formula |
| [Cold Start and Maturity](cold-start-and-maturity.md) | Why novelty is meaningless on run one; maturity gating |
| [Corpus and Priors](corpus-and-priors.md) | AUR-wide snapshot, global priors, local novelty weighting |
| [Fire Rates](fire-rates.md) | Per-rule false-positive rates on the benign corpus and the 30 % gate |
| [What TrustSight Cannot See](what-trustsight-cannot-see.md) | The reasoned ceiling of the tool |
| [Seed Provenance](seed-provenance.md) | How the novelty seed is built, signed on the release channel, and audited |
| [Benchmarks and Methodology](benchmarks-and-methodology.md) | Per-class separation, CI gates, reproducible eval |
| [Sandboxing the Tokenizer](sandboxing-the-tokenizer.md) | Why the tokenizer is the component worth isolating, and the conditions for doing it |
