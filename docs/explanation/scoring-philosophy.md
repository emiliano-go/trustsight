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
