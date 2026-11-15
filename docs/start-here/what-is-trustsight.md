<!-- description: What TrustSight is, what it analyses, what it produces, and the boundaries that make its reports useful rather than authoritative. -->

# What is TrustSight?

**See beyond the package.**

TrustSight is a security analysis and intelligence platform for the Arch User
Repository ecosystem. It audits a `PKGBUILD` before you build it: it reads the
diff and the post-patch recipe, applies published detection rules, and reports
what changed, what matched, and what it could not see.

## What it analyses

- **The change.** A review compares the previous commit with the current one,
  so it can tell a version bump from a maintained package being quietly
  repointed.
- **The recipe as it will be read.** Variables, arrays, function boundaries
  and source URLs are resolved where static resolution allows. The analysis
  never executes the PKGBUILD.
- **Ecosystem signals.** Maintainer history, package age, adoption, release
  cadence, dependency relationships and cross-package correlation place the
  change in context.
- **Declared verification.** Checksums, PGP keys and pinning are reported, not
  credited. A declaration an attacker can assert for free must not lower a
  score.

## A platform, not only a diff check

TrustSight is a security analysis and intelligence platform for the Arch User
Repository ecosystem. It combines static analysis, supply-chain intelligence,
behavioral heuristics, dependency graph analysis, threat intelligence, and
historical correlation to uncover suspicious package updates and emerging
threats.

Beyond package analysis, TrustSight tracks ecosystem activity and lifecycle
signals, including maintainer histories and changes, package adoptions and
orphan status, ownership transitions, release patterns, and dependency
relationships. It uses these signals to identify unusual behavior, suspicious
takeovers, stale package revivals, and coordinated activity across packages.

It transforms package changes and ecosystem signals into deterministic,
evidence-linked security assessments, helping you understand what changed, who
is behind it, and what it might mean before you install.

## What a run produces

A review is a deterministic, evidence-linked report:

- **Findings**: a named rule with the file, side and line it matched, and a
  plain-English description.
- **A change summary**: what the update altered, including source and checksum
  moves, dependency additions and maintainer or version changes.
- **Coverage gaps**: what the run could not fully assess, stated outright so
  an incomplete analysis is never mistaken for a clean one.
- **A template verdict**: the findings rendered into a review direction. It
  describes what fired; it never grants permission to skip review.

The default output is evidence, not a verdict, and nothing it prints is a
promise of safety. The evidence is what you decide on. See
[How TrustSight Works](../security-design/how-it-works.md) for the full
pipeline and [Understanding Your First Report](understanding-your-first-report.md).

## What it is not

TrustSight is an **instrument, not a judge**. It reports evidence, and the
absence of evidence, and never substitutes its report for your decision.
Absence of alerts is not a promise of safety. It does not decide whether a
package is safe, and a quiet result is not a certificate: it means no
monitored condition matched in the material examined. The
[security model](../security-design/security-model.md) states the boundaries
behind that promise, and how each one is enforced.

The [security model](../security-design/security-model.md) states the
guarantees and their enforcement. The
[threat model](../security-design/threat-model.md) states the limits.

## Where to go next

1. [Install TrustSight](installation.md).
2. [Run your first review](quickstart.md).
3. [Understand the report](understanding-your-first-report.md).
4. Pick a workflow: [auditing before an update](../workflows/auditing-before-update.md),
   [gating yay and paru](../workflows/integrating-yay-and-paru.md), or
   [using TrustSight in CI](../workflows/using-in-ci.md).
