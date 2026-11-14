<!-- description: Where each rule category comes from, what a finding means in the world, and how to read it. -->

# Rule Nature

Every rule category on the [Rule System tab](../rules/index.md) answers both
*how* its rules detect and *why the category exists at all*. This tab is the
second half: for each category, where the idea came from and what a finding
means once you have one. The two pages are paired by **subject**, not by
mechanism: a category's system page owns the mechanics and per-rule
definitions, and its Nature page owns the provenance and interpretation.

The [Rule Series page](../rules/nature.md) reads the other axis, by
mechanism (R, H, C, and the rest). Series cross-cut subjects: a temporal
finding can come from an H heuristic or a T history read, and an integrity
finding is an integrity finding whichever series produced it.

Two more labels are easy to mistake for a third subject axis. The evidence
**layer** (`L1`-`L8`, plus the optional `L9` artifact lane) groups findings by
the kind of evidence and is derived from the series with a small override
table; it is a report view, not an independent taxonomy, and the numbers are
not stages. L9 is the external-build lane and carries no `L1`-`L8` layer. The evidence **tier**
(`A`-`D`) describes how a signal is sourced for scoring. The
[Rule labels explained](../../explanation/rule-taxonomy.md) puts all of them side by
side.

Each page below opens with the rule IDs in its subject, so the series mix in a
category is visible without leaving the page.

## Categories

- [Fetch and Execution](fetch-and-execution.md); the classic fetch-then-run shape, the security core
- [Obfuscation](obfuscation.md); making the recipe unreadable, so the reviewer cannot read it
- [Deception and Anti-Analysis](deception.md); tricks aimed at the reviewer, not the compiler
- [Install and Persistence](install-and-persist.md); arranging to run again after the build
- [Staging and Reconnaissance](staging-and-recon.md); reading the target before acting
- [Integrity and Verification](integrity.md); defeating the checksum promise
- [Naming and Dependencies](naming-and-dependency.md); name-clones and transitive trust
- [Maintainer and Metadata](maintainer-and-metadata.md); the account and recipe signals around the code
- [Temporal Context](temporal.md); timing as evidence
- [Composition](composition.md); chains that are only dangerous together
- [Count-Based](count-based.md); thresholds over matched evidence
- [Corpus Behavioral](corpus-behavioral.md); deviation from what the ecosystem normally does
- [Crossfire](crossfire.md); a package attacking its own build environment
- [Sabotage](sabotage.md); tampering with the code that gets built
- [Unverifiable](unverifiable.md); claims TrustSight cannot check
- [Meta and Confluence](meta.md); the run's own health, and agreement across families
- [Entropy](entropy.md); randomness as a build-output signal
- [Correlation](correlation.md); the immune-import model of campaigns (the G-series)
- [Artifact](artifact.md); what actually lands in the package
- [Indicators](indicator.md); concrete observables from signed data
- [Upstream Manifests](upstream-manifests.md); declared source against what upstream published
- [Upstream Release Integrity](upstream-release.md); a declared upstream's build automation and unauditable source transports

## See also

- [Rule System tab](../rules/index.md); the catalog and mechanics
- [Rule Series (mechanism)](../rules/nature.md); the mechanism axis
- [Rule labels explained](../../explanation/rule-taxonomy.md); series, subject, layer and tier side by side
- [Assurance Layers](../../assurance-layers.md); how the categories combine into a verdict
