<!-- description: What a rule category is, how the closed RuleCategory set relates to capability fields and series, and where each category's threat context and definitions live. -->

# Rule Categories

A TrustSight rule makes one kind of claim. That claim is its **category** (the
`RuleCategory` value, sometimes called its subject). There is exactly one
category per rule, the set is closed, and each category owns exactly one
documentation page.

A category page does two jobs at once, because a reader needs both:

- it explains **where the idea comes from and what a finding means** (the
  threat context and interpretation); and
- it carries the **definition of every rule in the category**, with severity,
  target, scope and limitations.

Those halves used to live on separate System and Nature pages. They are now one
canonical page per category, so there is no parallel navigation to keep in
step. The taxonomy itself is still defined in `src/trustsight/categories.py`;
`tests/test_docs.py` fails if a rule is documented on a page its category does
not own.

## Category is not capability, and not series

Three labels are easy to confuse:

- **Category** answers *what kind of claim does this rule make?* It decides
  which page owns the rule.
- **Capability** is the per-rule `category` field in `rules.toml`
  (`network_execution`, `installer`, `obfuscation`). It names what a match
  touched and is used by `H027` to count capability density.
- **Series** answers *how does the rule detect?* It is the leading letter of
  the rule ID. See [Rule Series](series.md).

A rule can carry `category = "meta"` as its capability and belong to the
Composition subject. The full side-by-side comparison is in
[Rule Labels Explained](interpretation.md).

## The categories

The generated table in [Rules Overview](index.md#categories) is the canonical
index. The pages themselves are:

### Code reaches the machine and runs

- [Fetch and Execution](fetch-and-execution.md): the classic fetch-then-run
  shape, and the security core of the ruleset.
- [Obfuscation](obfuscation.md): hiding what the recipe does from a reader.
- [Deception and Anti-Analysis](deception.md): tricks aimed at the reviewer,
  not the compiler.
- [Install and Persistence](install-and-persist.md): arranging to run again
  after the build.
- [Staging and Reconnaissance](staging-and-recon.md): reading the target before
  acting.
- [Sabotage](sabotage.md): a payload aimed at the operator's machine.
- [Crossfire](crossfire.md): the evasion technique itself, not the payload.

### Trust, identity and history

- [Integrity and Verification](integrity.md): defeating the checksum promise.
- [Naming and Dependencies](naming-and-dependency.md): name-clones and
  transitive trust.
- [Maintainer and Metadata](maintainer-and-metadata.md): account and recipe
  signals around the code.
- [Temporal Context](temporal.md): timing as evidence.
- [Corpus Behavioral](corpus-behavioral.md): deviation from the ecosystem
  baseline.
- [Upstream Manifests](upstream-manifests.md): committed dependency manifests.
- [Upstream Release Integrity](upstream-release.md): declared upstream and CI
  surfaces.

### Composition and cross-package signals

- [Composition](composition.md): chains that are only dangerous together.
- [Count-Based](count-based.md): thresholds over matched evidence.
- [Meta and Confluence](meta.md): claims about other findings.
- [Correlation](correlation.md): patterns across packages in a window.
- [Entropy](entropy.md): statistical abnormality of added content.

### Evidence outside the static diff

- [Artifact](artifact.md): what actually lands in the built package.
- [Indicators](indicator.md): concrete observables from signed data.
- [Unverifiable](unverifiable.md): claims TrustSight cannot check.

## How to use a category page

Each page follows the same order: an overview, the threat context, the
detection mechanisms, the individual rule definitions, the interpretation, and
related documentation. If you are triaging a finding, read the interpretation
section before the definition; the definition explains what matched, while the
interpretation explains what that match does and does not establish.
