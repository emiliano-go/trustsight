<!-- description: Rules reading the package's position in the corpus, or its deviation from a corpus baseline. Silent without prior observations; run once per metadata cycle. -->

# Corpus Behavioral

## Overview


The package's position in the corpus, or its deviation from a corpus
baseline. H046, H057, H060, H061, and H073 are Class D rules that run once
per metadata cycle in `trustsight full-aur`.

They are silent without a prior snapshot, which is enforced rather than
assumed: the calibration gate is `fire_rate(no_baseline) == 0`. H061 and
H057/H060 are prioritisation rather than accusation; they say what a
compromise would reach, not that anything is wrong.

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---

## Threat context

You know a friend has been replaced by an impostor not because they did
anything obviously wrong, but because they **do not sound like themselves**. A
teacher catches a ghostwritten essay the same way: the voice is subtly off. The
corpus-behavioral rules work on that instinct. Most rules ask "is this pattern
dangerous?"; these ask "does this package behave like the thousands of benign
packages we have seen?" The model is trained on the benign corpus, so what it
flags is **novelty** - the package that does not look like its peers, whether
or not any human named the pattern.

This is the learned layer of TrustSight, and its limits are the corpus's
limits: it can only know normal from the examples in the priors, so a
rare-but-legitimate build can read as novel. It is deliberately a
*mild-signal* contributor that raises suspicion for named rules to
corroborate.

## Detection mechanisms

The rules that make up this category are listed below, each with the series that implements it and the severity it carries. Scoring, matching and identifier allocation are shared across every category: see [Rule Mechanics](mechanics.md).

## Individual rules

<!-- generated: page-index -->
| Rule | Name | Severity |
|---|---|---|
| [H028](#h028) | Accelerated Release Cadence | - |
| [H046](#h046) | Orphan/Adoption Dependency | MEDIUM |
| [H057](#h057) | Transitive Exposure | INFO |
| [H060](#h060) | Transitive Orphan Risk | INFO |
| [H061](#h061) | Dependency Centrality | INFO |
| [H073](#h073) | Introduction Rate Deviation | MEDIUM |
<!-- /generated: page-index -->

### H028: Accelerated Release Cadence {#h028}

H028 is **metadata, never a scored finding**. The pipeline records whether the
HEAD commit has 3+ commits within 24 hours (counting HEAD itself) as the
`recent_commit_burst` boolean on `PackageFact`; it is not appended to
`triggered_rules` and contributes nothing to the score.

### H046: Orphan/Adoption Dependency {#h046}

- **Severity:** MEDIUM (weight 15)
- **Category:** `dependency`

- **Condition:** A package depends directly on a package orphaned or adopted in this cycle.

### H057: Transitive Exposure {#h057}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`

- **Condition:** A package's transitive closure, at least `[thresholds] h057.min_hops` (default 2) hops away, reaches a package adopted out of the orphan state this cycle. Context only, never additive.

### H060: Transitive Orphan Risk {#h060}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`

- **Condition:** A package's transitive closure includes a currently orphaned package. Context only, never additive.

### H061: Dependency Centrality {#h061}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`

- **Condition:** A package is depended on by at least `[thresholds] h061.min_dependents` (default 50) AUR packages. Prioritisation only: it says what a compromise would reach, not that anything is wrong.

### H073: Introduction Rate Deviation {#h073}

- **Severity:** MEDIUM (weight 15)
- **Category:** `adoption`

- **Condition:** The corpus-wide introduction rate for a cycle deviates from the baseline mean by at least `[thresholds] h073.z_score` (default 3.0), once at least `h073.min_history_cycles` (default 3) cycles of history exist. An immature history is quiet.

## Interpretation

- The finding says the package deviates from the benign corpus's behaviour,
  with the feature(s) driving it. It is not a named attack.
- A lone novelty finding is weak; novelty plus a concrete rule is the case
  where the corpus adds real value.
- If the priors were trained on a narrow slice, novelty findings will be
  noisy; this is a corpus-provenance question, not a package one.

## Related documentation

- [Corpus and Priors](../explanation/historical-and-behavioral-analysis.md)
- [Cold Start and Maturity](../explanation/scoring-and-verdicts.md)
