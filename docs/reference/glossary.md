<!-- description: The TrustSight vocabulary: rule family, subject, evidence category, evidence tier, detection, coverage, boundary, and the report terms built on them. -->

# Glossary

One page for the labels TrustSight uses, each defined once and linked to the
page that explains it in full. Two axes are independent: a rule carries a
**family** (how it works) and a **subject** (what it looks for), and those
cross-cut. Its findings also carry an **evidence category** (what kind of
evidence the finding is), which is derived from the family with per-rule
overrides. An **evidence tier** is not a classification of the rule at all:
it describes how a scoring signal is sourced. See
[Rule labels explained](../explanation/rule-taxonomy.md) for all of them side
by side.

## How a rule is classified

**Anergic rule.** A shipped detection held at weight 0 because the second signal it needs has not arrived. The rule still reports; the anergy ledger names the missing signal and the promotion evidence. See [Anergy](../standards.md#anergy-is-a-standing-state-not-a-silent-omission).

**Two-signal activation.** A detection scores only after both signals hold: the detection shape and the calibration evidence (corpus rate below the fire-rate cap plus a true-positive twin). The anergy ledger is the state between them.

**Tag convergence.** The weight-0 ledger entry emitted when a single diff carries N distinct tag kinds. Tags coat evidence for later detection; convergence says the coating is thick enough to look once.

**Tender point.** A persistent report-header note that a package has accumulated unresolved review verdicts over a window. It asks a human to look; it never claims damage.

**Finding.** One rule's report that it matched, with the file, side and line it
matched. A run produces a list of findings; the report groups and reads them.

**Benign false positive.** A rule hit on a genuine bad practice by the packager, where the package itself is not malicious. The finding is real; the practice is undesirable, and the fix belongs with the packager or in a documented known false positive. See [Standards](../standards.md#false-positive-vocabulary).

**Malicious false positive.** A bad rule trigger: the rule fired with no bad practice or malicious behaviour behind it. A misread option, an allowlist gap, or a counting or grouping error is a malicious false positive; the fix belongs in the detection shape and ships with the true-positive twin. See [Standards](../standards.md#false-positive-vocabulary).

**Rule family (series).** How a rule reaches its conclusion: a regex match
(`R`), a structural invariant over parsed documents (`C`), a graph walk (`D`),
a heuristic (`H`), an evasion or refusal check (`X`), a statistic (`E`), a
history read (`T`), a cross-package correlation (`G`), an indicator lookup
(`I`), a predicate over other findings (`M`), or an artifact inspection (`A`).
`P` reports declared practices and `W` reports analysis boundaries; neither is a
detection. Full list: [Rule Series](rules/nature.md).

**Subject (category).** What a rule looks for, as a closed set with one
reference page each (fetch and execution, obfuscation, integrity, and so on). A
rule belongs to exactly one subject. Full list: [Rules Overview](rules/index.md).

**Evidence category (layer).** The kind of evidence a finding represents, one
of `L1`-`L8`
([Part 1: Evidence Categories](../assurance-layers/evidence-categories.md)). A
finding is labelled by the check that produced it, not by every other check it
might complement.

**L9 (artifact lane).** The optional build lane that inspects an externally
built package manifest instead of the diff (`trustsight verify-build
--manifest`), reporting artifact rules `A001`-`A008`. It is off by default,
carries no `L1`-`L8` layer, and never changes the static score. With no
manifest it reports `l9_unavailable`; a disagreement with the static analysis
adds `l9_divergence`. See [Artifact](rules/artifact.md).

**Evidence tier.** How much external data a scoring signal needs before it
means anything: `A` (structural, always available), `B` (priors, static lists),
`C` (history, needs a warm corpus), `D` (declared verification, reported never
weighted). It describes sourcing and scoring, not a property every rule is
filed under. Tiers are orthogonal to layers: a finding has both a tier (how it
is sourced) and a layer (what kind of evidence it is). See
[Evidence Tiers](evidence-tiers.md) and
[Scoring Philosophy](../explanation/scoring-philosophy.md).

**Shared dependencies.** The infrastructure a rule relies on: the tokenizer,
parser, history database, corpus, or indicator baseline. Two rules with
different families can share one dependency, so a single input-handling failure
can blind both. Recorded in
[`trustsight.detectors`](../assurance-layers/enforcement.md).

## How a run is reported

**Detection.** Whether a finding in a category was produced: `fired` or `none`.

**Coverage.** Whether a category could be assessed at all: `complete`,
`incomplete` (a truncated diff, an unresolvable value, a partial file), or
`not_applicable` (the analysis mode cannot exercise it, as `L8` in a
single-package review). Detection and coverage are independent: a category can
fire *and* be incompletely read. See
[Part 3: Reporting](../assurance-layers/reporting.md).

**Boundary.** One object per shortfall that forbids a clean verdict, carrying
`forbids_clean`. A boundary is the same shortfall as an `incomplete` coverage,
seen from the verdict's side. See
[the security model](../security/what-a-result-claims.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

**Verdict.** The findings rendered into a review direction, naming the fired
evidence categories. It describes what fired; it never grants permission to skip
review.

**Score and risk band.** A deterministic weight summary of the fired findings,
available on request (`--score`), never volunteered, and never a probability of
safety. See [How TrustSight Works](../explanation/index.md).

## See Also

- [Assurance Layers](../assurance-layers.md) - the `L1`-`L8` model in full
- [Rules Overview](rules/index.md) - subjects and the rule catalog
- [Evidence Tiers](evidence-tiers.md) - the `A`-`D` taxonomy
- [Security Model](../security.md) - what a result does and does not claim
