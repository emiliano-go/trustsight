<!-- description: Where the fetch-and-execution rules come from (the Trojan-horse shape of the classic supply-chain attack) and what a finding means. -->

# Fetch and Execution

Mechanics live on the [Fetch and Execution system page](../rules/fetch-and-execution.md).

<!-- generated: nature-rules -->
**Rules in this nature:** [C007](../rules/fetch-and-execution.md#c007), [C015](../rules/fetch-and-execution.md#c015), [C016](../rules/fetch-and-execution.md#c016), [H003](../rules/fetch-and-execution.md#h003), [H004](../rules/fetch-and-execution.md#h004), [H009](../rules/fetch-and-execution.md#h009), [H011](../rules/fetch-and-execution.md#h011), [H015](../rules/fetch-and-execution.md#h015), [H016](../rules/fetch-and-execution.md#h016), [H031](../rules/fetch-and-execution.md#h031), [H034](../rules/fetch-and-execution.md#h034), [H041](../rules/fetch-and-execution.md#h041), [H068](../rules/fetch-and-execution.md#h068), [H069](../rules/fetch-and-execution.md#h069), [H071](../rules/fetch-and-execution.md#h071), [H072](../rules/fetch-and-execution.md#h072), [H075](../rules/fetch-and-execution.md#h075), [H077](../rules/fetch-and-execution.md#h077), [H081](../rules/fetch-and-execution.md#h081), [H082](../rules/fetch-and-execution.md#h082), [H083](../rules/fetch-and-execution.md#h083), [H090](../rules/fetch-and-execution.md#h090), [H094](../rules/fetch-and-execution.md#h094), [H107](../rules/fetch-and-execution.md#h107), [R001](../rules/fetch-and-execution.md#r001), [R002](../rules/fetch-and-execution.md#r002), [R008](../rules/fetch-and-execution.md#r008), [R010](../rules/fetch-and-execution.md#r010), [R011](../rules/fetch-and-execution.md#r011), [R041](../rules/fetch-and-execution.md#r041), [R042](../rules/fetch-and-execution.md#r042), [R044](../rules/fetch-and-execution.md#r044), [R046](../rules/fetch-and-execution.md#r046), [R047](../rules/fetch-and-execution.md#r047), [R048](../rules/fetch-and-execution.md#r048), [R051](../rules/fetch-and-execution.md#r051), [R055](../rules/fetch-and-execution.md#r055), [R056](../rules/fetch-and-execution.md#r056), [R057](../rules/fetch-and-execution.md#r057), [R152](../rules/fetch-and-execution.md#r152) (40 rules).
<!-- /generated: nature-rules -->

## Where it comes from

The oldest analogy for this family is the **Trojan horse**. The recipe looks
like an ordinary set of build instructions, but one instruction says "go fetch
new instructions from a stranger, and run them". What executes is not what the
reviewer read, and the diff they approved becomes a smokescreen for code that
was never in it.

That is the oldest and best-understood attack in the PKGBUILD space, and the
shape `curl | bash` made famous. The rules are ordered by how directly they
express it, from the literal pipe to the same effect spread across lines with
variables, base64, or a helper. The H-series is the security core of
TrustSight: built first, calibrated hardest, and the one the fire-rate work is
measured against.

## What a finding means

- The rule names the **use** (fetch, then execute), not proof of malice. A
  package that genuinely must build from a download can say so; the point is
  that the reviewer sees it and it cannot hide in the noise.
- Findings are line-anchored and come with the matched text, so the reviewer
  reads the actual recipe rather than trusting a label.
- Fetch and execute in one line, across lines, via a variable, or through a
  package manager are the same finding family; the cross-file and
  reducing-the-h-series work exists so the set stays small enough to audit.

## See also

- [Fire Rates](../../explanation/fire-rates.md); how H rules are calibrated
- [Reducing the H-Series](../../explanation/reducing-the-h-series.md)
- [Fetch and Execution system page](../rules/fetch-and-execution.md)
