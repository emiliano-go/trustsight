<!-- description: Where the fetch-and-execution rules come from (the Trojan-horse shape of the classic supply-chain attack) and what a finding means. -->

# Fetch and Execution

Mechanics live on the [Fetch and Execution category page](fetch-and-execution.md).

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

- [Fire Rates](../explanation/historical-and-behavioral-analysis.md); how H rules are calibrated
- [Reducing the H-Series](../explanation/detection-and-evidence.md)
- [Fetch and Execution category page](fetch-and-execution.md)
