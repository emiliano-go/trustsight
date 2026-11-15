<!-- description: The recorded reports: detection evidence from the wild and the measured evaluations of the rule set. -->

# Reports

These pages are records, not explanations of how the pipeline works. They keep
the evidence a claim rests on alongside the claim.

## Detection reports

Incidents whose diffs the watcher raised, collected under one index so each
campaign keeps its own page:

- [In the Wild](in-the-wild.md): the watcher's incident records, how to read
  them, and what a flag did and did not mean.

## Measurement reports

Point-in-time measurements of the rule set on the locked benign corpus, and the
methodology and gates behind them:

- [Fire Rates](fire-rates.md): the false-positive rate of each rule, the 30 %
  gate, and how a new rule is measured.
- [Benchmarks and Methodology](benchmarks-and-methodology.md): per-class
  separation, the CI gates that re-measure it, and the current figures.
- [Hot-path baseline](hot-path-baseline.md): the measured cost of a review, and
  the first optimization applied to it.

None of these records is a certificate. A clean measurement describes the corpus
and configuration it was taken from, not an AUR update you have not read.
