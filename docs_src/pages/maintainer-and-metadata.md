<!-- description: Rules for a change of ownership, a long-stable property changing, a maintainer's activity deviating from their baseline, or a new epoch. -->

# Maintainer and Metadata


Who owns the package changed (H026, H044, H074, C006), a property that held
across a long run of observations changed (H037, H049, H050, H051, H054), a
maintainer's activity deviated from their baseline (H058), or an epoch was
introduced (H063).

The longitudinal rules on this page do not read a diff at all. They read
`PropertyBreak` records from the corpus property layer, gated by `[longitudinal]
stability_floor` (default 10): a value must hold at least that many
consecutive observations before a change is reported. Every one of them is
silent on a cold database by construction, because the first observation of
a property only inserts it.

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---
