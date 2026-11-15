<!-- description: Where the corpus-behavioral rules come from (deviation from a familiar baseline) and what a finding means. -->

# Corpus Behavioral

Mechanics live on the
[Corpus Behavioral category page](corpus-behavioral.md).

## Where it comes from

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

## What a finding means

- The finding says the package deviates from the benign corpus's behaviour,
  with the feature(s) driving it. It is not a named attack.
- A lone novelty finding is weak; novelty plus a concrete rule is the case
  where the corpus adds real value.
- If the priors were trained on a narrow slice, novelty findings will be
  noisy; this is a corpus-provenance question, not a package one.

## See also

- [Corpus and Priors](../explanation/historical-and-behavioral-analysis.md)
- [Cold Start and Maturity](../explanation/scoring-and-verdicts.md)
- [Corpus Behavioral category page](corpus-behavioral.md)
