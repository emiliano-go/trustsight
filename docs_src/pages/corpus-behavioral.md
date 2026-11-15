<!-- description: Rules reading the package's position in the corpus, or its deviation from a corpus baseline. Silent without prior observations; run once per metadata cycle. -->

# Corpus Behavioral


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
