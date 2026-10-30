<!-- description: Rules reading how recently the package or this revision appeared, from AUR commit timestamps alone. None of them needs a diff. -->

# Temporal Context

Where these rules come from and what a finding means: [Rule Nature](../nature/temporal.md).

How recently the package or this revision appeared. These read git commit
timestamps on the AUR repository and nothing else, so none of them needs a
diff. H020 and H021 also fire on first-seen packages through
`_make_fresh_analysis()` in `src/trustsight/analysis/pipeline/_analyze_helpers.py`; H022 needs a prior commit, so it
fires only on the incremental path.

None is calibrated against the benign corpus, because each one is a
function of when the scan runs rather than of what the package contains.
H020 and H021 are INFO for that reason: recency has no meaning on its own,
and only escalates a package once another signal fires alongside it.

Release cadence is a related but separate claim and is not scored at all;
see [H028](corpus-behavioral.md#h028).

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---
