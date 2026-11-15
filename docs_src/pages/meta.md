<!-- description: M-series rules reason about other findings: a declared practice contradicted by structure, or a composition of weak signals across layers. -->

# Meta and Confluence


M rules take **other rules' findings** as their input. Every other series
reads the recipe; this one reads the finding set.

An M finding never lowers a score and never duplicates a line: its input is
the finding multiset *after* the ownership resolver, so two rules that
matched the same line have already collapsed to one owner by the time M
runs. Its value is the relationship - a practice the recipe claims and a
finding that contradicts it, or several weak signals whose combination is
the story.

This is a reference page. For how weight and scope work, see
[Rule Mechanics](mechanics.md).

## Reading an M finding

- It reads the profile, not the diff: the evidence names the findings that
  composed, and the recipe text they came from.
- M001 scores (HIGH); M002 and M003 are weight-0 but **escalate the band one
  step** (never add points), gated on the benign-corpus cap
  `M escalation stays below the benign cap`.
- It fires at the layer of its inputs, so it has no static layer.

---
