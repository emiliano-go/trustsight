<!-- description: A-series rules inspect the built package manifest in the optional L9 build lane - off by default, never blended into the static score. -->

# Artifact


A rules inspect the **built package manifest**, not the diff. They are the
optional **L9 build lane**: off by default, run only inside the project's
rootless, networkless container, and never blended into the static score.

The static core never executes package code. A L9 finding is evidence from
*outside* the static analysis, reported alongside it; when the lane did not
run, the report says `l9_unavailable` rather than implying the artifact was
clean.

This is a reference page. For how weight and scope work, see
[Rule Mechanics](mechanics.md).

## Reading an A finding

- It is L9 evidence, never folded into the L1-L8 score.
- When the lane is disabled or the container is unavailable, the run
  carries an `l9_unavailable` boundary (weight 0), which never reads as
  "malicious" or "clean".
- Disagreement between L9 and L1-L8 renders both profiles in full and
  carries an explicit `l9_divergence` notice.

---
