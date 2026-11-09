<!-- description: E-series rules read the added content as a distribution - a statistical outlier is suspicion, never a verdict, and the thresholds are calibrated at a 0.5% benign tail. -->

# Entropy

Where these rules come from and what a finding means: [Rule Nature](../nature/entropy.md).

E rules read the **distribution** of the added content. No patterns, no
refusal semantics: an attacker who writes resolvable-but-obfuscated code
defeats the X-series' refusal coupling, but a distribution does not care
*why* the content is strange.

This is the statistical twin of [Crossfire](crossfire.md): X catches what
the tokenizer refuses to fold, E catches what folds cleanly but weirdly.

This is a reference page. For how weight and scope work, see
[Rule System](system.md).

## Reading an E finding

- It is **suspicion, never a verdict**. An E finding never reaches FATAL.
- Its thresholds are calibrated from the locked benign corpus at a 0.5%
  per-rule tail. A p05 E001 would add 15 points to one in twenty benign
  diffs and move the published p95.
- It names the measured value, never the content.

---
