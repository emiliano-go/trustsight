<!-- description: E-series rules read the added content as a distribution - a statistical outlier is suspicion, never a verdict, and the thresholds are calibrated at a 0.5% benign tail. -->

# Entropy

## Overview


E rules read the **distribution** of the added content. No patterns, no
refusal semantics: an attacker who writes resolvable-but-obfuscated code
defeats the X-series' refusal coupling, but a distribution does not care
*why* the content is strange.

This is the statistical twin of [Crossfire](crossfire.md): X catches what
the tokenizer refuses to fold, E catches what folds cleanly but weirdly.

This is a reference page. For how weight and scope work, see
[Rule Mechanics](mechanics.md).

## Reading an E finding

- It is **suspicion, never a verdict**. An E finding never reaches FATAL.
- Its thresholds are calibrated from the locked benign corpus at a 0.5%
  per-rule tail. A p05 E001 would add 15 points to one in twenty benign
  diffs and move the published p95.
- It names the measured value, never the content.

---

## Threat context

Encryption and compression leave a **fingerprint of randomness**. Legitimate
build output has structure - source text, logs, compiled code - but a
ciphertext or a packed archive looks like noise, and a high-entropy blob
written by a recipe is a classic way to smuggle a payload past a reviewer who
only reads the shell. Picture a diary where one paragraph has been replaced by
a line of random letters: you cannot say what it means, only that it does not
belong. The entropy rules measure that randomness in build-adjacent data and
flag the blob that does not fit.

This is a probabilistic family: the finding is a statistical property of the
data, not a decode. It is a lead for a human, not a verdict, and it is
score-bounded accordingly.

## Detection mechanisms

The rules that make up this category are listed below, each with the series that implements it and the severity it carries. Scoring, matching and identifier allocation are shared across every category: see [Rule Mechanics](mechanics.md).

## Individual rules

<!-- generated: page-index -->
| Rule | Name | Severity |
|---|---|---|
| [E001](#e001) | Added-Text Compression Ratio | MEDIUM |
| [E002](#e002) | Encoded-Alphabet Fraction | MEDIUM |
| [E003](#e003) | Identifier Entropy | MEDIUM |
<!-- /generated: page-index -->

### E001: Added-Text Compression Ratio {#e001}

- **Target:** programmatic (added-text distribution)
- **Severity:** MEDIUM (weight 15)
- **Category:** `entropy`

- **Condition:** The added lines compress below `[thresholds] e001.max_ratio`.

A highly compressible addition is repetitive, the shape of a packed or padded payload. Silent unless the threshold is set.

### E002: Encoded-Alphabet Fraction {#e002}

- **Target:** programmatic (added-text distribution)
- **Severity:** MEDIUM (weight 15)
- **Category:** `entropy`

- **Condition:** At least `[thresholds] e002.min_fraction` of the added tokens are base64/base32/hex runs of at least `e002.min_length` (default 64) characters.

The alphabet sets are X029's, applied as a statistic rather than a staging predicate.
The contents of a `sha256sums`/`sha512sums`/`md5sums`/`b2sums` array are removed before
the statistic runs: a recipe that declares a dozen digests adds a block of 64-hex
tokens, and a digest list is metadata for the build rather than encoded payload.
E001 measures the same filtered text for the same reason.

### E003: Identifier Entropy {#e003}

- **Target:** programmatic (added-text distribution)
- **Severity:** MEDIUM (weight 15)
- **Category:** `entropy`

- **Condition:** The entropy of newly assigned variable/function names falls outside the configured band - unigram Shannon entropy (`e003.min_entropy`..`e003.max_entropy`) or **bigram** entropy (`e003.min_bigram`..`e003.max_bigram`).

The second-order statistic keeps the structure a unigram distribution flattens, so it separates generated names (`a`, `b`, `x1` - few bigrams) from packed names more reliably.

**Calibration.** Every E threshold ships empty. `scripts/entropy_calibrate.py`
measures the E001/E002/E003 distributions on the locked benign corpus in the
calibration CI job and prints conservative percentile floors; copying one
into `config.toml` is the deliberate calibration decision, and the tool never
rewrites the shipped defaults.

## Interpretation

- The finding reports an entropy anomaly with the location; false positives
  are expected on legitimately compressed assets, which is why it is a
  weak weighted signal.
- High entropy plus a fetch or an obfuscation step is the combination worth
  acting on; high entropy alone may be a bundled archive.
- Because the ceiling is statistical, treat it as "look here", not "this is
  malformed".

## Related documentation

- [Why Static Analysis](../explanation/static-analysis-and-resolution.md)
