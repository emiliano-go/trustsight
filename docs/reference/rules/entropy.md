<!-- description: E-series rules read the added content as a distribution - a statistical outlier is suspicion, never a verdict, and the thresholds ship empty until the corpus sets them. -->

# Entropy

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
- Its thresholds ship **empty**: every E rule is silent until an operator or
  the calibration job sets the threshold from the first corpus measurement.
  The benign fire rate is the published number once measured.
- It names the measured value, never the content.

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [E001](#e001) | Added-Text Compression Ratio | MEDIUM |
| [E002](#e002) | Encoded-Alphabet Fraction | MEDIUM |
| [E003](#e003) | Identifier Entropy | MEDIUM |
<!-- /generated: page-index -->

### E001: Added-Text Compression Ratio {#e001}

**MEDIUM** (weight 15) · category `entropy`

Fires when the added lines compress below `[thresholds] e001.max_ratio` -
a highly compressible addition is repetitive, the shape of a packed or
padded payload. Silent unless the threshold is set.

### E002: Encoded-Alphabet Fraction {#e002}

**MEDIUM** (weight 15) · category `entropy`

Fires when at least `[thresholds] e002.min_fraction` of the added tokens
are base64/hex runs of at least `e002.min_length` (default 64) characters.
The alphabet sets are X029's, applied as a statistic rather than a staging
predicate.

### E003: Identifier Entropy {#e003}

**MEDIUM** (weight 15) · category `entropy`

Fires when the Shannon entropy of newly assigned variable/function names
falls outside `e003.min_entropy`..`e003.max_entropy`. Generated names
(`a`, `b`, `x1` - low entropy) and packed names (high entropy) are both
outliers against the corpus.
