<!-- description: Where the entropy rules come from (randomness as a signal of hidden payloads) and what a finding means. -->

# Entropy

Mechanics live on the [Entropy category page](entropy.md).

## Where it comes from

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

## What a finding means

- The finding reports an entropy anomaly with the location; false positives
  are expected on legitimately compressed assets, which is why it is a
  weak weighted signal.
- High entropy plus a fetch or an obfuscation step is the combination worth
  acting on; high entropy alone may be a bundled archive.
- Because the ceiling is statistical, treat it as "look here", not "this is
  malformed".

## See also

- [Why Static Analysis](../explanation/static-analysis-and-resolution.md)
- [Entropy category page](entropy.md)
