<!-- description: Rules for a recipe hiding what it does from whoever reads it: encoding, runtime assembly and name indirection, where the line shown is not the command that runs. -->

# Obfuscation


The recipe hides what it does from whoever reads it. Encoding (R003, R043,
R045), runtime assembly (R039, R040) and name indirection (H080) are
all the same move: the line a reviewer sees is not the command that runs.

H065 is the counterpart rather than a detection. The tokenizer rebuilds
these forms so the other rules match on meaning rather than spelling, and
H065 is what tells the reader the reconstruction happened, so the report
never quotes text the file does not contain.

Density, not shape, is [H036](count-based.md#h036): three or more
indicators on one line, counted rather than pattern-matched. Integrity
checks that read as hiding (a hidden drop, an archive trailer) belong to
[staging and reconnaissance](staging-and-recon.md) and
[integrity](integrity.md), which own the target rather than the technique.

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---
