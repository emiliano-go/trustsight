<!-- description: Rules for a verification the recipe carried being weakened, removed, or unable to cover what it claims: checksums, signatures and build flags. -->

# Integrity and Verification


A verification the recipe carried is weakened, removed, or cannot cover
what it claims to. The checksum rules (H001, H002, C001 to C005) and the
signature rules (H024, H078) are the core; the build-flag rules
(R049, R050, H025, H047, H079) are the same claim applied to
mitigations rather than to sources.

The asymmetry is deliberate throughout. Declaring verification costs an
attacker nothing, so a declaration is reported at weight 0 as a
[P-series](scoring.md) fact. Removing verification is a
change to the recipe's own prior behaviour, which is evidence, so it
scores. See [B10](../security-design/security-model.md#b10-positive-evidence-is-reported-never-credited).

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---
