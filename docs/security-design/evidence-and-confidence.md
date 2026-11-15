<!-- description: How TrustSight classifies evidence: the A-D tiers that describe sourcing, the L1-L8 layers that describe evidence kind, and what "confidence" means in a deterministic report. -->

# Evidence and Confidence

TrustSight labels evidence along two independent axes, and neither is a
probability.

- The **evidence tier** (`A`-`D`) describes how a signal is sourced and how
  much external state it needs before it means anything.
- The **evidence layer** (`L1`-`L8`, plus the optional `L9` artifact lane)
  describes what kind of check produced a finding.

"Confidence" in TrustSight is not a statistical probability attached to a
package. It is the combination of three visible facts: which evidence tier the
signal comes from, whether the check had complete coverage, and how much
history the database holds. All three are reported; none is hidden behind a
single score.

## Evidence tiers

| Tier | Source | Cold-start behaviour |
|---|---|---|
| `A` Structural | Rule matches against the parsed recipe and diff | Always available |
| `B` Priors | Static source-bucket classification | Always available, deterministic |
| `C` History | URL and maintainer novelty from the local database | Gated by maturity; meaningless on run one |
| `D` Verification | Declared checksums, keys and pinning | Reported at weight 0, never credited |

The full taxonomy, including maturity gating and the cold-start rules, is in
[Evidence Tiers](../reference/evidence-tiers.md).

## Evidence layers

The layer is a report and coverage view, not a sequence of barriers. A finding
at `L4` does not mean an attacker passed `L1`-`L3`; it means the check that
caught it belongs to the evasion-shape category. A layer that stayed silent is
not proof of safety.

[Assurance Layers](assurance-layers.md) owns the layer model, the coverage
states and a worked report example.
[Evidence Categories](../reference/evidence-categories.md) owns the
classification table and the rule-family mapping.

## Confidence in practice

- A **weight-0** finding is context, not lower confidence. It is shown because
  its absence would be misleading.
- A finding on an **incomplete** analysis is still evidence; it does not
  license conclusions about the parts that were not read.
- A **cold database** withholds novelty rather than inventing it, and may
  produce `Inconclusive` when novelty is the only thing holding the score up.
- A **declared** practice (checksum, key, pin) is a statement by the recipe,
  not a verification performed by TrustSight.

## Related documentation

- [Rule Interpretation](../rules/interpretation.md): how labels combine on a
  finding.
- [Security Model](security-model.md): what a result guarantees.
- [Threat Model and Limitations](threat-model.md): what it cannot see.
- [Glossary](../reference/glossary.md): the vocabulary, defined once.
