<!-- description: Security and design documentation: the guarantees TrustSight makes while reading hostile input, the boundaries it enforces, the evidence model, and the limits of the analysis. -->

# Security & Design

TrustSight reads hostile AUR content. This section explains the guarantees
behind that, how they are enforced, how evidence is grouped, and what the
analysis cannot see.

| Page | Answers |
|---|---|
| [Security Model](security-model.md) | What TrustSight guarantees, and which gate proves each guarantee |
| [Security Boundaries](security-boundaries.md) | The `A1`-`A15` invariants that keep the reading machine safe |
| [How TrustSight Works](how-it-works.md) | The analysis pipeline from parse to verdict |
| [Evidence and Confidence](evidence-and-confidence.md) | The tier and layer axes, and what confidence means |
| [Assurance Layers](assurance-layers.md) | The `L1`-`L8` evidence groups, coverage states and a worked report |
| [Threat Model and Limitations](threat-model.md) | The adversary, the trust boundary, and the inherent limits |

## Where each subject is owned

| Subject | Authoritative location |
|---|---|
| Security guarantees | [Security Model](security-model.md) |
| Enforcement mechanisms | [Security Model](security-model.md) and the [Enforcement Map](enforcement-map.md) |
| Evidence layers | [Assurance Layers](assurance-layers.md) |
| Evidence classification | [Evidence Categories](../reference/evidence-categories.md) |
| Analysis limitations | [Security Model](security-model.md) and [Threat Model and Limitations](threat-model.md) |
| Detection interpretation | [Rule Interpretation](../rules/interpretation.md) |

Other pages link to these sources instead of restating them in full. A change
to a guarantee, a `B` clause or an enforcement gate is a
security-documentation change and needs the same review as the code it
describes.

## Supporting pages

These are reachable from the pages above and remain part of the security
record, but they are not primary navigation entries:

- [What a Result Claims](what-a-result-claims.md): the `B1`-`B11` clauses.
- [Enforcement Map](enforcement-map.md): every invariant mapped to its gate.
- [Vulnerability Reporting](vulnerability-reporting.md): supported versions,
  contact and timeline.
- [Release Signing](release-signing.md): what signs a release and how to
  verify it.
- [Part 4: Tests and Evaluation](assurance-layers/enforcement.md): what the
  assurance gates prove and what they do not.
- [Diversity and Detector Intake](assurance-layers/diversity.md): how a new
  detector is judged complementary, not just independent.
- [Reporting and the layers object](assurance-layers/reporting.md): the
  report's `layers` payload.

## The rule that keeps this section honest

A security claim without a gate is a claim not made. Every guarantee in the
security model maps to an executable check in `scripts/security_gates.py` or
one of the CI workflows, and a change to a guarantee is reviewed as a
security-documentation change, not as editorial cleanup.
