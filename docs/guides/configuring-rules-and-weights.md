---
description: How to edit rules.toml, config.toml, and adjust severity and evidence weights.
---

# Configuring Rules and Weights

TrustSight exposes two configuration files. Together they control which rules fire, how much each signal contributes to the score, and how evidence tiers are weighted.

## Configuration files

| File | Purpose |
|------|---------|
| `rules.toml` | Enable/disable individual rules, adjust severity weights, set scope constraints |
| `config.toml` | Global scoring parameters: `severity_weights`, `source_bucket_weights`, `verification_evidence`, `pinning_weights` |

Both files live in the TrustSight config directory and are read automatically on every run.

## Rule namespaces

TrustSight has two rule namespaces:

| Namespace | Location | Editable | Description |
|-----------|----------|----------|-------------|
| **R-series** (R001-R013) | `rules.toml` | Yes | Detection rules : PKGBUILD pattern matching. Users can enable, disable, and re-weight these. |
| **C-series** (C001-C003) | Code only | No | Structural invariants : domain classification, checksum coherence, dependency graph anomalies. These cannot be disabled through `rules.toml`. |

The C-series enforce invariants that the detection rules depend on. They fire automatically and their contribution is built into the scoring model. If you need to adjust their impact, modify the evidence tier weights in `config.toml` rather than trying to suppress them.

## Adjusting severity weights in rules.toml

```toml
[rules.R004]
enabled = true
severity = "HIGH"        # default: HIGH
weight_override = 15     # default severity weight

[rules.R009]
enabled = true
severity = "MEDIUM"
scope = "function_body"  # only fire inside function bodies
```

Changing a rule's severity or weight directly changes the score. Always re-run benchmarks after editing `rules.toml`.

## Adjusting scoring parameters in config.toml

```toml
[severity_weights]
INFO = 2
LOW = 5
MEDIUM = 10
HIGH = 20
CRITICAL = 40
FATAL = 100

[source_bucket_weights]
known = 0
trusted = 3
untrusted = 8
unknown = 15
malicious = 40

[verification_evidence]
checksum_present = -10
validpgpkeys = -10
gpg = -5

[pinning_weights]
checksum_pinned = -5
tag_pinned = -3
```

The verification evidence block subtracts from the score when the PKGBUILD includes security-relevant metadata. Pinning weights reward builds that pin to a specific checksum or tag.

## Re-baselining after changes

**Any change to weights or rules invalidates the current baseline.** Scores will shift; packages that were CLEAN may become FLAGGED and vice versa.

After editing `rules.toml` or `config.toml`:

1. Run `trustsight review` against your full package set.
2. Review the new score distribution.
3. If the new baseline is acceptable, persist it with the [re-baselining workflow](../contributing/re-baselining.md).

## Warnings

> **Changing weights changes scores.** A small adjustment to `MEDIUM` from 10 to 12 shifts every package that fires a MEDIUM rule. Always validate against your package set before committing config changes.

> **C-series rules are not configurable in `rules.toml`.** If you need to adjust their contribution, modify the corresponding evidence tier weight in `config.toml`. Their logic is structural and cannot be disabled without forking the codebase.

## See also

- [Config reference](../reference/configuration.md): full schema for both files.
- [Rules reference (R001-R013)](../reference/rules.md): per-rule defaults.
- [Tuning false positives](tuning-false-positives.md): how to fix rules that over-fire on your packages.
- [Running the sandbox](running-the-sandbox.md): isolated build execution.
