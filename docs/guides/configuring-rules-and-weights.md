---
description: How to edit rules.toml and config.toml to match your threat model: enabling and reweighting individual rules, and adjusting the evidence-tier weights.
---

# Configuring Rules and Weights

TrustSight exposes two configuration files. Together they control which rules fire, how much each signal contributes to the score, and how evidence tiers are weighted.

## Configuration files

| File | Purpose |
|------|---------|
| `rules.toml` | Definitions for every R-series regex rule: pattern, severity, target, and scope |
| `config.toml` | Global scoring parameters: `severity_weights`, `source_bucket_weights`, `novelty_weights` |

Both files live in the TrustSight config directory and are read automatically on every run.

## Rule namespaces

TrustSight has several rule families. Only the non-FATAL rules defined in `rules.toml` accept the per-rule controls described below.

| Namespace | Location | Editable | Description |
|-----------|----------|----------|-------------|
| **R-series** (32 rules) | `rules.toml` | Non-FATAL rules only | Regex detection rules for PKGBUILD pattern matching. `[rules.R###]` controls in `config.toml` set `enabled` and `weight_override`. Every R rule has a TOML definition, so every R rule reads these controls. |
| **H-series** (95 rules) | Code only | No | Heuristics needing diff context a single regex cannot see. They have no `rules.toml` entry and do not read `[rules.H###]` controls. |
| **C-series** (C001-C009) | Code only | No | Structural invariants : checksum/source coherence and related diff anomalies. These cannot be disabled through `rules.toml`. |

The C-series enforce invariants that the detection rules depend on. They fire automatically and their contribution is built into the scoring model. If you need to adjust their impact, modify the evidence tier weights in `config.toml` rather than trying to suppress them.

## Per-rule controls in config.toml

```toml
[rules.R007]
enabled = true
weight_override = 15     # default severity weight

[rules.R010]
enabled = false
```

`enabled` and `weight_override` are read from `config.toml`; they do not change a rule's TOML definition. FATAL rules cannot be disabled, and their score hard-stops at 100, so a weight override has no effect. Code-emitted rules have their own configuration paths where provided, such as `[experimental_rules]`; `[rules.R###]` does not control them. Always re-run benchmarks after changing an effective weight.

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
```

There is no block for verification or pinning. Declared checksums, PGP keys,
GPG sources and source pins are reported as weight-0 `P001`-`P008` findings and
cannot be given a weight: a signal an attacker can assert for free must not be
able to move a score. See
[B10](../security.md#b10-positive-evidence-is-reported-never-credited).

## Re-baselining after changes

**Any change to weights or rules invalidates the current baseline.** Scores will shift; packages that were UNFLAGGED may become FLAGGED and vice versa.

After editing `rules.toml` or `config.toml`:

1. Run `trustsight review` against your full package set.
2. Review the new score distribution.
3. If the new baseline is acceptable, persist it with the [re-baselining workflow](../contributing/re-baselining.md).

## Warnings

> **Changing weights changes scores.** A small adjustment to `MEDIUM` from 10 to 12 shifts every package that fires a MEDIUM rule. Always validate against your package set before committing config changes.

> **Only TOML-defined non-FATAL rules accept `[rules.R###]` controls.** C-series and code-emitted rules cannot be disabled or reweighted that way. Their logic is structural or programmatic and requires the documented dedicated setting, if one exists, or a code change.

## See also

- [Config reference](../reference/configuration.md): full schema for both files.
- [Rules reference](../reference/rules/index.md): per-rule defaults across the complete R/H/C/D/S/X catalog.
- [Tuning false positives](tuning-false-positives.md): how to fix rules that over-fire on your packages.
