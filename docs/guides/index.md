---
description: Task-oriented guides for common TrustSight workflows.
---

# Guides

These pages cover common tasks you'll perform with TrustSight. Each guide is focused on a single workflow and assumes you've completed the [quickstart](../getting-started/quickstart.md).

---

| Guide | When to read it |
|-------|-----------------|
| [Auditing Before Update](auditing-before-update.md) | You want to scan AUR packages before `yay -Syu` : the everyday workflow. |
| [Using TrustSight in CI](using-in-ci.md) | You want to gate package installs in a CI/CD pipeline using exit codes or policy thresholds. |
| [Acting on a Flag](acting-on-a-flag.md) | A package scored above 20 or returned INCONCLUSIVE : what to do next. |
| [Configuring Rules and Weights](configuring-rules-and-weights.md) | You need to edit `rules.toml` or `config.toml` to match your threat model. |
| [Tuning False Positives](tuning-false-positives.md) | A rule is firing too often on your package set : how to identify and fix it. |

## Reference

- [CLI reference](../reference/cli.md)
- [Rules reference (complete R/H/C/D/S/X catalog)](../reference/rules/index.md)
- [Code rules reference (C001-C009)](../reference/rules/system.md#c-series)
- [Config reference](../reference/configuration.md)
- [Evidence tiers](../reference/evidence-tiers.md)
- [Exit codes](../reference/exit-codes.md)
