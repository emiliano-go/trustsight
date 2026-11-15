<!-- description: Task-oriented workflows for everyday TrustSight work: auditing before an update, gating CI, investigating a flag, configuring rules, tuning false positives, and reducing the tool's blast radius. -->

# Workflows

These pages cover the tasks you perform with TrustSight in day-to-day
operations. Each one is focused on a single job and assumes you have completed
the [quickstart](../start-here/quickstart.md).

---

| Workflow | When to read it |
|-------|-----------------|
| [Auditing Before Update](auditing-before-update.md) | You want to scan AUR packages before `yay -Syu` : the everyday workflow. |
| [Using TrustSight in CI](using-in-ci.md) | You want to gate package installs in a CI/CD pipeline using policy thresholds on the JSON report. |
| [Acting on a Flag](acting-on-a-flag.md) | A package flagged above the review bar or returned INCONCLUSIVE : what to do next. |
| [Configuring Rules and Weights](configuring-rules-and-weights.md) | You need to edit `rules.toml` or `config.toml` to match your threat model. |
| [Tuning False Positives](tuning-false-positives.md) | A rule is firing too often on your package set : how to identify and fix it. |
| [Watching the AUR Continuously](watching-the-aur-continuously.md) | You want an always-on scanner over the whole AUR : the watch loop, service setups, and webhook alerts. |
| [Reducing Blast Radius](reducing-blast-radius.md) | You want the auditor itself contained: a dedicated unprivileged account or an ephemeral container around the process. |

## Reference

- [CLI reference](../reference/cli.md)
- [Rules reference (complete R/H/C/D/S/X catalog)](../rules/index.md)
- [Code rules reference (C001-C034)](../rules/series.md)
- [Config reference](../reference/configuration.md)
- [Evidence tiers](../reference/evidence-tiers.md)
- [Exit codes](../reference/exit-codes.md)
