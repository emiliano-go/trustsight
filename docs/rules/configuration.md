<!-- description: The rule configuration surface: every rules.toml field, the structural rule table, and how config.toml overrides enablement, severity and weight. -->

# Rule Configuration

Rules live in two files. `rules.toml` defines what a regex or structural rule
matches; `config.toml` controls how the shipped rule set behaves at runtime.
When both set the same field, `config.toml` wins. The complete key reference,
including every non-rule key, is in the
[Configuration Reference](../reference/configuration.md).

## The `rules.toml` rule fields

The fields below describe an R-series rule. H-series rules carry the same
severity, category and weight vocabulary in their findings, but they are not
configured through this file.

Each rule supports these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Rule identifier. Every id in `rules.toml` is an `R` id: `R001`-`R003`, `R007`-`R008`, `R010`-`R013`, `R017`, `R039`-`R059`, `R078`, `R091`, `R099`, `R104`, `R144`, and `R152`. |
| `name` | `string` | Human-readable name. |
| `pattern` | `string` | Python regex applied to the match target. |
| `severity` | `string` | `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `category` | `string` | The capability the match touched (`network_execution`, `obfuscation`, `installer`, `privilege`, `network_usage`, `injection`, `unicode`, `integrity`). This is not the rule's subject: see [Rule labels explained](interpretation.md). |
| `match_target` | `string` | `"resolved"` : apply to variable-resolved command strings after tokenization. `"raw_line"` : apply to raw diff lines after stripping the `+`/`-` prefix. |
| `scope` | `list[string]` | (Optional, `raw_line` only) Restrict matching to line contexts (`["function_body"]`, `["message"]`, `["other"]`) or to a named PKGBUILD function (`["pkgver"]`, `["package"]`, `["package_foo"]`). When absent, matches all lines. |
| `added_only` | `bool` | (Optional, `raw_line` only) Match only added (`+`) lines. Raw diff lines include removals, so without this a maintainer *deleting* a suspicious line raises the score. All `raw_line` `R039`+ rules set it. |
| `experimental` | `bool` | (Optional) Skip the rule unless `[rules] experimental = true` in `config.toml`. Used for rules whose false-positive rate has not been measured against the benign corpus. |
| `include_comments` | `bool` | (Optional) Also match comment lines, which are filtered out for every other rule. Only for rules whose target is the *reader* rather than the shell (R012, R013): a commented-out command does not run, but a comment is exactly where an injection or a hidden character lives. |
| `exclude_if_matches` | `list[string]` | (Optional) Defer to a more precise rule: suppress this rule's finding when any listed rule id also matches the same item, with the same match target and enabled. Keeps one finding per operation without making evaluation order part of the rule contract. |

## Structural rules

A second table in the same file, `[[structural]]`, asks the typed recipe
instead of the raw line. It has its own fields and five match primitives;
the design, the partial-diff rule and the severity cap are in
[Recipe-Targeted User Rules](../explanation/static-analysis-and-resolution.md).

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Rule identifier following the R-series convention, `R###`. |
| `field` | `string` | An array name (`source`, `depends`, `sha256sums`) or `scalars.` plus a scalar name (`scalars.install`). |
| `match` | `string` | `entry_added`, `entry_removed`, `host_added`, `scalar_changed`, or `renamed`. |
| `pattern` | `string` | Python regex searched against the value the primitive selects, never against a raw line. |
| `severity` | `string` | (Optional) Defaults to `MEDIUM`; `FATAL` and `CRITICAL` clamp to `HIGH`. |
| `name` | `string` | (Optional) Defaults to the id. |
| `category` | `string` | (Optional) Capability touched; defaults to `structural`. |
