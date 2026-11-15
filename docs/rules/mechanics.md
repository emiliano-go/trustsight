<!-- description: How the rule engine fits together: the matching surface, scoring, configuration, identifiers and series, each owned by one focused reference page. -->

# Rule Mechanics

The category pages describe what rules claim. This page describes the engine
that evaluates them: what a rule sees, how a match becomes weight, how rules
are configured, and how identifiers are allocated. Each subject has one owner;
this page is the landing point.

## The evaluation path

1. **Parse and resolve.** The PKGBUILD is read into a typed document and, where
   static resolution allows, variable references are expanded. What cannot be
   resolved is recorded as a boundary, never guessed. See
   [Static Analysis and Resolution](../explanation/static-analysis-and-resolution.md).
2. **Match.** Regex and structural rules run against the chosen surface;
   heuristic, graph and history rules run in code because they need context a
   single line cannot see. See [Rule Matching](matching.md).
3. **Score.** Every finding contributes its severity weight. Priors and
   maturity-gated novelty add alongside the rules. See [Rule Scoring](scoring.md).
4. **Report.** Findings, coverage states and the verdict are rendered
   deterministically. See [Report Schema](../reference/report-schema.md).

## The five mechanics pages

| Subject | Owner | Covers |
|---|---|---|
| Scoring | [Rule Scoring](scoring.md) | Severity weights, score calculation, FATAL, review thresholds |
| Matching | [Rule Matching](matching.md) | `match_target`, scope, resolved versus raw-line matching, limitations |
| Configuration | [Rule Configuration](configuration.md) | `rules.toml` fields, `config.toml` overrides, structural rules, enablement |
| Identifiers | [Rule Identifiers](identifiers.md) | Reserved ranges, allocation, retired and skipped IDs |
| Series | [Rule Series](series.md) | Mechanism definitions and series-specific detection behaviour |

## Which file controls what

| File | Controls | Reference |
|---|---|---|
| Shipped `rules.toml` | Regex patterns, targets, scopes, severities | [Rule Configuration](configuration.md) |
| `config.toml` | Per-rule overrides, enablement, thresholds, profiles | [Configuration Reference](../reference/configuration.md) |
| `src/trustsight/categories.py` | The closed category set and the page each category owns | [Rule Categories](categories.md) |
| `src/trustsight/rule_id_history.py` | Retired and renamed identifiers | [Rule Identifiers](identifiers.md) |
| `scripts/build_rules_index.py` | Generated category tables and the full catalog | [Rules Overview](index.md) |

## Where to go next

- New to the rule system? Start with [Rule Categories](categories.md).
- Tuning a rule? Read [Rule Scoring](scoring.md) and
  [Configuring Rules and Weights](../workflows/configuring-rules-and-weights.md).
- Writing a rule? Read [Writing a Rule](../contributing/writing-a-rule.md) and
  [Rule Identifiers](identifiers.md).
- Reading a finding? Read [Rule Interpretation](interpretation.md).
