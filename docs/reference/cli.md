# CLI Reference

## Synopsis

```
trustsight <command> [options]
```

Global entry point defined at `src/trustsight/cli.py`.

---

## trustsight review

Scan all installed AUR packages, check for newer versions on the AUR, produce a diff for each outdated package, run the full analysis pipeline, and print a summary table.

```
trustsight review [--limit N]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--limit` | `int` | `20` | Maximum number of outdated packages to review. Falls back to `limits.default_review_limit` from config if omitted (default: 20). |

### Behaviour

1. Lists every AUR-installed package via `pacman -Qm`.
2. Queries `https://aur.archlinux.org/rpc?v=5&type=info&arg[]=<names>` in a single batched request.
3. Filters to packages whose installed version differs from the latest AUR version.
4. For each outdated package (up to `--limit`): clones/fetches the repository, computes a git diff between the last-analysed commit and HEAD, applies R001-R013 and C001-C003 rules, classifies source URLs into trust buckets, checks novelty against the local database, calculates a deterministic 0-100 score, and generates a verdict.
5. Prints a table with columns: **Package**, **Risk Score**, **Verdict**.

### Output

Uses [rich](https://github.com/Textualize/rich) tables when available; falls back to plain text.

### Exit codes

| Code | Condition |
|------|-----------|
| `0` | All packages scored ≤20 (CLEAN). |
| `1` | One or more packages scored >20 (FLAGGED) or verdict is INCONCLUSIVE. |

---

## trustsight inspect

Show the full analysis for a single package: version diff, score with risk level, maintainer change, diff summary, checksum behaviour, added source URLs with bucket classification, resolved commands, score breakdown, and verdict.

```
trustsight inspect <package>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `package` | Yes | AUR package name to analyse. |

### No flags

This command takes no additional flags.

### Output

When [rich](https://github.com/Textualize/rich) is available:

```
TrustSight Inspect: <package>
  Version: <old> → <new>
  Score: <N>/100 (<risk>)

  Diff Summary
  Files changed: PKGBUILD, .SRCINFO
  Lines: +<N>/-<N>

  Checksum behavior: <behaviour>

  Source URLs Added
    <url> (<bucket>)

  Resolved Commands
    <command>

  Score Breakdown
  +<weight> <SEVERITY>  <rule_id>  <reason>

  Verdict
  <verdict text>
```

Plain-text fallback prints a condensed subset of the same information.

### Database

The analysis result (`PackageFact` serialised to JSON, triggered rules, raw diff) is persisted to the local SQLite database before output is printed.

---

## trustsight history

Show analysis history for a package.

```
trustsight history <package> [--limit N] [--score-breakdown]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `package` | Yes | AUR package name. |

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--limit` | `int` | `20` | Maximum number of history entries to display. |
| `--score-breakdown` | flag | `false` | When set, print the score breakdown for the latest (most recent) history entry. |

### Output

Table with columns: **Date**, **Old**, **→ New**, **Score**, **Risk**.

If `--score-breakdown` is set, the triggered rules for the latest entry are printed below the table.

---

## trustsight config

View or modify TrustSight configuration.

```
trustsight config show
trustsight config set <key> <value>
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `show` | Print the current configuration from `~/.config/trustsight/config.toml`. Displays LLM provider, model, API key (masked), and base URL. |
| `set <key> <value>` | Set a configuration value. Only `api_key` and `base_url` are supported. Writes to `llm.openai.<key>` in `config.toml`. |
| `sync-rules` | Add rules that ship with this version but are absent from your `rules.toml`. |

### `sync-rules`

```
trustsight config sync-rules [--update]
```

`rules.toml` is written only when it does not exist, so upgrading the package
never changes it. An install that predates a rule addition silently never
receives that rule, and a corrected pattern never reaches anyone who already
has the file.

| Flag | Description |
|------|-------------|
| `--update` | Also replace rules whose current pattern is one this project shipped previously. A rule whose pattern matches neither the current default nor a known earlier one has been edited by you and is never touched. |

Adding is always safe and happens by default. Replacing is not, which is why it
is opt-in and limited to rules you demonstrably have not customised.
`trustsight lint-rules` reports both conditions.

### Supported keys for `set`

| Key | Target config path |
|-----|-------------------|
| `api_key` | `llm.openai.api_key` |
| `base_url` | `llm.openai.base_url` |

### Config file location

`~/.config/trustsight/config.toml`; created automatically on first run via `ensure_default_configs()`.

---

## trustsight override

Suppress a rule that misfires on your packages, with a recorded reason.

```
trustsight override list
trustsight override add <rule_id> --reason "..." [--package NAME]
trustsight override rm <rule_id> [--package NAME]
```

Some rules are correct in general and wrong for you. R010 fires on any `curl`
inside a build function; if you maintain a package that legitimately fetches at
build time, that finding is noise on every single review, and noise that never
goes away is worse than no finding at all, because it trains you to skim.

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `list` | Show configured overrides. This is the default when no subcommand is given. |
| `add <rule_id>` | Suppress a rule. `--reason` is required. |
| `rm <rule_id>` | Stop suppressing a rule. Exits non-zero if no override matched. |

### Flags

| Flag | Description |
|------|-------------|
| `--reason TEXT` | Why the rule is suppressed. Required on `add`; an override with no stated reason is indistinguishable later from a mistake. |
| `--package NAME` | Limit the override to one package. Without it, the override applies to every package. |

### What an override does not do

An override removes a finding from the score, but the finding is still recorded
and still reported, under a **Suppressed by override** heading in
`trustsight inspect`, with the reason you gave. A suppression you cannot see is
indistinguishable from a detection that never happened.

**FATAL rules cannot be overridden.** `add` refuses to create one, and the
filter refuses to honour one even if the file is edited by hand. R012 (prompt
injection) and R013 (unicode deception) are the two findings an attacker would
most want switched off, and both indicate the package is trying to deceive the
reviewer rather than merely doing something unusual.

Overrides live in `~/.config/trustsight/overrides.json`.

---

## trustsight seed-db

Import the novelty seed database, so a fresh install is not cold.

```
trustsight seed-db [--import] [--file PATH] [--force]
```

On an empty database every source URL looks first-seen and `maturity()` returns 0, which gates tier C off entirely and downgrades every Medium verdict to INCONCLUSIVE. The seed supplies both halves of what maturity is really asking about: a body of known AUR source URLs, and a bootstrap observation count.

The bundled seed is built from the AUR git mirror by `scripts/generate_seed.py`, which parses each package's `.SRCINFO` (including the arch-suffixed `source_x86_64` arrays, where `-bin` packages put their real download) and the `# Maintainer:` comment from its PKGBUILD. URLs are normalised with the same `normalize_url()` the runtime uses, so a routine version bump matches a seeded entry.

### Flags

| Flag | Description |
|------|-------------|
| `--import` | Import the seed. This is the default action; the flag is accepted for explicitness. |
| `--file PATH` | Import a specific `.db` or `.db.gz` instead of the bundled one. |
| `--force` | Re-import even if a seed has already been imported. |

### Automatic import

`trustsight review` and `trustsight inspect` import the bundled seed on first use when the database has no seed **and** no analysis history. Disable with:

```toml
[seed]
auto_import = false
```

Import takes a few seconds for the full seed and is additive: existing rows win, so a seed can never overwrite something learned from a real analysis, and re-importing is a no-op.

### Maturity handover

`effective_observation_count()` returns `max(real_analyses, seed_observation_count)`. Real analyses take over as soon as they outnumber the seed, so ordinary use replaces the bootstrap and the tool never depends on external data permanently.

### Trust

The seed is derived entirely from public AUR data and is reproducible: re-running the generator against the same mirror produces the same database. It only ever makes novelty signals *quieter*; it cannot lower a rule score, change a severity, or suppress a finding. A tampered seed could at most hide a novelty signal, never fabricate a clean verdict.

---

## trustsight lint-rules

Check `rules.toml` for rules that are unreachable, over-broad, or malformed.

```
trustsight lint-rules [--file PATH]
```

A malformed rule fails silently at runtime. An empty pattern matches every line, and at FATAL severity forces every package to score 100. A pattern that only matches comment text can never fire, because the engine strips comments before matching. Neither failure is visible without a corpus.

### Flags

| Flag | Description |
|------|-------------|
| `--file PATH` | Lint a specific rules TOML file instead of `~/.config/trustsight/rules.toml`. Use in CI to check the ruleset in the repository. |

### Checks

| Check | Level | Meaning |
|-------|-------|---------|
| `required-field` | error | A rule is missing `id`, `name`, `pattern`, `severity`, or `category`. |
| `empty-pattern` | error | The pattern is empty, so it matches every line. |
| `matches-everything` | error | The pattern matches the empty string. |
| `compile` | error | The pattern does not compile. `apply_rules()` skips uncompilable rules silently. |
| `backtracking` | error | The pattern is superlinear on adversarial input; a crafted PKGBUILD line could hang the scan. |
| `duplicate-id` | error | Two rules share an id, so the later one silently redefines what the id means in baselines and fixtures. |
| `programmatic-id` | error | The id is one that `analysis.py` emits (`R004`, `R005`, `C001`-`C003`). |
| `severity` | error | Unknown severity. Unknown severities score 0. |
| `match-target` / `scope` | error | Unknown `match_target`, or an unknown scope value. |
| `comment-shadowed` | error | Every line the pattern matches is a comment or `depends` declaration, which `filter_raw_lines()` strips before matching. |
| `scope-contradiction` | error | The pattern matches a function header line while scoping itself to `function_body`. The header is classified `other`, so the rule can never fire. |
| `benign-hit` | warning | A MEDIUM-or-higher rule fires on ordinary packaging in the probe corpus (for example `chmod 644` or an `install` into `$pkgdir/etc`). |
| `end-anchor` | warning | A `raw_line` pattern is anchored with `$`, but raw diff lines keep trailing quotes and parentheses. |
| `scope-shadowed` | warning | The pattern matches probe lines, but none within its declared scope. |
| `id-format` / `scope-ignored` | warning | The id does not follow the `R###`/`C###` convention, or `scope` is set on a `resolved` rule, where it is ignored. |

### How reachability is checked

Rules are run through the real matching engine against a small annotated probe diff, so comment filtering and function-body scoping apply exactly as they do in production. Probe lines are tagged benign or suspicious; a high-severity rule firing on a benign line is reported as `benign-hit`, because a rule that matches ordinary packaging will fire across a large share of the AUR.

Backtracking is measured rather than guessed. Static nested-quantifier heuristics false-positive on safe patterns such as `(?:-\S+\s+)*`, where the inner and outer character classes are disjoint. Probe inputs are capped at 18 characters so that detecting an exponential pattern does not itself hang the linter.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No errors (warnings may be present). |
| `1` | At least one error. |
| `2` | `--file` path does not exist. |

---
