# CLI Reference

## Synopsis

```
trustsight <command> [options]
```

Global entry point defined at `src/trustsight/cli.py:210`.

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
4. For each outdated package (up to `--limit`): clones/fetches the repository, computes a git diff between the last-analysed commit and HEAD, applies R001–R013 and C001–C003 rules, classifies source URLs into trust buckets, checks novelty against the local database, calculates a deterministic 0–100 score, and generates a verdict.
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

### Supported keys for `set`

| Key | Target config path |
|-----|-------------------|
| `api_key` | `llm.openai.api_key` |
| `base_url` | `llm.openai.base_url` |

### Config file location

`~/.config/trustsight/config.toml`; created automatically on first run via `ensure_default_configs()`.

---

## trustsight sandbox

```
trustsight sandbox
```

Placeholder for a future sandbox execution environment. Not yet implemented. Gated behind capability detection.

---
