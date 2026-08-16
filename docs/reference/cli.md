# CLI Reference

## Synopsis

```
trustsight <command> [options]
```

Global entry point defined in the `src/trustsight/cli/` package.

## Global flags

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Show help message, including config subcommands and usage examples. |
| `-v`, `--version` | Print version number (`trustsight X.Y.Z`) and exit. |
| `--json` | Output in JSON format instead of the default rich/plain text. Available on all commands. |

The help output also documents `trustsight config show`, `trustsight config set <key> <value>`, and `trustsight config sync-rules` with inline examples.

## Interrupt handling

`Ctrl+C` during any operation prints `Interrupted.` and exits with code 130 instead of dumping an SSL/httpx traceback.

---

## trustsight review

Scan packages for newer versions on the AUR, produce a diff for each outdated package, run the full analysis pipeline, and print one panel per package with a summary line.

```
trustsight review [--limit N] [--repo REPO]... [--foreign] [--all-repos] [--verbose] [--score] [--risk] [--depth N] [--deps]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--limit` | `int` | `[limits] default_review_limit` (0) | Maximum number of outdated packages to review. `0` means unlimited, which is the shipped default: a review that stops early has not looked at the rest. When the limit does cut the list, the summary names how many went unread rather than reporting the smaller number as the whole. |
| `--verbose` | flag | `false` | Show triggered rules per package in an additional column. |
| `--quiet` | flag | `false` | Suppress the progress bar during analysis. |
| `--score` | flag | `false` | Show aggregate trust score for each package. |
| `--risk` | flag | `false` | Show risk level; colours the panel border by risk. |
| `--depth` | `int` | `[depth] levels` (1) | AUR dependency levels to analyse. `0` disables it, `1` analyses direct AUR dependencies, `n` analyses `n` levels, and `-1` walks every level there is - bounded by `depth.MAX_DEPTH_LEVELS` (8) and `depth.MAX_DEPTH_NODES` (200), because the dependency graph is written by the party under review. A walk cut short by either ceiling records the `deps_not_scanned` coverage gap. |
| `--all` | flag | `false` | Review all installed AUR packages, not just outdated ones. |
| `--deps` | flag | `false` | Review the AUR **dependencies** of the discovered packages instead of the packages themselves. Each dependency is reviewed as a package in its own right, and reports a **Required by** section naming the packages in the reviewed set that declare it. Honours `--depth`, which here means levels *of dependencies to review* rather than levels below each one: `--deps --depth 2` reviews direct dependencies and their dependencies. The roots are not reviewed - they are what you get without the flag. Bounded by the same `depth.MAX_DEPTH_LEVELS` and `depth.MAX_DEPTH_NODES` ceilings, and a closure cut short says so. |
| `--repo` | `str` | - | Scan packages from a specific local repository. Can be repeated (`--repo aur --repo testing`). |
| `--foreign` | flag | `false` | Also include foreign packages (`pacman -Qm`). When used with `--repo`, foreign packages are added to the set. |
| `--all-repos` | flag | `false` | Automatically detect all local repositories from `/etc/pacman.conf` (excludes official repos: `core`, `extra`, `community`, `multilib`, `testing`, etc.) and scan packages from all of them. |

#### Flag precedence

If any discovery flag (`--repo`, `--foreign`, `--all-repos`) is given on the command line, the `[discovery]` config section is ignored for that run. Otherwise, the config defaults apply (see [Configuration Reference](configuration.md)).

### Examples

```
trustsight review                      # Foreign packages only (default)
trustsight review --repo aur           # Packages from the aur repo only
trustsight review --repo aur --repo testing --foreign
                                       # aur + testing repos + foreign
trustsight review --all-repos          # All local repos, no foreign
trustsight review --deps               # The dependencies, not the packages
trustsight review --deps --depth 2     # ...and their dependencies too
trustsight review --all-repos --foreign
                                       # All local repos + foreign
```

### Behaviour

Discovery uses a local AUR metadata snapshot by default:

1. Collects package names and versions from the requested sources (repo contents via `pacman -Sl <repo>` intersected with `pacman -Q`, foreign via `pacman -Qm`, or auto-detected repos via `pacman-conf --repo-list`).
2. Looks up each installed package in the AUR metadata snapshot (`full-aur-meta.json`, an offline copy of the AUR package database). On the first run the snapshot is downloaded and the run stops there, since there is nothing to compare against yet. Later runs reuse the snapshot until it is older than `[discovery] metadata_ttl_minutes` (default 60), then refetch it: the version a review compares against is the snapshot's, so a snapshot left to age reports a machine with pending updates as fully current. A refresh that cannot reach the AUR keeps the snapshot on disk and warns that a package updated since then will not be reported.
3. Filters to packages whose installed version is older than the snapshot version (using `vercmp`).
4. For each outdated package (up to `--limit`): clones/fetches the repository, computes a git diff between the last-analysed commit and HEAD, applies the R-series detection rules (R001-R131) and code-structure rules (C001-C007), classifies source URLs into trust buckets, checks novelty against the local database, calculates a deterministic 0-100 score, and generates a verdict.
5. Prints one panel per package, and a summary line counting what needed review separately from what was read.

With `--deps` the subject changes: step 3's outdated set becomes the *roots* of a dependency closure walked to `--depth`, and it is the dependencies that are analysed and printed, each naming the packages that require it.

If the metadata snapshot is unavailable or corrupt, the tool falls back to the AUR RPC interface (`https://aur.archlinux.org/rpc?v=5&type=info`) for the same comparison.

### Output

Uses [rich](https://github.com/Textualize/rich) tables when available; falls back to plain text.

---

## trustsight inspect

Show the full analysis for a single package: version diff, maintainer change, diff summary, checksum behaviour, added source URLs with bucket classification, resolved commands, triggered rules, and status.

```
trustsight inspect <package>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `package` | Yes | AUR package name to analyse. |

### Flags

| Flag | Description |
|------|-------------|
| `--verbose` | Show triggered rules and score breakdown (already shown by default in rich mode; primarily useful with `--json` to include breakdown data). |
| `--score` | Show aggregate trust score with weight contribution breakdown. |
| `--risk` | Show risk level with per-rule severity labels. Implies a coloured border in rich mode. |
| `--depth` | AUR dependency levels to analyse: `0` off, `1` (default) direct dependencies, `n` levels, `-1` every level (bounded). Each dependency is analysed as a package in its own right, with its own score and band, shown as a mini-card inside the package's card. |

### Output

When [rich](https://github.com/Textualize/rich) is available:

```
╭───────────────────── TrustSight Inspect: example-pkg ──────────────────────╮
│                Version  1.4.2-1 -> 1.5.0-2                                 │
│             Not vetted  the diff exceeded the size cap, so only its first  │
│                         bytes were examined                                │
│                  Lines  +6 -2                                              │
│             Maintainer  Jane Doe <jane@example.org>                        │
│               Checksum  checksum_added_or_changed                          │
│                                                                            │
│           What changed                                                     │
│                           pkgver 1.4.2-1 -> 1.5.0-2                        │
│                           checksums added or changed                       │
│                           source host added: example.invalid               │
│                                                                            │
│          Files changed                                                     │
│                           ~ PKGBUILD                                       │
│                           ~ .SRCINFO                                       │
│                                                                            │
│      Source URLs added                                                     │
│                           [unknown] https://example.invalid/p.tar.gz       │
│                                                                            │
│      Resolved commands                                                     │
│                           curl -fsSL https://example.invalid/p.tar.gz      │
│                                                                            │
│        Rules Triggered                                                     │
│                         R001 Remote Script Execution                       │
│                                                                            │
│           Dependencies                                                     │
│                         ╭──────────────── L1  libhelper ─────────────────╮ │
│                         │ Findings 2                                     │ │
│                         ╰────────────────────────────────────────────────╯ │
│                                                                            │
│ Suppressed by override                                                     │
│                           R099  known                                      │
│                                                                            │
│                 Status  The update is not trivial. Review it.              │
╰────────────────────────────────────────────────────────────────────────────╯
```

Sections appear only when they have content. `Status` is printed once, at the
foot of the panel.

The `--score` flag shows per-rule weights (`+40`) and a `Score  N/100 (risk)`
row with the weight sum beneath it. The `--risk` flag shows per-rule severities
(`CRITICAL`) and a `Risk  <level>` row, and colours the border by band. Without
either flag the band is withheld everywhere, dependency cards included, and the
border is blue. When both are given the Score row wins, since it already names
the band.

The plain-text fallback carries the **same sections** in the same order. It is
not a condensed subset: a field on one renderer and not the other is a
difference in information, which
[B11](../security.md#b11-every-surface-reports-the-same-thing) forbids.

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

## trustsight list

List all packages tracked in the database with their latest score.

```
trustsight list [--limit N]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--limit` | `int` | `0` | Maximum number of packages to show. `0` means unlimited. |

### Output

Table with columns: **Package**, **Version**, **Maintainer**, **Last Checked**, **Score**, **Risk**.

Packages that have never been analysed show `-` for score.  Version strings that could not be resolved (raw bash expressions, nested parameter expansions) display as `unresolved`.

---

## trustsight forget

Remove a tracked package and all associated history (analysis history, triggered rules, snapshots, profiles, alert state).  Package data is removed permanently; source URL and maintainer records are reassigned to the internal sentinel rather than deleted.

```
trustsight forget <package>...
trustsight forget --prune [--dry-run]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `package` | One or more | Package name(s) to remove from tracking. |

### Flags

| Flag | Description |
|------|-------------|
| `--prune` | Remove every tracked package that no longer exists in the AUR.  Re-verifies each name against the AUR RPC and removes absent ones.  Useful for cleaning up packages that were deleted from the AUR or that were never in it. |
| `--dry-run` | Show what would be removed without actually deleting anything.  Only meaningful with `--prune`. |
| `--yes` | Skip the confirmation prompt when removing named packages (always skips for `--prune`). |

### Behaviour

When removing named packages:

1. Deletes `alert_state`, `pkgbuild_snapshots`, `package_profiles`, and `package_properties` rows keyed by the package name.
2. Deletes `triggered_rules` rows (via `analysis_history`).
3. Deletes `analysis_history` rows.
4. Reassigns `source_urls.first_seen_package_id` and `maintainers.first_seen_package_id` to the internal sentinel (id 0).
5. Deletes the `packages` row.

Reserved names (`__seed__`, or any name starting with `__`) cannot be forgotten and raise an error.

### Examples

```
trustsight forget aurch                    # Remove a single non-AUR helper
trustsight forget aurch openssl-1.1        # Remove multiple packages
trustsight forget --prune --dry-run        # Show what would be pruned
trustsight forget --prune                  # Remove all non-AUR packages
```

---

## trustsight status

Show database and system health statistics.

```
trustsight status
```

### Output

| Metric | Description |
|--------|-------------|
| Packages tracked | Number of distinct packages in the local database. |
| Total analyses | Analysis runs recorded across all packages. |
| Effective observations | Max of real analyses and seed bootstrap (what maturity() actually sees). |
| Seed observations | Bootstrap count from the novelty seed, or 0 if not imported. |
| Dependency corpus | Whether the dependency observation table has been populated. |

---

## trustsight config

View or modify TrustSight configuration.

```
trustsight config show
trustsight config set <key> <value>
trustsight config sync-rules [--update]
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `show` | Print the current configuration from `~/.config/trustsight/config.toml`. Displays seed auto-import status, experimental rules toggle, and scoring weights. |
| `set <key> <value>` | Set a configuration value. Example: `trustsight config set seed.auto_import false`. |
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

### Config file location

`~/.config/trustsight/config.toml`; created automatically on first run via `ensure_default_configs()`.

---

## trustsight override

Suppress a rule that misfires on your packages, with a recorded reason.

```
trustsight override list
trustsight override add <rule_id> --reason "..." [--package NAME]
trustsight override rm <rule_id> [--package NAME]
trustsight override wizard <package>
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
| `wizard <package>` | Interactive wizard: analyses the package, shows triggered non-FATAL rules, and prompts you to suppress each with a reason. |

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

The seed no longer ships inside the package. It is published as the signed
`baseline-seed.tar.gz` release asset (v2 hashed format) and fetched with
`trustsight seed fetch`; `seed-db --file` still imports any `.db`, `.db.gz`
or `.tar.gz` seed you built yourself. The underlying data is built from the
AUR git mirror by `scripts/generate_seed.py`, which parses each package's
`.SRCINFO` (including the arch-suffixed `source_x86_64` arrays, where `-bin`
packages put their real download) and the `# Maintainer:` comment from its
PKGBUILD. URLs are normalised with the same `normalize_url()` the runtime
uses, so a routine version bump matches a seeded entry.

### Flags

| Flag | Description |
|------|-------------|
| `--import` | Import the seed. This is the default action; the flag is accepted for explicitness. |
| `--file PATH` | Import a specific seed file (`.db`, `.db.gz`, or a `.tar.gz` v2 seed) instead of the default. |
| `--force` | Re-import even if a seed has already been imported. |

### Automatic import

`trustsight review` and `trustsight inspect` attempt the verified
release-channel seed on first use when the database has no seed **and** no
analysis history; on a machine without network, or when the download fails
verification, the attempt is silently skipped and the run starts cold.
Disable with:

```toml
[seed]
auto_import = false
```

Import takes a few seconds for the full seed and is additive: existing rows win, so a seed can never overwrite something learned from a real analysis, and re-importing is a no-op.

### Maturity handover

`effective_observation_count()` returns `max(real_analyses, seed_observation_count)`. Real analyses take over as soon as they outnumber the seed, so ordinary use replaces the bootstrap and the tool never depends on external data permanently.

### Trust

The seed is derived entirely from public AUR data and is reproducible: re-running the generator against the same mirror produces the same database. The release asset is accepted only when its detached ed25519 signature verifies against the key pinned in the package (fingerprint in [baseline keys](baseline-keys.md)); the import records the digest of the exact bytes that were verified. It only ever makes novelty signals *quieter*; it cannot lower a rule score, change a severity, or suppress a finding. A tampered seed could at most hide a novelty signal, never fabricate an UNFLAGGED verdict.

---

## trustsight seed

Inspect and migrate the hashed maintainer seed (v0.12.0).

```
trustsight seed info
trustsight seed stats
trustsight seed migrate [--from-backup]
trustsight seed fetch [--tag TAG] [--key PATH]
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `info` | Show seed metadata and hashing configuration. |
| `stats` | Show hashed maintainer counts by source. |
| `migrate` | Migrate plaintext maintainer rows into the hashed store. |
| `fetch` | Download `baseline-seed.tar.gz` from the release channel, verify its detached Ed25519 signature against the pinned distribution key, and import it. Refuses (exit 2) anything that does not verify. |

### Flags

| Flag | Description |
|------|-------------|
| `--tag` | Fetch a specific release tag instead of the latest release. |
| `--key` | Verify against this ed25519 public key file instead of the pinned key shipped in the package. |
| `--from-backup` | Migrate from the `maintainers_deprecated_backup` table left behind after the automatic v0.12.0 migration. |
| `--json` | Output JSON. |

---

## trustsight db

Database maintenance commands: integrity check, vacuum, and backup.

```
trustsight db check
trustsight db vacuum [--force]
trustsight db backup [--output PATH]
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `check` | Run `PRAGMA integrity_check` on the database. Exits 0 on success, 1 if corruption is detected. |
| `vacuum` | Reclaim disk space by rebuilding the database file. Prompts for confirmation unless `--force` is passed. |
| `backup` | Create a safe online backup via `sqlite3.backup()`. No need to stop TrustSight. Default output: `<db_path>.YYYYMMDD-HHMMSS.bak`. |

### Common flags

| Flag | Description |
|------|-------------|
| `--json` | Output JSON. |

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
| `programmatic-id` | error | The id is one emitted by code (`R004`, `R005`, `C001`-`C003`). |
| `severity` | error | Unknown severity. Unknown severities score 0. |
| `match-target` / `scope` | error | Unknown `match_target`, or an unknown scope value. |
| `comment-shadowed` | error | Every line the pattern matches is a comment or `depends` declaration, which `filter_raw_lines()` strips before matching. |
| `scope-contradiction` | warning | The pattern matches a function header line while scoping itself to `function_body`. A bare header is classified `other`, so the rule misses the ordinary multi-line form; it still fires on a single-line definition. |
| `benign-hit` | warning | A MEDIUM-or-higher rule fires on ordinary packaging in the probe corpus (for example `chmod 644` or an `install` into `$pkgdir/etc`). |
| `end-anchor` | warning | A `raw_line` pattern is anchored with `$`, but raw diff lines keep trailing quotes and parentheses. |
| `scope-shadowed` | warning | The pattern matches probe lines, but none within its declared scope. |
| `id-format` / `scope-ignored` | warning | The id does not follow the `R###`/`C###` convention, or `scope` is set on a `resolved` rule, where it is ignored. |

### How reachability is checked

Rules are run through the real matching engine against a small annotated probe diff, so comment filtering and function-body scoping apply exactly as they do in production. Probe lines are tagged benign or suspicious; a high-severity rule firing on a benign line is reported as `benign-hit`, because a rule that matches ordinary packaging will fire across a large share of the AUR.

Backtracking is measured rather than guessed. Static nested-quantifier heuristics false-positive on safe patterns such as `(?:-\S+\s+)*`, where the inner and outer character classes are disjoint. Probe inputs are capped at 22 characters (adjusted for Python 3.12+ optimized `re` engine) so that detecting an exponential pattern does not itself hang the linter.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No errors (warnings may be present). |
| `1` | At least one error. |
| `2` | `--file` path does not exist. |

---

## trustsight baseline

Build or import a full-AUR baseline corpus.  The baseline is a signed artifact
containing analysis profiles for every AUR package, priors for novelty
detection, and a metadata snapshot for delta computation.

```
trustsight baseline build [--resume] [--export FILE]
trustsight baseline import FILE
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `build` | Bootstrap or incrementally update the corpus. Fetches the AUR metadata snapshot, diffs against the stored copy, processes changed packages, and stores results. The first run processes all packages; subsequent runs only process changed ones. Suitable for cron. |
| `import` | Import a signed baseline artifact. Verifies the signature, then merges profiles, priors, and the metadata snapshot into the local database. After import the database is warm. |

### Flags (`build`)

| Flag | Description |
|------|-------------|
| `--resume` | Resume an interrupted bootstrap. The bootstrap saves progress after each package. |
| `--export PATH` | Write the signed baseline artifact to this path. |
| `--sign PATH` | Path to an ed25519 private key to sign the artifact. |
| `--json` | Output JSON. |

### Flags (`import`)

| Flag | Description |
|------|-------------|
| `--allow-unsigned` | Import even if the artifact is unsigned. Use only for self-built local artifacts. |
| `--json` | Output JSON. |

---

## trustsight full-aur

Bootstrap or update the full-AUR baseline corpus. Fetches the AUR metadata snapshot, downloads PKGBUILDs via codeload (no git repos), analyses stateless rules, and optionally emits a signed baseline artifact.

```
trustsight full-aur [--bootstrap] [--resume] [--export PATH] [--sign PATH]
trustsight full-aur --watch [--interval SECONDS] [--cycles N]
```

### Flags

| Flag | Description |
|------|-------------|
| `--bootstrap` | Allow a from-scratch bootstrap of the whole AUR when there is no prior snapshot. Required to start one, because it fetches every PKGBUILD; without it a snapshot-less run refuses rather than scraping ~120k packages by accident. The bootstrap is capped per cycle and resumes automatically, so run the command repeatedly to finish it in gentle chunks. |
| `--resume` | Continue an interrupted cycle. Now implied: every cycle resumes automatically from its saved progress, so this flag is accepted but no longer needed. |
| `--export PATH` | Write the signed baseline artifact to this path. Only written when the cycle *completes* the current transition; a capped, still-pending cycle does not export a half-built corpus. |
| `--sign PATH` | Path to an ed25519 private key to sign the artifact. |
| `--watch` | Keep running cycles on an interval until interrupted. |
| `--interval SECONDS` | Seconds between `--watch` cycles. Defaults to `[limits] watch_interval` (3600) and is clamped to `[limits] watch_min_interval` (60). |
| `--cycles N` | Stop `--watch` after N cycles. `0`, the default, means run until interrupted. |
| `--json` | Output JSON. |

With a prior snapshot present (any `trustsight review` run creates one), a cycle processes only the changed packages, which is the intended cadence: run it periodically and the corpus grows incrementally. A from-scratch bootstrap is the exception, gated behind `--bootstrap`. Either way, each invocation is capped at `[limits] corpus_max_per_cycle` (default 2000) and resumes, so a large amount of work advances in bounded, resumable chunks rather than one avalanche.

Use `--export` to produce a shareable baseline that other TrustSight instances can consume via `trustsight import-baseline`.

### What one cycle does

1. Fetch the AUR metadata snapshot and diff it against the stored copy.
2. Download and analyse the PKGBUILDs of everything added or changed.
3. Run the Class D corpus sweep over the whole metadata delta, which returns one finding per cluster rather than one per member.
4. Record the cycle into the adoption feed that R125's introduction-rate baseline reads.
5. Report the packages that scored 40 or more this cycle, worst first.

The first cycle of a fresh install is a bootstrap: with no prior snapshot there is nothing to deviate from, so the corpus sweep is silent by construction.

### Progress and performance

A bootstrap analyses the whole AUR (tens of thousands of packages), and its cost is dominated by one PKGBUILD fetch per package. Two things make that bearable:

- **A progress bar.** When the output is an interactive terminal, the analysis loop renders a live bar on **stderr** with the current package, an `M/N` count, elapsed time and an ETA. It is on stderr so it never corrupts a `--export` artifact or a piped `--json` stream; a non-TTY (a cron job, a pipe, `--json`) falls back to a log line every 1000 packages.
- **Parallel fetching, rate-capped.** PKGBUILDs are fetched a window ahead, several at a time (`[limits] corpus_fetch_workers`, default 5). Analysis itself stays strictly serial and in package order, because novelty reads the observations earlier packages recorded; only the fetch is parallelised. The AUR's cgit rate-limits per IP and runs anti-scraping, so the fetcher enforces a **global aggregate rate cap** (~5 requests/second across all workers) and **backs off** on `429`, `5xx` and connection resets, honouring a `Retry-After` header. Raising the worker count past what the cap can keep busy only idles threads; the cap, not the worker count, is what keeps a 120k-package bootstrap from getting the IP blocked.

Benign per-package fetch fallbacks (a VCS or `-bin` package with no snapshot tarball falls back to a cgit text fetch) are logged at debug level, so they do not flood the bar; a genuine unfetchable PKGBUILD is counted and the total reported once at the end.

Even so, a full from-scratch bootstrap is roughly a hundred thousand rate-limited fetches, which takes hours and leans on a shared community host. Prefer to let the corpus grow **incrementally**: run `full-aur` (or `--watch`) periodically so each cycle fetches only the small metadata delta, and publish updated baselines over time rather than rebuilding the whole corpus at once.

### Watch mode

```
trustsight full-aur --watch --interval 1800
```

`--watch` repeats that cycle on an interval and adds memory. A cluster is announced the first time it is seen and counted afterwards, so a quiet night prints nothing instead of re-announcing the same forty-package adoption on every cycle. The record lives in the `alert_state` table, keyed by package and rule, with a first-seen timestamp and a count.

The interval floor exists because the AUR regenerates its metadata dump every few minutes: anything shorter re-downloads the same snapshot and re-walks the same diff. A mistyped `--interval 1` is raised to 60 rather than turned into a request loop against someone else's mirror.

Interrupting with Ctrl-C ends the loop, during a cycle or during the wait. Nothing is lost by stopping: each cycle writes its metadata snapshot and resume file before it returns, so the next run picks up from there.

`--watch` cannot be combined with `--export` or `--sign`. Those describe a single artifact, and pairing them with a loop would silently overwrite it every cycle; the command exits with status 2 instead.

---

## trustsight import-baseline

Import a signed baseline corpus artifact. Verifies the signature, then merges profiles, priors, and the metadata snapshot into the local database. After import the database is warm: no cold-start floor, real `stable_for_n` values, populated priors.

```
trustsight import-baseline <path>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `path` | Yes | Path to the baseline artifact (`.tar.zst`). |

### Flags

| Flag | Description |
|------|-------------|
| `--allow-unsigned` | Import even if the artifact is unsigned. Use only for self-built local artifacts. |
| `--json` | Output JSON. |

---

## trustsight ioc

Manage IOC federation baselines.  Baselines are signed or unsigned directories
containing `manifest.json` and `iocs.jsonl`; they supplement the local
`iocs.toml` used by R106.

```
trustsight ioc sources
trustsight ioc import <dir> [--source NAME] [--allow-unsigned]
trustsight ioc update [--path DIR]...
trustsight ioc list [--source SOURCE] [--type TYPE] [--include-expired]
trustsight ioc export [<dir>] [--source SOURCE] [--json]
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `sources` | Show configured and imported baseline sources. |
| `import` | Import a baseline directory. Replaces any existing rows for the same source. |
| `update` | Re-import baselines from local directories, or, when no `--path` is given, update every enabled feed whose `url` is a release-channel URL: the `baseline-ioc-<prefix>-manifest.json` / `-iocs.jsonl` pair is downloaded, verified against the pinned distribution key, and imported (curator-key verification still applies). Feeds with any other URL are refused. |
| `list` | List active IOC entries, optionally filtered by source or type. |
| `export` | Write the current IOC database to a baseline directory, or with `--json` and no directory, print the merged IOC view to stdout for debugging. |

### Flags

| Flag | Description |
|------|-------------|
| `--source` | Override or filter by baseline source name. |
| `--allow-unsigned` | Import a baseline whose signature is missing or cannot be verified. Use only for local baselines. |
| `--path` | Baseline directory to re-import with `ioc update`. Can be repeated. |
| `--type` | Filter `ioc list` by indicator type (`package`, `domain`, or `hash`). |
| `--include-expired` | Include expired entries in `ioc list`. |

---

## trustsight corpus pivot

Given one indicator, list every corpus package that references it. This inverts R106: instead of asking what a single package carries, it asks who points at a published indicator, which is the question an advisory creates.

```
trustsight corpus pivot <indicator> [--json]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `indicator` | Yes | A package name, domain, or artifact hash. The type is inferred from its shape. |

### Flags

| Flag | Description |
|------|-------------|
| `--type` | Force the indicator type (`package`, `domain`, or `hash`) when the shape is ambiguous: a package name spelled like a host, or a name that is all hex of digest length. |
| `--json` | Output JSON. |

### Behaviour

The match is exact: `evil.example` matches neither `notevil.example` nor `cdn.evil.example`, and a truncated digest matches nothing. The query does not have to appear in `iocs.toml`; when it does, the entry's provenance and confidence tier are reported with the result.

Only stored corpus material is searched: the AUR metadata snapshot (names, declared dependencies, upstream `url=`) and the stored PKGBUILD snapshots. Nothing a PKGBUILD points at is ever fetched. Package-name queries read the metadata only, because a name appearing in PKGBUILD text is not a declared fact.

The output names which stores were searched. An empty corpus reports that nothing was searched, never that nothing references the indicator. **A miss is uninformative:** the indicator list records what has already been reported, so it says nothing about a package it does not name.

---
