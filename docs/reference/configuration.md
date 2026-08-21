# Configuration Reference

## File locations

| Path | Purpose |
|------|---------|
| `~/.config/trustsight/config.toml` | Main configuration (weights, limits). |
| `~/.config/trustsight/rules.toml` | Definitions for the TOML-defined R-series subset. Per-rule `enabled` and `weight_override` controls live in `config.toml`. |
| `~/.config/trustsight/trusted_domains.toml` | Domain classification lists for source bucket assignment. |
| `~/.config/trustsight/iocs.toml` | R106 indicator list: confirmed-malicious package names, domains, and artifact hashes, each with provenance and a confidence tier. Ships empty. |
| `~/.cache/trustsight/repos/` | Cloned AUR package repositories (bare git repos). |
| `~/.local/share/trustsight/` | SQLite database (analysis history, source URL tracking, maintainer tracking). |

All directories and default files are created on first run by `ensure_default_configs()` in `src/trustsight/config.py`.

---

## config.toml

TOML file at `~/.config/trustsight/config.toml`.

### `[severity_weights]`

Map each severity level to its numeric contribution to the base score. FATAL rules short-circuit to score 100 regardless of weight.

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `FATAL` | int | `0` | Hard-stop score at 100; weight not used. |
| `CRITICAL` | int | `40` | Added to score for each CRITICAL rule fired. |
| `HIGH` | int | `25` | Added to score for each HIGH rule fired. |
| `MEDIUM` | int | `15` | Added to score for each MEDIUM rule fired. |
| `LOW` | int | `5` | Added to score for each LOW rule fired. |
| `INFO` | int | `0` | Informational only; no score effect. |

### `[source_bucket_weights]`

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `trusted_forge` | int | `0` | Well-known forges (github.com, gitlab.com, etc.). Neutral: hosting on a forge is a declared fact reported as `P007`, never a credit (B10). |
| `official` | int | `0` | Official project domains (kernel.org, python.org, etc.). No score change. |
| `raw_hosting` | int | `15` | Raw/paste hosting (raw.githubusercontent.com, pastebin.com, etc.). |
| `unknown` | int | `20` | Domain not in any allowlist. |
| `homograph_attack` | int | `30` | Domain contains visually confusable non-ASCII characters (Cyrillic homoglyphs, etc.). |

URLs in the diff are classified by `classify_url()` in `src/trustsight/buckets.py`.

### `[novelty_weights]`

Raw weights for Tier C novelty signals. These are multiplied by the maturity multiplier (`observation_count / 50`, capped at 1.0) before being added to the score.

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `url_first_in_package` | int | `5` | Raw weight for a URL never seen before in this package's history. |
| `url_first_globally` | int | `10` | Raw weight for a URL never seen before in any package in the corpus. |
| `maintainer_first_in_package` | int | `15` | Raw weight for a maintainer never seen before for this package. |

### `[review]`

Controls the review workload, not score arithmetic or risk bands. A report is
`flagged` when its score is above the selected profile's threshold. JSON records
the profile, effective threshold, and flag; the configuration fingerprint covers
the selected policy too.

| Profile | Default threshold | Intended use |
|---------|-------------------|--------------|
| `default` | `20` | Historical behavior; about 13.1% of locked benign-corpus diffs enter the review queue. |
| `quiet` | `40` | Smaller queue; it does not claim the same labelled-fixture coverage as `default`. |
| `strict` | `10` | Broader queue for operators who prefer sensitivity over review volume. |

```toml
[review]
profile = "quiet"

## Optional local changes to the three published workload choices.
[review.profiles]
quiet = 45
```

Only `default`, `quiet`, and `strict` are accepted. Thresholds must be integers
from 0 through 100. Changing a profile does not change a score, risk band, or
calibration result; it changes only the reports marked for review.

### Removed: `[verification_evidence]` and `[pinning_weights]`

Both sections applied negative weights for declared checksums, PGP keys, GPG
verification and source pinning. They are gone, and setting them in a local
`config.toml` now does nothing.

Everything TrustSight sees is attacker-declared, and TrustSight never fetches,
so it never confirms that a declared key signs anything or that a pinned commit
holds what it claims. A signal an attacker can assert for free must not be able
to lower a score. These facts are now reported as weight-0 declared-practice
findings in the `P` namespace (`P001`-`P007`); see
[the security model](../security.md#b10-positive-evidence-is-reported-never-credited).

Pinning classification via `classify_pinning_level()` in
`src/trustsight/buckets.py` still runs; it decides which `P` finding is
emitted, not a score.

### `[ports]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `standard` | array of ints | `[80, 443, 8080, 8443]` | Ports excluded from R047 (non-standard port detection). Add custom standard ports to suppress false positives. |

### `[domains]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `free_registrar_tlds` | array of strings | `["tk", "ml", "ga", "cf", "gq", "pw"]` | TLDs flagged by R048 (source URL on free registrar TLD). Update this list as new free TLDs appear. |

### `[tools]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `network_makedepends` | array of strings | `["curl", "wget", "aria2", "git", ...]` | Package names that D003 treats as network-accessible makedepends. |

### `[rules]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `experimental` | bool | `false` | Run rules marked `experimental = true` in `rules.toml`. The R039 to R059 set is calibrated and runs unconditionally; this gates future additions whose false-positive rate has not been measured. |

#### `[rules.R###]`

Per-rule controls belong in `config.toml`, keyed by the rule ID:

```toml
[rules.R007]
enabled = false
weight_override = 15
```

`enabled` and `weight_override` apply only to rules defined in `rules.toml` and
only have an effective scoring use for non-FATAL rules. A FATAL rule cannot be
disabled and always hard-stops the score at 100. Code-emitted rules have no TOML
definition, so `[rules.R###]` does not affect them; use their documented
dedicated settings where available, such as `[experimental_rules]`.

### `[experimental_rules]`

Rules emitted from code rather than `rules.toml`, so the `experimental` flag above cannot reach them. All default to `true` since v0.7.0 after corpus calibration; see [Fire Rates](../explanation/fire-rates.md).

A config written before this section existed still gets these defaults: `load_config()` reads the file verbatim without merging defaults, so the fallbacks live in code (`_EXPERIMENTAL_DEFAULTS` in `src/trustsight/analysis/base.py`). Setting a key here always overrides them.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `D001` | bool | `true` | Optional corpus-context signal: fire when a dependency name is added that has never been observed anywhere in the AUR. Requires a seeded `dependency_names` table; with no seed the rule stays silent rather than flagging everything. This avoids measuring an empty database rather than an unusual dependency. |
| `D002` | bool | `true` | Fire when a novel dependency name is within one or two edits of a popular one (`openss1` for `openssl`). Refines D001: a name is only compared once D001 has found it globally unknown. |
| `D003` | bool | `true` | Fire when `makedepends` gains a network-capable tool (`curl`, `git`, `python-requests`, …), meaning the build can now fetch code that no checksum covers. |
| `R060` | bool | `true` | Report that the diff modifies `build()`, `prepare()`, `check()`, or `package()`. INFO severity, so it carries weight 0 and cannot move a score: it fires on 21.4% of benign diffs and exists as reviewer context. On by default for that reason. |
| `D004` | bool | `true` | Fire when `provides`/`replaces` claims an established package unrelated to this one, which installs it in front of the real thing. Variants and siblings (`htop-vim` providing `htop`, `linux-cachyos` providing `linux-headers`) do not fire. |
| `R061` | bool | `true` | Fire when a download inside a build function targets a URL absent from `source=()`. |
| `R062` | bool | `true` | Fire when a `.install` hook body fetches over the network or performs a privileged operation (`chmod u+s`, `systemctl enable`, `eval`). Hooks run as root. |
| `R063` | bool | `true` | Fire when a patch is applied from outside the build tree: a URL, an absolute path, or process substitution. Does *not* check `source=()` membership, since patches legitimately arrive inside the extracted tarball. |
| `R064` | bool | `true` | Fire when a `source=` URL is downgraded from `https://` to `http://`. |

### `[seed]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auto_import` | bool | `true` | On an eligible first CLI `review` or `inspect`, optionally import the novelty seed when the database has neither a seed nor analysis history. The seed lives on the release channel as `baseline-seed.tar.gz`; the fetch verifies it and skips silently when offline or verification fails. Set this to `false` to use structural detection without seeded context. Other commands do not fetch it automatically. See [`trustsight seed-db`](cli.md#trustsight-seed-db). |

### `[baselines]`

Container for optional federated baseline sources. Currently only the IOC
baseline stage is implemented. Baselines add attributed context; they never
replace local structural detection or alter rules, weights, or thresholds.

#### `[baselines.ioc]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Run the IOC baseline match stage during analysis. |
| `sources` | array of strings | `[]` | Baseline source names to consult. An empty list means "all imported sources". |

#### `[[baselines.ioc.feeds]]`

Configured feed entries for `trustsight ioc update`.  TrustSight ships with
no default feeds; operators add trusted sources here.  A feed whose `url`
names the TrustSight [release channel](baseline-keys.md#the-release-channel)
is updated automatically: `ioc update` downloads the pair
`baseline-ioc-<prefix>-manifest.json` and `baseline-ioc-<prefix>-iocs.jsonl`
(plus their detached signatures), verifies both against the pinned
distribution key, then imports with the curator-key check the normal
`ioc import` path performs.  Any other `url` is refused with an explicit
"not implemented" error; there is no scheme in which an unverified remote
baseline is imported.

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Feed identifier (a `[a-z0-9.-]` slug by default, or set `asset`). |
| `url` | string | Feed URL.  Release-channel URLs (`https://github.com/emiliano-go/trustsight/releases`) trigger verified updates. |
| `asset` | string | Optional asset prefix override.  Defaults to `name`; the assets fetched are `baseline-ioc-<prefix>-manifest.json` and `baseline-ioc-<prefix>-iocs.jsonl`. |
| `enabled` | bool | Whether the feed is active. |

### `[depth]`

```toml
[depth]
levels = 1
```

How far into a package's AUR dependency closure to analyse. `0` disables it,
`1` (the default) analyses direct AUR dependencies, `n` analyses `n` levels,
and `-1` walks every level there is.

`-1` is bounded, and it has to be: the dependency graph is written by the
party under review, so an unbounded walk would let a crafted recipe decide
how many repositories this machine clones. The ceilings are
`depth.MAX_DEPTH_LEVELS` (8) and `depth.MAX_DEPTH_NODES` (200 dependencies
per run), and a walk cut short by either records the `deps_not_scanned`
coverage gap. A walk that *completed* is not a gap: asking for depth 1 and
getting depth 1 answers the question that was asked.

Each dependency is analysed exactly as a package - its own score, its own
band, its own row in the database. Nothing is folded into the parent's score,
because `depth` is deliberately absent from the config fingerprint and a
score that moved with `--depth` would break
[B1](../security.md#b1-a-score-is-a-sum-of-matched-evidence-nothing-more)
for anyone comparing two runs.

Overridden per run by `--depth`.

### `[deep]`

!!! note "Reserved, not implemented"

    These keys are written to the default config but no code reads them.
    Setting them has no effect.

Deep analysis mode: reserved.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable deep analysis mode. |
| `threshold` | int | `80` | Minimum score to trigger deep analysis. |

### `[diff]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_context_lines` | int | `3` | Number of context lines in git diffs passed to `pygit2.Diff`. |
| `max_diff_bytes` | int | `5242880` | Maximum UTF-8 byte prefix analysed from one diff (5 MiB). A larger diff sets `diff_truncated` and the `diff_truncated` coverage gap; the score describes only that prefix. This is independent of the `rules.MAX_SCANNED_LINES` line cap, which can set `scan_truncated` even when the byte cap was not reached. |

### `[discovery]`

Controls which packages are scanned when no `--repo`/`--foreign`/`--all-repos` flags are given on the command line. See [CLI Reference](cli.md#trustsight-review) for the full precedence rules.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_repos` | array of strings | `[]` | List of repository names to scan by default when no CLI flags are given. |
| `include_foreign` | bool | `false` | Whether to also include foreign packages (`pacman -Qm`) when `default_repos` is non-empty or `all_repos` is true. When all defaults are empty/false, foreign packages are scanned as a fallback. |
| `all_repos` | bool | `false` | If true, automatically detect all local repositories from `/etc/pacman.conf` (excluding official repos) and use them as the default scope. `default_repos` are added to the auto-detected list. |
| `show_unmatched` | bool | `true` | With `--all`, include installed packages that are absent from the AUR metadata snapshot (orphaned, very new, removed from the AUR). Set to false to skip them. |
| `cache_ttl_minutes` | int | `60` | Minutes an AUR RPC response is cached for. Applies to the RPC fallback path, not to the metadata snapshot. `0` disables the cache. |
| `metadata_ttl_minutes` | int | `60` | Minutes the offline AUR metadata snapshot is used before `review` refetches it (~60 MB). A snapshot past this age would report every installed package as current, so refreshing it is what keeps "no outdated packages" a fact rather than an artefact of age. `0` never refreshes automatically: comparisons stay as current as the snapshot on disk, which is the right setting only for an offline machine. If the refresh fails, the old snapshot is used and `review` warns that a newer package may go unreported. |

If none of these settings are explicitly configured, the tool scans foreign packages only (backward-compatible default).

### `[limits]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_review_limit` | int | `0` | How many packages `trustsight review` reads when `--limit` is not given. `0` means all of them, which is the default because a review that stops early has not looked at the rest. Any other value is honoured, and the packages left unread are named in the summary rather than dropped quietly. An explicit `--limit 0` always wins over this. Before 0.13.2 the key shipped as `20` and was never read: the flag's own default won every time, so setting it did nothing. |
| `network_connect_timeout` | int | `10` | Seconds libgit2 may spend connecting to the AUR before aborting a clone/fetch. |
| `network_transfer_timeout` | int | `30` | Seconds libgit2 may wait for data on an established connection. Without it a silently stalled connection hangs a fetch indefinitely. |
| `prefetch_timeout` | int | `120` | Seconds `trustsight review` waits for the whole prefetch batch. Whatever has not arrived is abandoned and fetched again during analysis. |
| `watch_interval` | int | `3600` | Seconds between cycles of `trustsight full-aur --watch`. |
| `watch_min_interval` | int | `60` | Floor applied to `--interval`. The AUR regenerates its metadata dump every few minutes, so a shorter interval only re-downloads the same snapshot. |
| `corpus_fetch_workers` | int | `5` | How many PKGBUILD fetches `trustsight full-aur` runs concurrently during a corpus build. Analysis stays serial and ordered; only the network fetch is parallelised. Not written to the shipped config, but honoured if you add it. A global aggregate rate cap in the fetcher (~5 requests/second) is the real limiter, because the AUR's cgit rate-limits per IP and now runs anti-scraping; raising this past what the cap can keep busy only idles threads. |
| `corpus_max_per_cycle` | int | `2000` | Maximum packages `trustsight full-aur` processes per invocation. A larger delta, or a bootstrap, advances in bounded, resumable chunks: the cycle stops after this many, saves progress, and the next run continues. Set to `0` to disable the cap and process the whole delta in one run. Not written to the shipped config, but honoured if you add it. |

---

## The pattern and threshold files

`config.toml` holds weights and limits. The lists a rule matches against live
in sibling files, so a rule can be retuned without touching code. Each is
written on first run and never rewritten, so an edited file is always kept.

### `hosts.toml`

| Key | Rules | Contents |
|-----|-------|----------|
| `paste_hosts` | R087, source buckets | Paste and ephemeral file-drop hosts. As `source=` URLs they are weighted by the `raw_hosting` bucket; as upload destinations inside a function they are R087's. |
| `standard_ports` | R047 | Ports a build may legitimately contact. |
| `free_registrar_tlds` | R048 | TLDs available at no cost, where a throwaway domain is cheap. |
| `source_schemes` | R080 | Allowlisted `source=` schemes. The base of a `transport+base` token is judged, so `git+https` reads as `https`. |
| `confusable_domains` | R013b | Popular domains a homoglyph label is tested against. A mixed-script label that resembles none of them stays quiet. |
| `covert_egress_endpoints` | R123 | DNS-over-HTTPS endpoints. |
| `covert_egress_clients` | R123 | Tunnelling and proxy clients, matched only at a command position. |

For the overlapping settings, `hosts.toml` has precedence: `standard_ports`
overrides `[ports] standard`, and `free_registrar_tlds` overrides `[domains]
free_registrar_tlds`. An empty sibling list falls back to the corresponding
`config.toml` value and then the shipped default. The other host lists are read
directly by their named rules; they do not merge with a generic host setting.

### `patterns.toml`

| Key | Rules | Contents |
|-----|-------|----------|
| `foreign_pkg_managers` | R081 | Package managers that are not pacman. |
| `obfuscation_indicators` | R082 | Per-line obfuscation markers, counted against a density threshold. |
| `anti_analysis_probes` | R119 | Debugger, VM, sandbox and CI probes. |
| `recon_commands` | R086 | Host-profiling commands, command-position anchored. |
| `parse_time_fetch` | R129 | Network clients whose invocation outside every function runs when the recipe is sourced. |
| `upload_flags` | R087 | `curl`/`wget` flags that send a request body, which is what separates an upload from a download. |
| `network_tools` | D003 | Package names that grant a build network access. |
| `security_relevant_flags` | R094, R131 | Hardening flags whose appearance or disappearance changes the mitigation set. |
| `security_relevant_libraries` | R095 | Libraries whose vendoring bypasses distribution security updates. |

These lists are consumed directly by their named rules. `network_tools` is the
exception with a legacy fallback: D003 reads `patterns.toml` first, then
`[tools] network_makedepends` in `config.toml`, then the shipped default. There
is no general precedence rule across sibling files.

### `naming.toml`

Ecosystem prefixes (D004, R116) and variant suffixes (D002, R074, R100, R101).
These decide when two package names belong to the same project, which is what
keeps a package claiming its own project's names from firing a scope-expansion
rule.

### `thresholds.toml`

| Key | Rule | Default | Meaning |
|-----|------|---------|---------|
| `r082.obfuscation_density` | R082 | `3` | Distinct obfuscation indicators on one line before it is reported. |
| `r089.attack_chain_stages` | R089 | `3` | Distinct kill-chain stages that must co-occur. |
| `r092.min_packages` / `r092.window_days` | R092 | `10` / `7` | Cluster size and window for mass adoption. |
| `r100.min_packages` | R100 | `3` | Unrelated packages that must share a source repository. |
| `r105.min_packages` / `r105.window_hours` | R105 | `5` / `24` | Cluster size and window for an attribute burst. |
| `r107.min_hops` / `r111.min_hops` | R107, R111 | `2` | Hops that make an exposure transitive rather than direct, keeping both out of R093's lane. |
| `r108.min_history_cycles` / `r108.z_score` / `r108.min_activity` | R108 | `3` / `2.0` / `3` | Baseline length, deviation and floor for maintainer activity. |
| `r112.min_dependents` | R112 | `50` | Dependents that make a package a hub. |
| `r125.min_history_cycles` / `r125.z_score` / `r125.min_introduced` | R125 | `3` / `3.0` / `3` | Baseline length, deviation and floor for the corpus introduction rate. |
| `r116.widely_provided_observations` | R116 | `25` | Observations that make a provided name widely provided. |
| `r126.window_days` | R126 | `14` | How recent the modification must be after an adoption. |
| `longitudinal.stability_floor` | Class C | `10` | Consecutive observations a property must hold before a change is reported at all. |

### `iocs.toml`

`[meta] version` plus `[[entries]]` of `type` (`package`, `domain` or `hash`),
`value`, `confidence`, `provenance`, `campaign` and `added`. The confidence
tier decides severity: `confirmed` is FATAL, `high` is CRITICAL, `medium` is
HIGH. The shipped file is empty, and a miss is uninformative.

---

## Default configuration

The full default config is embedded in `src/trustsight/config.py` as `DEFAULT_CONFIG` and written to `~/.config/trustsight/config.toml` on first invocation. Users may edit it freely.
