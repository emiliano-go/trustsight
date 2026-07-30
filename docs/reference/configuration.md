# Configuration Reference

## File locations

| Path | Purpose |
|------|---------|
| `~/.config/trustsight/config.toml` | Main configuration (weights, limits). |
| `~/.config/trustsight/rules.toml` | R-series rule definitions (R001-R013 core; R039+ are code-emitted). |
| `~/.config/trustsight/trusted_domains.toml` | Domain classification lists for source bucket assignment. |
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
| `trusted_forge` | int | `-10` | Subtracted per URL from well-known forges (github.com, gitlab.com, etc.). Capped at -20 total across all URLs. |
| `official` | int | `0` | Official project domains (kernel.org, python.org, etc.). No score change. |
| `self_hosted` | int | `10` | Domain controlled by the maintainer. |
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

### `[verification_evidence]`

Subtractions (negative modifiers) for structural integrity protections present in the resolved PKGBUILD. Computed over the post-diff end-state, not the delta.

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `checksum_present` | int | `-10` | Post-diff PKGBUILD has a non-empty checksum array. |
| `validpgpkeys_declared` | int | `-10` | Post-diff PKGBUILD declares PGP key fingerprints. |
| `gpg_verify_present` | int | `-5` | Post-diff PKGBUILD runs `gpg --verify` or equivalent. |

### `[pinning_weights]`

Subtractions for source pinning levels. Only the weakest (worst) pinning level across all added URLs is used.

| Key | Type | Default | Effect |
|-----|------|---------|--------|
| `checksum_pinned` | int | `-5` | URL covered by a valid sha256 checksum. |
| `tag_pinned` | int | `-3` | URL references a tag or version (immutable ref). |
| `branch_pinned` | int | `0` | URL references a mutable branch. |
| `unpinned` | int | `0` | None of the above. |

Pinning classification via `classify_pinning_level()` in `src/trustsight/buckets.py`.

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

### `[experimental_rules]`

Rules emitted from code rather than `rules.toml`, so the `experimental` flag above cannot reach them. All default to `true` since v0.7.0 after corpus calibration; see [Fire Rates](../explanation/fire-rates.md).

A config written before this section existed still gets these defaults: `load_config()` reads the file verbatim without merging defaults, so the fallbacks live in code (`_EXPERIMENTAL_DEFAULTS` in `src/trustsight/analysis/base.py`). Setting a key here always overrides them.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `D001` | bool | `true` | Fire when a dependency name is added that has never been observed anywhere in the AUR. Requires a seeded `dependency_names` table; with no seed the rule stays silent rather than flagging everything. |
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
| `auto_import` | bool | `true` | Import the bundled novelty seed the first time TrustSight runs against a database that has neither a seed nor any analysis history. See [`trustsight seed-db`](cli.md#trustsight-seed-db). |

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

### `[discovery]`

Controls which packages are scanned when no `--repo`/`--foreign`/`--all-repos` flags are given on the command line. See [CLI Reference](cli.md#trustsight-review) for the full precedence rules.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_repos` | array of strings | `[]` | List of repository names to scan by default when no CLI flags are given. |
| `include_foreign` | bool | `false` | Whether to also include foreign packages (`pacman -Qm`) when `default_repos` is non-empty or `all_repos` is true. When all defaults are empty/false, foreign packages are scanned as a fallback. |
| `all_repos` | bool | `false` | If true, automatically detect all local repositories from `/etc/pacman.conf` (excluding official repos) and use them as the default scope. `default_repos` are added to the auto-detected list. |

If none of these settings are explicitly configured, the tool scans foreign packages only (backward-compatible default).

### `[limits]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_review_limit` | int | `20` | Default `--limit` for `trustsight review` when not explicitly provided. |

---

## Default configuration

The full default config is embedded in `src/trustsight/config.py` as `DEFAULT_CONFIG` and written to `~/.config/trustsight/config.toml` on first invocation. Users may edit it freely.
