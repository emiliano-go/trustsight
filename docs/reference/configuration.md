# Configuration Reference

## File locations

| Path | Purpose |
|------|---------|
| `~/.config/trustsight/config.toml` | Main configuration (weights, LLM, limits). |
| `~/.config/trustsight/rules.toml` | R-series rule definitions (R001-R013). |
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

### `[llm]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `provider` | string | `"openai"` | LLM provider: `"openai"` or `"ollama"`. |
| `model` | string | `"gpt-4o-mini"` | Model name passed to the OpenAI-compatible API. |
| `enabled` | bool | `true` | Set to `false` to skip LLM verdict generation entirely (always uses fallback template). |
| `max_tokens` | int | `1024` | Maximum tokens in the LLM response. |
| `temperature` | float | `0.3` | Sampling temperature. |
| `top_p` | float | `1` | Nucleus sampling parameter. |
| `seed` | int | `42` | Random seed for deterministic LLM output (provider-dependent). |

#### `[llm.openai]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `api_key` | string | `""` | OpenAI API key. Can also be set via `TRUSTSIGHT_API_KEY` environment variable (takes precedence). |
| `base_url` | string | `"https://api.openai.com/v1"` | Base URL for the OpenAI-compatible API. Can also be set via `TRUSTSIGHT_BASE_URL` environment variable (takes precedence). |

#### `[llm.ollama]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | string | `"http://localhost:11434/v1"` | Ollama server URL. |

### `[rules]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `experimental` | bool | `false` | Run rules marked `experimental = true` in `rules.toml`. The R039 to R059 set is calibrated and runs unconditionally; this gates future additions whose false-positive rate has not been measured. |

### `[seed]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auto_import` | bool | `true` | Import the bundled novelty seed the first time TrustSight runs against a database that has neither a seed nor any analysis history. See [`trustsight seed-db`](cli.md#trustsight-seed-db). |

### `[deep]`

!!! note "Reserved, not implemented"

    These keys are written to the default config but no code reads them.
    Setting them has no effect.

Deep analysis mode : gates LLM-assisted analysis for scores above threshold.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable deep analysis mode. |
| `threshold` | int | `80` | Minimum score to trigger deep analysis. |

### `[diff]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_context_lines` | int | `3` | Number of context lines in git diffs passed to `pygit2.Diff`. |
| `max_diff_chars_for_llm` | int | `2000` | Maximum characters of the prompt sent to the LLM. Truncated from the start. |

### `[limits]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_review_limit` | int | `20` | Default `--limit` for `trustsight review` when not explicitly provided. |

---

## Environment variables

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `TRUSTSIGHT_API_KEY` | `llm.openai.api_key` | API key for OpenAI-compatible LLM provider. Takes precedence over the config file value. |
| `TRUSTSIGHT_BASE_URL` | `llm.openai.base_url` / `llm.ollama.url` | Base URL for the LLM API. Takes precedence over the config file value. |

Read at `src/trustsight/llm.py` and `src/trustsight/llm.py`.

---

## Default configuration

The full default config is embedded in `src/trustsight/config.py` as `DEFAULT_CONFIG` and written to `~/.config/trustsight/config.toml` on first invocation. Users may edit it freely.
