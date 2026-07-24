# Report Schema

The `PackageFact` dataclass (defined in `src/trustsight/schema.py`) is the core analysis result. It is serialised to JSON via `fact_to_dict()` (`src/trustsight/schema.py`) for database storage and display in `trustsight inspect` and `trustsight history --score-breakdown`.

---

## JSON structure

```json
{
  "package_name": "string",
  "old_version": "string",
  "new_version": "string",
  "old_commit": "string",
  "new_commit": "string",
  "maintainer_changed": bool,
  "previous_maintainer": "string",
  "current_maintainer": "string",
  "diff_summary": {
    "files_changed": ["string"],
    "lines_added": int,
    "lines_removed": int
  },
  "source_changes": {
    "added_urls": ["string"],
    "removed_urls": ["string"],
    "checksum_behavior": "string"
  },
  "source_buckets": {"url": "bucket"},
  "execution_changes": {
    "resolved_commands": ["string"],
    "suspicious_patterns_detected": ["string"],
    "unresolved_patterns": ["string"]
  },
  "novelty_context": {
    "url_first_seen_in_this_package": bool,
    "url_first_seen_globally": bool,
    "maintainer_first_seen_for_this_package": bool
  },
  "score_breakdown": [
    {
      "rule_id": "string",
      "severity": "string",
      "weight": int,
      "reason": "string"
    }
  ],
  "first_seen": bool,
  "suppressed_rules": [
    {
      "rule_id": "string",
      "severity": "string",
      "override_reason": "string",
      "override_package": "string or null"
    }
  ],
  "final_score": int
}
```

---

## Field descriptions

### Top-level

| Field | Type | Description |
|-------|------|-------------|
| `package_name` | `string` | AUR package name. |
| `old_version` | `string` | Previously analysed version. Empty string on first analysis (no prior commit). |
| `new_version` | `string` | Version at HEAD of the AUR repository. |
| `old_commit` | `string` | Git commit SHA of the previously analysed version. Empty string on first analysis. |
| `new_commit` | `string` | Git commit SHA of the HEAD version. |
| `maintainer_changed` | `bool` | `true` if the committer/author changed between old and new commits (both known). |
| `previous_maintainer` | `string` | Committer name for the old commit, or empty string. |
| `current_maintainer` | `string` | Committer name for the HEAD commit. |
| `first_seen` | `bool` | `true` if this is the first analysis for this package (no prior commit to diff against). |
| `suppressed_rules` | `list[dict]` | Rules suppressed by user override. Each entry has `rule_id`, `severity`, `override_reason`, and `override_package`. These did not contribute to the score. |
| `final_score` | `int` | Deterministic risk score, 0-100. Computed by `calculate_score()` in `src/trustsight/scoring.py`. |

### `diff_summary`

| Field | Type | Description |
|-------|------|-------------|
| `files_changed` | `list[string]` | File paths touched in the diff (filtered to `PKGBUILD`, `.SRCINFO`, `*.install`). |
| `lines_added` | `int` | Total insertion count from `pygit2.Diff.stats.insertions`. |
| `lines_removed` | `int` | Total deletion count from `pygit2.Diff.stats.deletions`. |

Extracted by `generate_diff()` in `src/trustsight/differ.py`.

### `source_changes`

| Field | Type | Description |
|-------|------|-------------|
| `added_urls` | `list[string]` | HTTP/HTTPS URLs found on diff lines starting with `+`. |
| `removed_urls` | `list[string]` | HTTP/HTTPS URLs found on diff lines starting with `-`. |
| `checksum_behavior` | `string` | One of: `"unchanged"`, `"changed_from_sha256_to_skip"`, `"checksum_array_emptied"`, `"checksum_added_or_changed"`. Detected by `detect_checksum_changes()` in `src/trustsight/differ.py`. |

### `source_buckets`

| Field | Type | Description |
|-------|------|-------------|
| `<url>` | `string` | Each added URL maps to its bucket classification: `"trusted_forge"`, `"official"`, `"self_hosted"`, `"raw_hosting"`, `"unknown"`, or `"homograph_attack"`. |

Classified by `classify_urls()` in `src/trustsight/buckets.py`.

### `execution_changes`

| Field | Type | Description |
|-------|------|-------------|
| `resolved_commands` | `list[string]` | Fully resolved command strings after tokenization and variable expansion. Each is a single command extracted from the diff. |
| `suspicious_patterns_detected` | `list[string]` | Rule IDs (`R001`-`R013`, `R039`-`R059`, `C001`-`C007`) that fired during analysis. |
| `unresolved_patterns` | `list[string]` | Source strings that the tokenizer could not fully resolve (e.g. interpolated variables, computed URLs). These produce INCONCLUSIVE outcomes per-url. |

Resolution performed by `tokenize_and_resolve()` in `src/trustsight/tokenizer.py`.

### `novelty_context`

| Field | Type | Description |
|-------|------|-------------|
| `url_first_seen_in_this_package` | `bool` | `true` if at least one added URL has never been seen before for this package (after URL normalisation). |
| `url_first_seen_globally` | `bool` | `true` if at least one added URL has never been seen before in any package in the corpus (after URL normalisation). |
| `maintainer_first_seen_for_this_package` | `bool` | `true` if the current maintainer has never been recorded for this package before. |

**Note:** The `NoveltyContext` dataclass also carries `observation_count` (int), but this field is **not** serialised in `fact_to_dict()`. It is used internally by `calculate_score()` for the maturity multiplier.

Novelty built by `build_novelty_context()` in `src/trustsight/novelty.py`.

### `score_breakdown`

Each entry:

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | `string` | Rule or category identifier: `R001`-`R013`, `R039`-`R059`, `C001`-`C007`, `SOURCE_BUCKET`, `NOVELTY`, `PINNING`, `VERIFICATION`. |
| `severity` | `string` | `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `weight` | `int` | Signed integer contribution. Positive = risk increase. Negative = risk decrease. |
| `reason` | `string` | Human-readable explanation of why this entry fired. Truncated to 80 characters in CLI display; full string in JSON. |

The sum of all `weight` values, floored at 0 and capped at 100, equals `final_score`. FATAL rules short-circuit: if any entry has severity `"FATAL"`, the score is 100 regardless of other entries.

---

## Database storage

The `PackageFact` JSON is stored in the `analyses` table under the `fact_json` column (TEXT, JSON). Triggered rules are stored in a separate `triggered_rules` table keyed by analysis ID. See `insert_analysis()` in `src/trustsight/analysis.py`.
