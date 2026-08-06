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
      "reason": "string",
      "template": "string",
      "evidence": {},
      "file": "string",
      "line": int
    }
  ],
  "first_seen": bool,
  "recent_commit_burst": bool,
  "diff_truncated": bool,
  "tree_analyzed": bool,
  "coverage_gaps": ["string"],
  "unresolved_sources": ["string"],
  "risk": "string",
  "adapter": "string",
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
| `recent_commit_burst` | `bool` | `true` when the package's recent commit timestamps cluster unusually tightly. |
| `diff_truncated` | `bool` | `true` when the diff exceeded `[diff] max_diff_bytes` and only its prefix was examined. The score then describes a prefix, not the change. |
| `tree_analyzed` | `bool` | `true` when the repository file manifest was inspected for R118-tree. A result produced without the tree reports `false`. |
| `coverage_gaps` | `list[string]` | What this run could not examine, as `"diff_truncated"`, `"line_truncated"`, `"tree_not_analyzed"` and `"unresolved_source"`. A non-empty list forbids an UNFLAGGED verdict: `risk` is `"Inconclusive"` unless a HIGH or worse finding fired, and in that case the band is shown qualified. Enforced by `coverage.fail_closed` and `coverage.qualified_band`; see [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete). |
| `unresolved_sources` | `list[string]` | The `source=` lines behind an `unresolved_source` gap, quoted so the reviewer can see what could not be resolved. |
| `risk` | `string` | The verdict band: `"Low"`, `"Medium"`, `"High"`, `"Critical"` or `"Inconclusive"`. **Not** always derivable from `final_score`: a cold database or a coverage gap downgrades it. Read this field; do not recompute it from the score. Read it **with** `coverage_gaps`: a band alone does not say whether the whole change was examined. |
| `adapter` | `string` | Which fetch path produced the analysis: `"git"` or `"corpus"`. |
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
| `suspicious_patterns_detected` | `list[string]` | Rule IDs (`R001`-`R013`, `R039`-`R082`, `C001`-`C007`, `D001`-`D004`) that fired during analysis. |
| `unresolved_patterns` | `list[string]` | Strings anywhere in the diff that the tokenizer could not fully resolve. Diagnostic only: nothing reads this field to decide a verdict. The subset that affects a verdict is the `source=` case, reported as the `unresolved_source` coverage gap and quoted in `unresolved_sources`. |

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
| `rule_id` | `string` | Rule or category identifier: `R001`-`R013`, `R039`-`R131`, `C001`-`C007`, `D001`-`D004`, `SOURCE_BUCKET`, `NOVELTY`, `PINNING`, `VERIFICATION`, `COVERAGE`. |
| `severity` | `string` | `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `weight` | `int` | Signed integer contribution. Positive = risk increase. Negative = risk decrease. |
| `reason` | `string` | Human-readable explanation of why this entry fired. Truncated to 80 characters in CLI display; full string in JSON. |
| `template` | `string` | The render string for this finding, with `{placeholders}` filled from `evidence`. Output is rendered from the template, so a finding says the same thing everywhere it appears. |
| `evidence` | `dict` | The declared facts that triggered the rule, plus the raw matched text as `match`. This is what the finding is *about*, as opposed to prose describing it. |
| `file` | `string` | The file the finding is in: `PKGBUILD`, `.SRCINFO`, `<name>.install`, or another path. |
| `line` | `int` or `null` | The 1-based line the finding anchors to. Explicitly `null`, never omitted, for findings that legitimately have no line: maintainer, graph, temporal and corpus rules, and a standing indicator match that is not in the current hunk. |

### The finding contract

Every rule emits a finding, never a judgement. A finding names a rule, a
location, a template, and the evidence that satisfied it; the verdict layer
renders from the template rather than from ad-hoc prose, which is what keeps
the wording of a rule in one place. Neutral facts are reported the same way
(new files, dependency additions, version bumps), at weight 0, so that "nothing
scored" and "nothing happened" stay distinguishable.

The sum of all `weight` values, floored at 0 and capped at 100, equals `final_score`. FATAL rules short-circuit: if any entry has severity `"FATAL"`, the score is 100 regardless of other entries.

---

## Database storage

The `PackageFact` JSON is stored in the `analyses` table under the `fact_json` column (TEXT, JSON). Triggered rules are stored in a separate `triggered_rules` table keyed by analysis ID. See `insert_analysis()` in `src/trustsight/analysis/pipeline.py`.

---

## The two serializers

There are two JSON shapes, and they are not the same object.

- `schema.fact_to_dict()` produces the stored `PackageFact`, documented above.
  It is what goes into `fact_json` and into an exported baseline.
- The CLI's report JSON (`trustsight review --json`, `trustsight inspect
  --json`) is a presentation view of the same analysis. It carries `package`,
  `score`, `risk`, `verdict`, `findings`, `file_changes`, `is_trivial`,
  `aur_note`, and `version_comparison`.

`version_comparison` is the one field worth knowing about by name. It records
how the installed version relates to the AUR's declared `pkgver`, as one of
`aur_ahead`, `no_aur_change`, `installed_ahead` or `inconclusive`. A VCS
package computes its version at build time, so the two sides are frequently not
comparable, and the outcome is stated rather than implied by an arrow. Machine
consumers should read this field before treating `old_version` and
`new_version` as an ordered pair.
