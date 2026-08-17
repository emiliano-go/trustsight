# Report Schema

The `PackageFact` dataclass (defined in `src/trustsight/schema.py`) is the core analysis result. It is serialised to JSON via `fact_to_dict()` (`src/trustsight/schema.py`) for database storage and for `trustsight history --score-breakdown`. The **report** bodies that `review --json`, `inspect --json` and the Python API's `to_dict()` emit are a different, shared shape, built by `reporting.report_body`: same keys on all three, with the score group withheld unless asked for. See [B11](../security.md#b11-every-surface-reports-the-same-thing).

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
    "file_changes": [{"path": "string", "status": "modified"}],
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
      "params": {},
      "template": "string",
      "evidence": {},
      "file": "string",
      "line": int
    }
  ],
  "first_seen": bool,
  "recent_commit_burst": bool,
  "diff_truncated": bool,
  "scan_truncated": bool,
  "tree_analyzed": bool,
  "config_fingerprint": "sha256:...",
  "changes": ["string"],
  "coverage_gaps": ["string"],
  "unresolved_sources": ["string"],
  "dependency_changes": {"added": ["string"], "removed": ["string"]},
  "dependencies": [
    {
      "name": "string",
      "depth": int,
      "score": int,
      "risk": "string",
      "risk_label": "string",
      "finding_count": int,
      "coverage_gaps": ["string"],
      "via": "string",
      "parent": "string",
      "failed": bool,
      "error": "string"
    }
  ],
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
  "ioc_matches": [
    {
      "type": "domain | hash | package",
      "value": "string",
      "source": "string",
      "confidence": "string",
      "provenance": "string",
      "campaign": "string",
      "surface": "string",
      "line": "int or null",
      "expired": bool
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
| `diff_truncated` | `bool` | `true` when the diff exceeded `[diff] max_diff_bytes` and only a deterministic UTF-8-safe prefix was examined. The score then describes a prefix, not the change; `coverage_gaps` is non-empty and the result cannot be read as a complete clean analysis. |
| `tree_analyzed` | `bool` | `true` when the repository file manifest was inspected for R118-tree. A result produced without the tree reports `false`. |
| `config_fingerprint` | `string` | `sha256:` digest of the effective ruleset, scoring weights, thresholds and active overrides (B1). Two reports with the same fingerprint were produced by the same instrument; a different fingerprint means a different configuration, not a nondeterministic tool. |
| `changes` | `list[string]` | Declared facts about what the diff did, whether or not a rule matched (B7): version moves, checksum behaviour, files added or removed, maintainer and source-host changes, and the no-change case. Context, not findings: no severity, no points, never in `triggered_rules`. `.SRCINFO` and `.gitignore` are suppressed as always-noisy. |
| `scan_truncated` | `bool` | `true` when the diff held more lines than `rules.MAX_SCANNED_LINES` and only its first lines were matched. Distinct from `diff_truncated` because they name different caps: rule matching costs per line, so a diff of many short lines stays under `[diff] max_diff_bytes` and is still cut here. A reader who saw only `diff_truncated` would raise the byte limit and find it changed nothing. |
| `coverage_gaps` | `list[string]` | What this run could not examine, as `"diff_truncated"`, `"scan_truncated"`, `"line_truncated"`, `"tree_not_analyzed"`, `"unresolved_source"`, `"unresolved_parse_time"`, `"snapshot_refused"`, `"unpinned_build_deps"` and `"deps_not_scanned"`. A non-empty list forbids an UNFLAGGED verdict: `risk` is `"Inconclusive"` unless a HIGH or worse finding fired, and in that case the band is shown qualified. Enforced by `coverage.fail_closed` and `coverage.qualified_band`; see [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete). |
| `unresolved_sources` | `list[string]` | The `source=` lines behind an `unresolved_source` gap, quoted so the reviewer can see what could not be resolved. |
| `risk` | `string` | The verdict band: `"Low"`, `"Medium"`, `"High"`, `"Critical"` or `"Inconclusive"`. **Not** always derivable from `final_score`: a cold database or a coverage gap downgrades it. Read this field; do not recompute it from the score. Read it **with** `coverage_gaps`: a band alone does not say whether the whole change was examined. |
| `adapter` | `string` | Which fetch path produced the analysis: `"git"` or `"corpus"`. |
| `suppressed_rules` | `list[dict]` | Rules suppressed by user override. Each entry has `rule_id`, `severity`, `override_reason`, and `override_package`. These did not contribute to the score. |
| `ioc_matches` | `list[dict]` | IOC federation baseline hits (v0.12.0). Attribution, not score: each entry names the curator (`source`) that flagged the artifact, its `type`/`value`, `confidence`, `provenance`, `campaign`, the `surface` it was found on and its `line`, and whether the indicator is `expired`. IOC matches never appear in `score_breakdown` and never change `final_score`. See [the IOC reference](ioc.md). |
| `final_score` | `int` | Deterministic risk score, 0-100. Computed by `calculate_score()` in `src/trustsight/scoring.py`. |

### `diff_summary`

| Field | Type | Description |
|-------|------|-------------|
| `files_changed` | `list[string]` | File paths touched in the diff (filtered to `PKGBUILD`, `.SRCINFO`, `*.install`). |
| `file_changes` | `list[dict]` | File-change rows, each with `path` and `status` (`added`, `removed`, or `modified`). |
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
| `<url>` | `string` | Each added URL maps to its bucket classification: `"trusted_forge"`, `"official"`, `"raw_hosting"`, `"unknown"`, or `"homograph_attack"`. |

Classified by `classify_urls()` in `src/trustsight/buckets.py`.

### `execution_changes`

| Field | Type | Description |
|-------|------|-------------|
| `resolved_commands` | `list[string]` | Fully resolved command strings after tokenization and variable expansion. Each is a single command extracted from the diff. |
| `suspicious_patterns_detected` | `list[string]` | Rule IDs from the published R/C/D/S/X families that fired during analysis. |
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
| `rule_id` | `string` | Rule or category identifier from the published R/C/D/S/X catalog, `P001`-`P007` (declared practice, always weight 0), or `SOURCE_BUCKET`, `NOVELTY`, `COVERAGE`. |
| `severity` | `string` | `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `weight` | `int` | Contribution to the score. Never negative: nothing lowers a score. `0` for annotations, coverage gaps and every `P` finding. |
| `reason` | `string` | Human-readable explanation of why this entry fired. Truncated to 80 characters in CLI display; full string in JSON. |
| `params` | `dict` | Parameters retained by the score entry for rendering or storage. |
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

The `PackageFact` JSON is stored in the `analysis_history` table under the `fact_json` column (TEXT containing JSON). Triggered rules are stored in the separate `triggered_rules` table keyed by `analysis_history.id`. See `insert_analysis()` in `src/trustsight/analysis/pipeline.py`.

---

## The two serializers

There are two JSON shapes, and they are not the same object.

- `schema.fact_to_dict()` produces the stored `PackageFact`, documented above.
  It is what goes into `fact_json` and into an exported baseline.
- The **report body** (`trustsight review --json`, `trustsight inspect
  --json`, and the Python API's `Report.to_dict()`) is a presentation view of
  the same analysis, built by `reporting.report_body`. All three surfaces
  return the same keys with the same values for the same result, which
  [B11](../security.md#b11-every-surface-reports-the-same-thing) requires and
  the `the API and CLI emit the same JSON body` gate enforces.

  Always present (`reporting.REPORT_KEYS`): `package`, `old_version`,
  `new_version`, `old_commit`, `new_commit`, `version_comparison`, `verdict`,
  `findings`, `file_changes`, `changes`, `coverage_gaps`, `suppressed_rules`,
  `ioc_matches`, `first_seen`, `is_trivial`, `diff_truncated`, `scan_truncated`, `failed`,
  `dependencies`, `depth_truncated`, `required_by`, `config_fingerprint`.

  On request only:

  | Keys | Asked for by |
  |---|---|
  | `score`, `risk`, `risk_label` (`SCORE_KEYS`) | `--score` / `--risk`, or `to_dict(include_score=True)` |
  | `score_breakdown` (`VERBOSE_KEYS`) | `--verbose`, or `to_dict(verbose=True)` |

  Withholding the score withholds nothing else: the evidence keys are in the
  default body on every surface. A finding in the default body carries no
  `weight` - a weight is score arithmetic and travels with the breakdown.

  `dependencies` is one entry per analysed AUR dependency, each with `name`,
  `depth`, `score`, `risk`, `risk_label`, `finding_count`, `coverage_gaps`,
  `via`, `parent`, `failed` and `error`. Each is a full analysis in its own
  right; a dependency's score is never folded into the parent's. See
  [`[depth]`](configuration.md#depth). `depth_truncated` says the walk stopped
  before the closure was exhausted, which also raises `deps_not_scanned`.

  `required_by` is the reverse relationship: the packages in the reviewed set
  that declare *this* package as a dependency. It is populated by
  [`review --deps`](cli.md#trustsight-review) and `TrustSight.review(deps=True)`,
  where the subject of the report is a dependency and the useful question is
  who needs it. Empty on an ordinary review, where the subject is the thing
  that was asked for - the key is always present so a consumer never has to
  special-case its absence.

  `ReviewResult.to_dict()` and `trustsight review --json` serialize a **list**
  of these report bodies, not a wrapper object. A review can complete its
  command successfully while containing failed rows: those rows set `failed`
  to `true` and state that the package was not vetted. A consumer must check
  that field rather than treating an empty finding list as a clean result.

`risk` is the bare band (`"Low"`, `"Medium"`, `"High"`, `"Critical"` or
`"Inconclusive"`). It is a **closed set**: a FATAL finding does not
add a member, it reports as `Critical` and names itself in `risk_label`
(`Critical (FATAL: R013)`). A CRITICAL finding also floors the band at `High`
regardless of the score, so `risk` is not a pure function of `score` - see
[the band rules](../security.md#the-programme). `risk_label` is the same band qualified for a person: a
coverage gap appends ` (incomplete analysis)` to an elevated band, and an
`Inconclusive` names its cause: the gap(s) behind it, e.g.
`Inconclusive (diff truncated: payload may be hidden)`, or the cold start,
e.g. `Inconclusive (cold start: 22 more analyses needed)`. Machine consumers
should gate on `risk` and `coverage_gaps`, not parse `risk_label`.

`version_comparison` is the one field worth knowing about by name. It records
how the installed version relates to the AUR's declared `pkgver`, as one of
`aur_ahead`, `no_aur_change`, `installed_ahead` or `inconclusive`. A VCS
package computes its version at build time, so the two sides are frequently not
comparable, and the outcome is stated rather than implied by an arrow. Machine
consumers should read this field before treating `old_version` and
`new_version` as an ordered pair.
