# Rules Reference

Two rule namespaces:

- **R-series** (R001–R013): detection rules defined in `~/.config/trustsight/rules.toml`. Configurable: patterns, severity, weight, and scope can be edited by the user.
- **C-series** (C001–C003): code (structural) rules hard-coded in `src/trustsight/analysis.py`. Not user-configurable. Fire based on structural heuristics around checksums and source-URL integrity.

---

## R-series (TOML-configurable detection rules) {#r-series}

Defined in `~/.config/trustsight/rules.toml`. Loaded at runtime via `load_rules()` in `src/trustsight/config.py:290`.

Each rule supports these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Rule identifier (`R001`–`R013`). |
| `name` | `string` | Human-readable name. |
| `pattern` | `string` | Python regex applied to the match target. |
| `severity` | `string` | `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `category` | `string` | Semantic category (`network_execution`, `obfuscation`, `installer`, `privilege`, `network_usage`, `injection`, `unicode`, `integrity`). |
| `match_target` | `string` | `"resolved"` : apply to variable-resolved command strings after tokenization. `"raw_line"` : apply to raw diff lines after stripping the `+`/`-` prefix. |
| `scope` | `list[string]` | (Optional, `raw_line` only) Restrict matching to specific line contexts: `["function_body"]`, `["message"]`, `["other"]`. When absent, matches all lines. |

### Rule table {#rule-table}

| ID | Name | Target | Severity | Weight | Category | Description |
|----|------|--------|----------|--------|----------|-------------|
| R001 | Remote Script Execution | `resolved` | CRITICAL | 40 | `network_execution` | Detects `curl \| bash`, `curl \| sh`, and variants (`python`, `zsh`, `dash`, `busybox sh`, `source /dev/stdin`). Pattern: `curl.*\| *(?:/bin/)?(?:bash\|sh\|python\|zsh\|dash\|busybox\s+sh\|source\s+/dev/stdin)`. |
| R002 | Wget Pipe to Shell | `resolved` | CRITICAL | 40 | `network_execution` | Detects `wget \| bash`, `wget \| sh`, and variants. Pattern: `wget.*\| *(?:/bin/)?(?:bash\|sh\|python\|zsh\|dash\|busybox\s+sh\|source\s+/dev/stdin)`. |
| R003 | Base64 Decode and Execute | `resolved` | CRITICAL | 40 | `obfuscation` | Detects `base64 -d \|` and `base64 --decode \|` piped to execution. Pattern: `base64.*(?:-d\|--decode).*\|`. |
| R004 | Checksum Disabled | programmatic | HIGH / INFO | 25 / 0 | `integrity` | Fires when `sha256sums=SKIP` appears in the diff. Severity is **HIGH** (weight 25) if no justification found; downgraded to **INFO** (weight 0) if the diff contains a VCS source (`git+https://`, `.git`), a signature file (`.sig`, `.asc`), `validpgpkeys` declaration, or DKMS reference. Justification checked via `is_skip_justified()` in `src/trustsight/differ.py:52`. Not TOML-configurable; hard-coded in `src/trustsight/analysis.py:88`. |
| R005 | Checksum Emptied | programmatic | HIGH | 25 | `integrity` | Fires when `sha256sums=()` appears in the diff (array set to empty). Not TOML-configurable; hard-coded in `src/trustsight/analysis.py:99`. |
| R006 | Insecure Download Protocol | `resolved` | LOW | 5 | `network_execution` | Detects `tar.gz` piped to execution (e.g. `curl ... tar.gz \| tar -x`). Originally HIGH/25; demoted to LOW/5 based on corpus fire rate. Pattern: `https?://.*\.tar\.gz.*\|`. |
| R007 | Install File Modification | `raw_line` | MEDIUM | 15 | `installer` | Fires when a `.install` file is added or modified in the diff. Scope: all lines (no function-body restriction). Pattern: `\+.*\.install.*`. |
| R008 | Unexpected File Download | `resolved` | HIGH | 25 | `network_execution` | Detects language runtimes downloading scripts from URLs: `python -c <url>`, `ruby -c <url>`, `perl -c <url>`. Pattern: `\b(python\|ruby\|perl)\s+-c\s+https?://`. |
| R009 | Privilege Escalation | `raw_line` | CRITICAL | 40 | `privilege` | Detects `sudo` inside function bodies. Scoped to `["function_body"]`; does not fire in comments, messages (`echo`, `printf`, `note`), or top-level declarations. Pattern: `\bsudo\b`. |
| R010 | Uses curl in PKGBUILD | `raw_line` | LOW | 5 | `network_usage` | Detects `curl` commands inside function bodies. Scoped to `["function_body"]`. Does not fire in comments or messages. Pattern: `\bcurl\s`. |
| R011 | Uses wget in PKGBUILD | `raw_line` | LOW | 5 | `network_usage` | Detects `wget` commands inside function bodies. Scoped to `["function_body"]`. Does not fire in comments or messages. Pattern: `\bwget\s`. |
| R012 | LLM Prompt Injection | `resolved` | FATAL | 0 | `injection` | Detects prompt-injection phrases in resolved strings: "ignore all previous instructions/commands/input". **Tripwire rule**: recall is 17 % on the benchmark corpus. When it fires, the package is almost certainly malicious. When it does not, nothing can be concluded. Score hard-stops at 100; contributes 0 weight. Pattern: `ignore\s+(?:all\s+)?previous\s+(?:instructions\|commands\|input)`. |
| R013 | Unicode Bidi Override | `raw_line` | FATAL | 0 | `unicode` | Detects unicode bidi override characters, zero-width spaces (U+200B–U+200D), BOM (U+FEFF), and directional formatting characters (U+202A–U+202E, U+2066–U+2069). Recall is 88 % on the benchmark corpus. Score hard-stops at 100; contributes 0 weight. Pattern: `[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]`. |

### Severity weights

Configured in `config.toml` `[severity_weights]`:

| Severity | Weight |
|----------|--------|
| FATAL | 0 (hard-stop score at 100) |
| CRITICAL | 40 |
| HIGH | 25 |
| MEDIUM | 15 |
| LOW | 5 |
| INFO | 0 |

### FATAL rules {#fatal-rules}

R012 and R013 are FATAL. They contribute **0 weight** to the running total but immediately set `final_score = 100` and risk level `"Critical"`. No other rules are evaluated for weight contribution after a FATAL fires; the short-circuit is in `calculate_score()` at `src/trustsight/scoring.py:87`.

---

## C-series (code, structural rules) {#c-series-c001c003}

Hard-coded in `src/trustsight/analysis.py:110–140`. Not configurable via TOML. Fire based on structural comparisons between the diff and the post-diff state.

| ID | Name | Severity | Weight | Condition |
|----|------|----------|--------|-----------|
| C001 | Checksum Changed Without Source Change With Stable Version | HIGH | 25 | `sha256sums` value changed (added or modified), **no** source URLs were added or removed, **and** `pkgver` did not change. A checksum changed with no corresponding version or source change is anomalous. |
| C002 | Checksum Updated With Version Bump | INFO | 0 | `sha256sums` value changed (added or modified), **no** source URLs were added or removed, **and** `pkgver` did change. Normal during routine version bumps. Recorded for audit trail; contributes no weight. |
| C003 | Source URL Changed Without Version Bump | INFO | 0 | Source URLs were both added **and** removed (the sets differ) **and** `pkgver` did not change. Source URLs swapped without a version bump is noteworthy but not necessarily malicious. Recorded for audit trail; contributes no weight. |

All C-series comparisons use `_pkgver_changed_in_diff()` from `src/trustsight/analysis.py:30` to detect `pkgver=` value changes.

---

## Benchmark performance

Measured against the TrustSight test corpus (267 tests).

| Rule | Recall | Notes |
|------|--------|-------|
| CRITICAL class (all) | 100 % | Every CRITICAL-class sample detected. |
| R012 (prompt injection) | 17 % | Tripwire; catches obvious patterns only. Low recall is intentional. |
| R013 (unicode bidi) | 88 % | Misses some bidi variants. |
| Benign zero-rate | 81.5 % | Percentage of benign diffs scoring 0. |
| Benign p95 | 20 | 95th percentile score on benign corpus. |
| CRITICAL p5 | 40 | 5th percentile score on CRITICAL-class corpus. |
