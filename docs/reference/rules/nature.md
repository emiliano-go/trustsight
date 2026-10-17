<!-- description: How each rule series detects: the mechanism behind R, H, C, D, S, X, T, G, E, I, M, A, U, P and W rules, and what that means for tuning and interpretation. -->

# Rule Nature

Every rule in TrustSight belongs to a **series** (R, H, C, D, S, X, T, G, E, I, M, A, P, or W) that determines *how* it detects, not *what* it detects. The series is the mechanism; the [category](index.md) is the subject. A rule can be `category = "integrity"` and still be an R-series regex, an H-series heuristic, or a C-series structural check.

Understanding the nature of a rule tells you what you can tune, what you cannot, and what the finding means.

## R-series: **Regex** Pattern Matching

**Count:** 37 rules (R001-R003, R007-R008, R010-R013, R017, R039-R059, R078, R091, R099, R104, R144, R152)

**Mechanism:** A Python regex is applied to either the resolved command text or the raw diff line. The pattern lives in `~/.config/trustsight/rules.toml` and is loaded at runtime by `load_rules()`.

**What you can tune:**

- The pattern itself (edit `rules.toml`)
- `match_target`: `resolved` (post-variable-expansion) or `raw_line` (literal diff line)
- `scope`: restrict to `function_body`, `message`, `other`, or a named function
- `severity` and `weight`: adjust via `config.toml` overrides
- `enabled`: switch the rule off entirely

Rule definitions in `rules.toml` control matching behavior (pattern, target, scope). `config.toml` controls runtime overrides (severity, weight, enablement). When both set the same field, `config.toml` wins.

**What you cannot tune:**

- The rule ID (immutable)
- The series assignment (R means regex, always)

**Example:** R001 matches `curl ... | bash` on resolved text. Changing the pattern to `wget ... | sh` would narrow the detection. Changing `match_target` to `raw_line` would miss payloads assembled from variables.

**When it fires:** On every diff line (or resolved line) that matches the pattern. No diff context needed; no history needed.

**Coupling to the tokenizer.** `match_target = resolved` rules detect only what the tokenizer can read; an assignment it refuses is not matched against, and the refusal routes suspicion to the X-series instead. A shrinking R fire rate beside a non-zero unresolved count is the tokenizer's boundary showing through, not silence from the recipe.

## H-series: **Heuristic** Behavioral Analysis

**Count:** 103 rules (H001-H103)

**Mechanism:** Engine-defined logic in `analysis/*.py` examines behavioral signals: what changed relative to, what the corpus has seen before, what files exist outside the diff hunk, or what the observation database records. H-series rules need context a single regex cannot see, but unlike C-series and D-series, they reason about *behavioral suspicion* rather than structural invariants or graph properties.

**What you can tune:**

- `severity` and `weight`: adjust via `config.toml` overrides
- `enabled`: switch the rule off entirely

**What you cannot tune:**

- The detection logic (engine-defined, not a pattern)
- The rule ID
- The match target (always `programmatic`)

**Example:** H015 fires when `build()` was modified between commits. It needs the old and new commit trees, not just the diff. H022 fires when a package gap exceeds 365 days. It needs the observation database.

**Internal taxonomy.** H carries two kinds that share a series anyway: *shape heuristics* (recipe-form reasoning, single-commit, deterministic) and *observational heuristics* (they need old trees, the observation database, or the seed: H015, H022, H029's floors). Both reason about behavioral suspicion rather than invariants, and both are engine-defined; the doc note exists so the series does not imply every H rule costs the same to replay.

**Known misfile.** H091 (checksum array shorter than the source array) is a two-field consistency invariant - the definition of the C-series - filed in H for ID-history reasons. Rule IDs are immutable citation targets, so the divergence is recorded here rather than migrated.

**When it fires:** When the behavioral condition is met. The finding carries a line number and body extracted from the diff, but the decision required multi-line or cross-commit context.

## C-series: **Check** Structural Invariants

**Count:** 31 rules (C001-C031)

**Mechanism:** Deterministic structural checks across the PKGBUILD. C-series rules enforce invariants that cannot be expressed as a single regex match: two conditions must hold simultaneously, or a relationship between fields must be consistent. Unlike H-series (which reasons about behavioral suspicion), C-series checks are purely mechanical: if condition A and condition B co-occur, the invariant is violated.

**What you can tune:**

- `severity` and `weight`: adjust via `config.toml` overrides
- `enabled`: switch the rule off entirely

**What you cannot tune:**

- The structural invariant (engine-defined logic)
- The rule ID

**Example:** C003 fires when source URLs changed without a version bump. It needs both the URL diff and the version diff to exist (or not exist) in the same change.

**When it fires:** When two or more structural conditions co-occur in a way that violates an invariant.

**Filing rule.** New invariant-shaped detections default to C-series even when the ID sequence has to skip: a C rule with a fresh ID beats another H misfile (the intake freeze). C014-C025 arrived this way.

## D-series: **Dependency** Graph Analysis

**Count:** 4 rules (D001-D004)

**Mechanism:** Graph algorithms walk the AUR dependency tree to detect naming anomalies, typosquatting, or suspicious dependency additions. D-series rules compare package names against known-good lists or edit-distance thresholds, and flag new network-using makedepends. Unlike H-series (which examines behavioral context) and C-series (which checks structural invariants), D-series operates specifically on the dependency graph topology.

**What you can tune:**

- `severity` and `weight`: adjust via `config.toml` overrides
- `enabled`: switch the rule off entirely

**What you cannot tune:**

- The graph-walking logic (engine-defined)
- The rule ID

**Example:** D002 fires when a dependency name is an edit-distance neighbor of a popular package (typosquatting). D003 fires when a new `makedepends` entry uses a network client.

**H029 versus D002.** H029 (package-name typosquat) and D002 (dependency typosquat) are the same mechanism on different graph positions: H029 scans the package's own name against observed popularity; D002 walks the dependency closure. The series split is positional, not mechanical, and that is the intended reading of "series = mechanism."

**Cold start.** D is weakest for new, low-observation packages - exactly where novel supply-chain attacks live. A D-rule that declines to fire for insufficient observations reports that abstention as a weight-0 boundary finding naming the rule and the observation count; the absence of a D finding is never read as evidence of safety.

**When it fires:** During the dependency closure walk, when a naming or composition anomaly is detected.

## S-series: **Sabotage** Hostile Impact Detection

**Count:** 8 rules (S001-S008)

**Mechanism:** Detects payloads intended to harm, abuse, compromise, or exploit the operator environment. These rules are distinguished from general payload detection because they specifically identify actions intended to negatively impact the host: resource exhaustion (fork bombs, disk fill), file deletion, privilege abuse, service disruption, data exfiltration, and resource theft.

**What you can tune:**

- `severity` and `weight`: adjust via `config.toml` overrides
- `enabled`: switch the rule off entirely

**What you cannot tune:**

- The detection logic (engine-defined)
- The rule ID

**Example:** S001 fires on fork bombs (`:(){ :|:& };:`). S004 fires on outbound data exfiltration patterns (the payload exfiltrates data from the operator's machine).

**The evidence vacuum.** Sabotage patterns are vanishingly rare in benign corpora, so S rules have near-zero measurable fire rates and are the least validated by calibration. The absence of an S finding is weak evidence: the series' value is severity-when-it-fires, not frequency. Every S rule ships with a mandatory fixture pair (one malicious that must fire, one benign lookalike that must not).

**When it fires:** When a sabotage pattern is found in the diff or the committed file tree.

## X-series: **Crossfire** Evasion Detection

**Count:** 33 rules (X001-X033)

**Mechanism:** Detects evasion techniques, not the payloads they hide. X-series rules fire on *how* a thing was written rather than *what* it does. The tokenizer could not resolve the command, so the evasion technique itself is the signal.

!!! tip "The key distinction"
    A **payload rule** (R001, H075) fires on what the command *does*. A **crossfire rule** (X017) fires on how the command was *hidden*. Both can fire on the same line; they score independently. This is why a single diff can legitimately produce findings from both families.

**What you can tune:**

- `severity` and `weight`: adjust via `config.toml` overrides
- `enabled`: switch the rule off entirely

**What you cannot tune:**

- The detection logic (engine-defined)
- The rule ID

**Example:** X007 fires when the tokenizer found multiple evasion techniques in one diff. X017 fires when `enable -f` loads an arbitrary ELF into bash as a builtin. X024 fires when a sensitive variable (DLAGENTS, COMPRESS*, PACMAN_AUTH) is assigned an indirect value.

**X is a function of refusal.** Any tokenizer improvement that resolves more constructs shrinks X's detection surface. That is the intended way this family shrinks, and every shrinkage is a measured event: the calibration replay records X-series aggregate fire rates per release, and a tokenizer change that moves any X rule's rate beyond the published epsilon carries a changelog adjudication naming the technique the family can no longer see and the rule that covers it now, if any.

**When it fires:** When the tokenizer reports that it could not resolve a command, and the evasion technique is identifiable.

## P-series: **Practice** Declared Practices

**Count:** 7 rules (P001-P008; P004 is skipped)

**Mechanism:** Reports practices the recipe *declares*, not risks that were found. P-series findings are emitted at weight 0 and never contribute to the score. They exist so a reviewer can see what the recipe claims (checksums, PGP keys, pinned sources) without those claims being able to lower the score.

**What you can tune:**

- Which P findings render (default vs `--verbose`)
- `enabled`: switch off entirely

**What you cannot tune:**

- The weight (always 0, by design: B10)
- The rule ID

**Example:** P001 reports "checksums declared for all non-VCS sources." P007 reports "source hosted on a trusted forge over HTTPS." Neither lowers the score; both are information for the reader.

**Absence is signal.** P findings are present-or-absent. No P001 means the recipe declares no checksums. Read P findings as a claims ledger - the recipe's own account of what it declares - and read the gaps between entries as what it does not. Not scored, per B10, forever.

**When it fires:** On every analysis, for every package that declares the practice. P findings are present or absent, not triggered by a diff.

## W-series: **Warning** Analysis Boundaries

**Count:** 10 rules (W001-W010)

**Mechanism:** Reports what the analysis *could not read*. W-series findings mark visibility boundaries in the analysis: a package will run code the examination did not cover, and silence about that would be dishonest. They **warn** the reviewer where the analysis stopped.

**What you can tune:**

- `enabled`: switch off entirely (not recommended)

**What you cannot tune:**

- The weight (always 0)
- The rule ID
- The fact that the gap exists (it is a property of the input, not the rule)

**Example:** W001 reports "a script invoked from inside the source tree was not read." W002 reports "npm install resolving dependencies from a registry." Neither changes the score; both tell the reviewer where the analysis stopped.

**When it fires:** When the analysis encounters a boundary it cannot cross. Always shown, never scored.

## T-series: **Temporal** Observation History

**Count:** 3 rules (T001-T003; 16 further history-backed rules still carry H ids)

**Mechanism:** Predicates over the observation database - the history of the package, its maintainers, its signing keys and its rates. The input is stored history, not the diff, which is what makes T a distinct kind from H: fire rates depend on how much history exists, cold-start semantics are special, and reproducibility requires a pinned DB fixture. The observation-database H rules (H020, H021, H022, H026, H037, H044, H045, H046, H058, H060, H073, H074, H086, H088) are T-natured and keep their H ids for citation stability; new history-backed rules take T ids.

**What you can tune:**

- `severity` and `weight`: adjust via `config.toml` overrides
- Per-instance thresholds under `[thresholds]` (`t_key.min_observations`, `t_dom.window_days`, ...)

**What you cannot tune:**

- The history reads (they are the instrument)
- The cold-start abstention contract: insufficient history is a decline, not a guess
- The rule ID

**Example:** T001 fires when an added `validpgpkeys` fingerprint has never been observed in the ecosystem key ledger. T003 fires when a key is removed and a different one added in one diff - the xz shape - and needs no history, so it fires cold.

**Cold start.** A fresh index has no baseline, so T rules **decline silently** rather than flag every key and domain a new install sees; the abstention is named as a weight-0 boundary, never read as a clean result.

**When it fires:** When the stored history makes the change anomalous, or a ledger entry is novel. Never on a diff alone.

## G-series: **Correlation** Cross-Package Joins

**Count:** 4 rules (G001-G004)

**Mechanism:** Joins across packages over the corpus database, windowed and clustered. G's input is the **set** of recent analyses: D walks one package's dependency graph, T reads one package's history, and G asks what several packages share. It fires one aggregate finding with a member list, so a campaign is one alert instead of N.

**What you can tune:**

- Per-rule thresholds: `g_host.min_packages`, `g_blob.min_length`/`min_packages`, `g_adopt.min_members`, and the cycle window

**What you cannot tune:**

- The join logic and the member-list rendering
- Where it runs: cycle end only, never per package
- The rule ID

**Example:** G001 fires when the same gained canonical host appears in at least `g_host.min_packages` (default 5) unrelated packages within the window - atomic-arch's signature: a new CDN is plausible once and damning five times.

**Not per package.** A single `review`/`inspect` cannot supply the input, so G runs only in the full-AUR sweep; the layer profile shows L8 as "not exercised" outside a correlation cycle. The shared literal's content is never printed - only its class and the members.

**When it fires:** At cycle end, when a host, literal or adopter is shared by enough packages in the window.

## E-series: **Entropy** Distribution Statistics

**Count:** 3 rules (E001-E003)

**Mechanism:** Distribution analysis of the added content - no patterns, no refusal semantics. E is the statistical twin of X: an attacker who writes *resolvable-but-obfuscated* code defeats X's refusal coupling, but a distribution does not care *why* the content is strange. Both live at L4 by design; the diversity is the point.

**What you can tune:**

- Thresholds under `[thresholds] e001/e002/e003` - **which ship empty**

**What you cannot tune:**

- That the series is suspicion, never a verdict: an E finding never reaches FATAL
- The rule ID

**Example:** E002 fires when the fraction of added tokens that are base64/base32/hex runs exceeds `e002.min_fraction`. E003 fires when the entropy of newly assigned names falls outside the configured band, checked both as unigram and bigram entropy.

**Calibration.** Every E threshold ships **empty**, so the series is silent until an operator or the calibration job sets it from the first corpus measurement (`scripts/entropy_calibrate.py` prints conservative percentile floors). The benign fire rate is the published number; the tool never rewrites the shipped defaults.

**When it fires:** When the added content's distribution crosses a configured threshold. Silent until one is set.

## I-series: **Indicator** Signed External Data

**Count:** 1 rule (H056, an H id under the indicator mechanism; new matches take `I` ids)

**Mechanism:** Membership in **signed external data** - the shipped/imported `iocs.toml` baseline, or a federated publisher's signed indicator set. The answer is exact equality against a list TrustSight did not invent; there is no heuristic and no pattern shape, only "is this surface on the list". H056 and the IOC federation are the same mechanism, so H056 is filed here with its id unchanged.

**What you can tune:**

- Which signed baselines are imported and their cadence (`ioc update`, `ioc update --federation`)
- `severity` by confidence tier via `config.toml` (a `confirmed` entry is FATAL and cannot be suppressed)

**What you cannot tune:**

- That a match is **outside the heuristic score** and reported at maximum alert priority
- The list's contents: TrustSight consumes signed output and never decides what belongs on it
- The rule ID

**Example:** H056 fires when a declared surface (package name, a dependency name, a URL host, a digest, or an added/`install=` file) exactly matches an entry in a signed baseline. Matching is exact - case, trailing root dot, IDNA spelling and quotes are normalised; subdomains are never stripped and names are never stemmed.

**Empty by default.** A fresh install ships an empty list, so a miss is uninformative until the operator imports a signed set; a stale or unsigned baseline is refused, never merged.

**When it fires:** On an exact indicator match, at maximum alert priority, outside the score.

## M-series: **Meta** Confluence Of Findings

**Count:** 3 rules (M001-M003; M004 is a tool-health check, never a package finding)

**Mechanism:** Predicates over the finding set itself. Every other series reads the recipe; M reads the *findings* - a declared practice contradicted by structure, or a composition of weak signals that is only visible from the whole profile. Its input is the finding multiset **after** the ownership resolver, so two rules that matched the same line have already collapsed to one owner.

**What you can tune:**

- `[thresholds] m002.min_layers` (the layer-span count) and the per-layer ceiling

**What you cannot tune:**

- The constitutional rule: **M never lowers a score; it only escalates**
- The cluster-rate gate: every M rule's benign fire rate must stay at or below its members' before its threshold ships
- The rule ID

**Example:** M001 fires when the recipe declares a practice and a structural finding contradicts it in the same run - checksums declared (P001) while H091 reports the arrays do not cover every source. M002 fires when three or more layers fired, none above the alert bar, and raises the reported band one step (never adding points).

**Fires at its inputs' layer.** M owns no static layer: it records which inputs composed and is labelled by them. M002/M003 are weight 0 but escalate the band one step, gated by `M escalation stays below the benign cap`.

**When it fires:** After the ownership resolver, when a contradiction or a weak-signal composition is present.

## A-series: **Artifact** Built-Package Inspection

**Count:** 8 rules (A001-A008)

**Mechanism:** Inspects the built `pkg.tar.zst` manifest - file list, modes, types and the `.INSTALL` payload - not the diff. A is the optional **L9 build lane**: mechanically distinct from every text-analysis series, off by default, run only inside the project's rootless, networkless container, and never blended into the static score. Nothing in the built package's code is executed; the container runs `makepkg`, nothing else.

**What you can tune:**

- Enablement only: `[verify] enabled` (default **false**)

**What you cannot tune:**

- That L9 evidence is never folded into the L1-L8 score
- The failure semantics: a failed/timed-out/capped build is `l9_unavailable` (weight 0), never "malicious" or "clean"
- The rule ID

**Example:** A001 fires for a setuid/setgid file the recipe cannot justify; A008 for an eBPF object or loader shipped in the package (the Atomic Arch rootkit's artifact shape).

**Disagreement stays visible.** When L9 contradicts L1-L8, both profiles render in full and the verdict carries an explicit `l9_divergence` notice; L9 never edits, suppresses or reweights static findings. Reproducibility comparison is a v1.1 query over recorded artifact hashes.

**When it fires:** Only in the optional L9 lane, when the built artifact does not match the recipe's declared surface.

## U-series: **Manifest** Committed Dependency Surfaces

**Count:** 5 rules (U001-U005)

**Mechanism:** Parses the dependency manifests committed beside a recipe - `Cargo.toml`, `package.json`, `requirements.txt`, `go.mod`, `Gemfile`, `composer.json` and peers - with the existing tree walk and diff. No fetch and no extraction (A2, A8): these are repository bytes the analysis already reads.

**What you can tune:**

- The filename table (`[patterns] manifest_filenames`) and `[thresholds] u005.jump_factor`

**What you cannot tune:**

- That a manifest-introduced remote host joins the run's `hosts_gained` view
- The rule IDs

**Example:** U003 fires when a `Cargo.toml` gains a `git = "..."` dependency whose host the recipe never declared; U002 records the added and removed dependency names at weight 0.

**When it fires:** On a committed manifest the diff added, removed or changed.

## Known fuzzy edges

The taxonomy is a reading aid, not a partition, and a divergence found later is documented here rather than migrated (the W-series honesty principle applied to the taxonomy itself):

- **H091 is C-natured** (a two-field consistency invariant) but keeps its H ID: citation stability outranks the taxonomy, the same reason rule IDs are immutable.
- **H029 and D002 are the same mechanism** on different graph positions (package name versus dependency closure); the series split is positional.
- **H carries an internal seam** between shape heuristics and observational heuristics; both reason about behavioral suspicion, but their replay costs differ. The observation-database H rules (H020, H021, H022, H026, H028, H037, H044, H045, H046, H058, H060, H073, H074, H086, H088) are **T-natured**: they read stored history, so their fire rates depend on history length and their cold-start semantics are special. IDs stay H for citation stability; the T-series (T001 signing-key novelty, T002 maintainer-domain novelty) is the destination for new history-backed rules.
- **R and X are both functions of the tokenizer**: R-on-resolved detects only what resolution can read, and X detects what it refuses. A tokenizer change moves both, so both carry measured-shrinkage/growth gates.
- **X and E share L4 by design**: X catches what the tokenizer refuses to fold; E catches what folds cleanly but is statistically weird. Two mechanisms at one layer is the diversity the layer model exists to keep.
- **I is membership in signed external data**, a mechanism of its own: H056 (the shipped/imported IOC baseline) and the IOC federation are the same idea, so H056 is filed under the [Indicators category](indicator.md) with its ID unchanged; new federation matches take I IDs. L7 is the indicator layer, and a match is outside the heuristic score.
- **M fires at the category of its inputs and owns none**: a claims contradiction (M001) or a weak-signal span (M002) has no evidence category of its own; it records which inputs composed. P (claims) and W (boundaries) are render surfaces, not evidence-category layers either.
- **A is the reserved L9 layer, not an L1-L8 rule layer**: it inspects the built artifact, only in the optional build lane, and its findings are never blended into the static score. The series is an artifact of execution, not of text analysis - the one mechanism that cannot be a static rule.
- **A rule whose mechanism later proves to belong to another series is documented here**, not renumbered.
- **The H-series is under an intake freeze**: no new H id is added while the live count is above the reduction target. Overlapping ids are merged in the survivor's favour once the co-fire audit is measured, and a retired id stays readable as an alias of its survivor forever (`trustsight.rule_id_history`). The freeze is enforced in `tests/test_h_reduction.py`; the audit, the freeze-versus-residue split, and why the retirement map is still empty are explained in [Reducing the H-Series](../../explanation/reducing-the-h-series.md).

## Summary Table

| Series | Full Name | Mechanism | Configurable | Weight | When it fires |
|--------|-----------|-----------|-------------|--------|---------------|
| R | **Regex** | Pattern match | Pattern, target, scope, severity | Severity-based | On every matching line |
| H | **Heuristic** | Behavioral analysis | Severity only | Severity-based | When behavioral condition is met |
| C | **Check** | Structural invariant | Severity only | Severity-based | When invariant is violated |
| D | **Dependency** | Graph algorithm | Severity only | Severity-based | During closure walk |
| S | **Sabotage** | Hostile impact detection | Severity only | Severity-based | When sabotage pattern found |
| X | **Crossfire** | Evasion detection | Severity only | Severity-based | When tokenizer reports evasion |
| E | **Entropy** | Distribution of added content | Thresholds (ship empty) | Severity-based | When a configured distribution threshold is crossed |
| T | **Temporal** | Ecosystem history and ledgers | Severity, thresholds | Severity-based | When history makes the change anomalous |
| G | **Correlation** | Cross-package joins over the cycle | N/M/window per rule | Severity-based | At cycle end, never per package |
| I | **Indicator** | Membership in signed external data | Curator keys, cadence | Outside the score | On an indicator match |
| M | **Meta** | Other rules' findings | Layer count, per-layer ceiling | Severity-based; M002/M003 weight 0 | After the ownership resolver |
| A | **Artifact** | Built package manifest | Enable flag only | Outside the score (L9) | Only in the optional build lane |
| P | **Practice** | Declared practice | Visibility only | 0 (always) | On every analysis |
| U | **Manifest** | Committed dependency surfaces | Filename table, threshold | U003/U004 MEDIUM; others 0 | When a committed manifest changes |
| W | **Warning** | Analysis boundary | Visibility only | 0 (always) | When boundary encountered |

## See Also

- [Rules Reference](index.md); complete catalog by category
- [Rule System Reference](system.md); engine internals, severity weights, field definitions
- [Configuring Rules and Weights](../../guides/configuring-rules-and-weights.md); how to tune R-series rules
