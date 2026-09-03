<!-- description: How each rule series detects: the mechanism behind R, H, C, D, S, X, P and W rules, and what that means for tuning and interpretation. -->

# Rule Nature

Every rule in TrustSight belongs to a **series** (R, H, C, D, S, X, P, or W) that determines *how* it detects, not *what* it detects. The series is the mechanism; the [category](index.md) is the subject. A rule can be `category = "integrity"` and still be an R-series regex, an H-series heuristic, or a C-series structural check.

Understanding the nature of a rule tells you what you can tune, what you cannot, and what the finding means.

## R-series: **Regex** Pattern Matching

**Count:** 36 rules (R001-R003, R007-R008, R010-R013, R017, R039-R059, R078, R091, R099, R104, R144)

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

## H-series: **Heuristic** Behavioral Analysis

**Count:** 97 rules (H001-H097)

**Mechanism:** Engine-defined logic in `analysis/*.py` examines behavioral signals: what changed relative to, what the corpus has seen before, what files exist outside the diff hunk, or what the observation database records. H-series rules need context a single regex cannot see, but unlike C-series and D-series, they reason about *behavioral suspicion* rather than structural invariants or graph properties.

**What you can tune:**
- `severity` and `weight`: adjust via `config.toml` overrides
- `enabled`: switch the rule off entirely

**What you cannot tune:**
- The detection logic (engine-defined, not a pattern)
- The rule ID
- The match target (always `programmatic`)

**Example:** H015 fires when `build()` was modified between commits. It needs the old and new commit trees, not just the diff. H022 fires when a package gap exceeds 365 days. It needs the observation database.

**When it fires:** When the behavioral condition is met. The finding carries a line number and body extracted from the diff, but the decision required multi-line or cross-commit context.

## C-series: **Check** Structural Invariants

**Count:** 9 rules (C001-C009)

**Mechanism:** Deterministic structural checks across the PKGBUILD. C-series rules enforce invariants that cannot be expressed as a single regex match: two conditions must hold simultaneously, or a relationship between fields must be consistent. Unlike H-series (which reasons about behavioral suspicion), C-series checks are purely mechanical: if condition A and condition B co-occur, the invariant is violated.

**What you can tune:**
- `severity` and `weight`: adjust via `config.toml` overrides
- `enabled`: switch the rule off entirely

**What you cannot tune:**
- The structural invariant (engine-defined logic)
- The rule ID

**Example:** C003 fires when source URLs changed without a version bump. It needs both the URL diff and the version diff to exist (or not exist) in the same change.

**When it fires:** When two or more structural conditions co-occur in a way that violates an invariant.

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

**When it fires:** When a sabotage pattern is found in the diff or the committed file tree.

## X-series: **Crossfire** Evasion Detection

**Count:** 25 rules (X001-X025)

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

**When it fires:** When the tokenizer reports that it could not resolve a command, and the evasion technique is identifiable.

## P-series: **Practice** Declared Practices

**Count:** 7 rules (P001-P003, P005-P008; P004 is skipped)

**Mechanism:** Reports practices the recipe *declares*, not risks that were found. P-series findings are emitted at weight 0 and never contribute to the score. They exist so a reviewer can see what the recipe claims (checksums, PGP keys, pinned sources) without those claims being able to lower the score.

**What you can tune:**
- Which P findings render (default vs `--verbose`)
- `enabled`: switch off entirely

**What you cannot tune:**
- The weight (always 0, by design: B10)
- The rule ID

**Example:** P001 reports "checksums declared for all non-VCS sources." P007 reports "source hosted on a trusted forge over HTTPS." Neither lowers the score; both are information for the reader.

**When it fires:** On every analysis, for every package that declares the practice. P findings are present or absent, not triggered by a diff.

## W-series: **Warning** Analysis Boundaries

**Count:** 6 rules (W001-W006)

**Mechanism:** Reports what the analysis *could not read*. W-series findings mark visibility boundaries in the analysis: a package will run code the examination did not cover, and silence about that would be dishonest. They **warn** the reviewer where the analysis stopped.

**What you can tune:**
- `enabled`: switch off entirely (not recommended)

**What you cannot tune:**
- The weight (always 0)
- The rule ID
- The fact that the gap exists (it is a property of the input, not the rule)

**Example:** W001 reports "a script invoked from inside the source tree was not read." W002 reports "npm install resolving dependencies from a registry." Neither changes the score; both tell the reviewer where the analysis stopped.

**When it fires:** When the analysis encounters a boundary it cannot cross. Always shown, never scored.

## Summary Table

| Series | Full Name | Mechanism | Configurable | Weight | When it fires |
|--------|-----------|-----------|-------------|--------|---------------|
| R | **Regex** | Pattern match | Pattern, target, scope, severity | Severity-based | On every matching line |
| H | **Heuristic** | Behavioral analysis | Severity only | Severity-based | When behavioral condition is met |
| C | **Check** | Structural invariant | Severity only | Severity-based | When invariant is violated |
| D | **Dependency** | Graph algorithm | Severity only | Severity-based | During closure walk |
| S | **Sabotage** | Hostile impact detection | Severity only | Severity-based | When sabotage pattern found |
| X | **Crossfire** | Evasion detection | Severity only | Severity-based | When tokenizer reports evasion |
| P | **Practice** | Declared practice | Visibility only | 0 (always) | On every analysis |
| W | **Warning** | Analysis boundary | Visibility only | 0 (always) | When boundary encountered |

## See Also

- [Rules Reference](index.md); complete catalog by category
- [Rule System Reference](system.md); engine internals, severity weights, field definitions
- [Configuring Rules and Weights](../../guides/configuring-rules-and-weights.md); how to tune R-series rules
