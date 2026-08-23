---
description: Rules that fire when a count of same-kind indicators crosses a fixed threshold within one artifact or one cluster.
---

# Count-Based

A count crossed a fixed threshold. What separates these from
[composition](composition.md) is that the count is over indicators of one
kind rather than over distinct kinds, and what separates them from
[corpus behavioral](corpus-behavioral.md) is that the threshold is a
configured constant rather than a deviation from a learned baseline.

H036 counts obfuscation indicators on one line. H030 counts added
dependencies weighted by rarity. H045, H052 and H055 count packages in a
cluster. Every threshold is configurable under `[thresholds]`, and every
one was set against the benign corpus rather than chosen.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [H030](#h030-rule) | Dependency-Set Expansion | MEDIUM |
| [H036](#h036) | Shell Obfuscation Density | MEDIUM |
| [H045](#h045) | Mass Adoption | HIGH |
| [H052](#h052) | Shared Source Repository | HIGH |
| [H055](#h055) | Attribute Burst | MEDIUM |
<!-- /generated: page-index -->

### H030: Dependency-Set Expansion {#h030-rule}

- **Target:** programmatic (delta over dependency arrays × per-dep novelty)
- **Severity:** MEDIUM (weight 15) - corpus rate 0.34 %
- **Category:** `dependency`
- **Condition:** A single diff adds 3+ `depends`/`makedepends`/`optdepends`/`checkdepends` entries whose **count × mean rarity** exceeds the expansion gate (≥1.5, tuned on corpus).

**Why not count alone:** Adding 5 deps that are all common (`glibc`, `qt6-base`, `cmake`) is a normal heavy build and should not fire. The signal is count **weighted by how rare/novel each added dep is**, reusing D001's `dependency_observation_count` as a rarity proxy. Novel/obscure deps push the magnitude up; common deps contribute near zero.

**No double-count with D001:** H030 fires on the **aggregate pattern** (multiple rare deps appearing together), which is a materially different signal from any single dep being novel. Individual D001 per-dep firings remain untouched. This is not the H027 mistake: the aggregate condition captures a different phenomenon (co-occurrence, not individual presence).

**Origin:** Socket/Snyk dependency-surface profiling - a version bump that expands the dependency graph with obscure entries is the "expand attack surface quietly" shape. D001 already flags each novel dep individually; H030 catches the disproportionate co-occurrence.

### H036: Shell Obfuscation Density {#h036}

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

### H045: Mass Adoption {#h045}

- **Severity:** HIGH (weight 25)
- **Category:** `adoption`
- **Condition:** One maintainer submitted at least `[thresholds] h045.min_packages` (default 10) packages within `h045.window_days` (default 7).

### H052: Shared Source Repository {#h052}

- **Severity:** HIGH (weight 25)
- **Category:** `adoption`
- **Condition:** At least `[thresholds] h052.min_packages` (default 3) otherwise unrelated packages share a source repository, a new domain, or an adoption window.

### H055: Attribute Burst {#h055}

- **Severity:** MEDIUM (weight 15)
- **Category:** `adoption`
- **Condition:** At least `[thresholds] h055.min_packages` (default 5) packages sharing a maintainer were modified within `h055.window_hours` (default 24).

Only modified packages count. H045 already claims the added-package clusters,
so counting additions here would report the same maintainer twice.
