# Naming and Dependencies

A name is claimed, or a dependency set changes, in a way that redirects
what gets installed. R074 covers the package's own name impersonating a
popular one; D002 covers the same attack against a dependency name; R116
and D004 cover `provides`/`replaces` claiming a name that belongs to
something else.

Every rule here needs the dependency corpus, which is seeded from every
`depends` entry in the AUR plus every package name and `provides` alias.
Without the seed they stay silent rather than treating an empty table as
"nothing has ever been seen". Aggregate expansion is counted rather than
named, so it lives in [count-based](count-based.md#r075-rule).

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

### R016: New Make/Opt/Check Dependency {#r016}

- **Target:** `raw_line`
- **Severity:** INFO (weight 0); see Note
- **Category:** `dependency`
- **Pattern:** `(?:makedepends|optdepends|checkdepends)\s*=`
- **Scope:** All lines
- **Description:** Fires when a `makedepends=`, `optdepends=`, or `checkdepends=` array is added or modified. At INFO it contributes weight 0 and reports context only. Sources a dependency-extraction exclusion: the dependency declaration itself is metadata, not a command, and must not be read for command-position matching.

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

### R095: Dependency Vendored Into Source {#r095}

- **Severity:** HIGH (weight 25) for a security-relevant library, MEDIUM (weight 15) otherwise
- **Category:** `dependency`
- **Condition:** A dependency was removed and a new source entry appeared whose project name matches the removed dependency name.

Narrowed to that mechanical case on purpose. Vendoring a library bypasses the
distribution's security updates for it, and `[patterns] security_relevant_libraries`
is what raises the severity.

### R101: Name/Host Consensus Divergence {#r101}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Condition:** An ecosystem-prefixed package (`python-`, `ruby-`, `nodejs-`, ...) is sourced from neither its ecosystem's canonical hosts nor a known forge.

### R110: Name/Repo Divergence {#r110}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Condition:** The package name and the repository it is built from share no meaningful token.
