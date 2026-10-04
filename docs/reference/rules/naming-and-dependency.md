<!-- description: Rules for a name being claimed, or a dependency set changing, in a way that redirects what actually gets installed. -->

# Naming and Dependencies

A name is claimed, or a dependency set changes, in a way that redirects
what gets installed. H029 covers the package's own name impersonating a
popular one; D002 covers the same attack against a dependency name; H064
and D004 cover `provides`/`replaces` claiming a name that belongs to
something else.

Most rules here need the dependency corpus, which is seeded from every
`depends`/`makedepends`/`optdepends`/`checkdepends` entry in the AUR plus every
package name and `provides` alias. Without the seed they stay silent rather
than treating an empty table as "nothing has ever been seen". The exceptions
read other sources: D003 uses the static `[patterns] network_tools` list, and
H053 and H059 compare the name against host and repository data. Aggregate
expansion is counted rather than named, so it lives in
[count-based](count-based.md#h030-rule).

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [D001](#d001) | Novel Dependency Added | HIGH |
| [D002](#d002) | Typosquatted Dependency | HIGH |
| [D003](#d003) | New Network-Using Makedepends | MEDIUM |
| [D004](#d004) | Dependency Hijack Via Provides | HIGH |
| [H006](#h006) | New Make/Opt/Check Dependency | - |
| [H029](#h029-rule) | Package-Name Typosquat | HIGH |
| [H048](#h048) | Dependency Vendored Into Source | HIGH |
| [H053](#h053) | Name/Host Consensus Divergence | MEDIUM |
| [H059](#h059) | Name/Repo Divergence | MEDIUM |
| [H064](#h064) | Provides/Replaces Scope Expansion | HIGH |
<!-- /generated: page-index -->

### H006: New Make/Opt/Check Dependency {#h006}

H006 is retained as a documentation anchor for a retired rule. It emits no
finding: a network-capable `makedepends` addition is scored by [D003](#d003),
and an `optdepends` addition is reported as a fact, never scored, without
corpus state.

### H029: Package-Name Typosquat {#h029-rule}

- **Target:** programmatic (package name against seeded candidate list)
- **Severity:** HIGH (weight 25) - corpus rate 0.00 % (0/202, package-name scan)
- **Category:** `naming`
- **Condition:** The package's own name is Damerau-Levenshtein distance ≤2 of an **established, far-more-popular** package - AND is not an expected variant (`-git`, `-bin`, `-debug`, `-lts`, etc.) of that package.

This is the AUR equivalent of the `python-sqlite` vs `pysqlite`, `electron` vs `electorn`, and trailing-space/separator-swap attacks that have hit every other registry. The AUR has **zero** typosquat defense; D002 already covers *dependency* names, but nothing covers the package's **own name** impersonating a popular one.

**The asymmetric gate (the make-or-break):**

Symmetric edit-distance is a census generator: `foo-git`, `foo-bin`, `foo-lts`, and every legitimate fork are distance-small from `foo`. A bare edit distance is also a coincidence generator: `plow`/`glow` and `nedit`/`gedit` are one edit apart and unrelated. This rule fires ONLY when all hold:

1. **Similar** - Damerau-Levenshtein ≤2 to a candidate `C`.
2. **Popular in absolute terms** - `C` is observed at least `[naming] h029_min_candidate_observations` (default 100) times via `dependency_observation_count`. The dependency corpus is long-tailed (median observation count 2), so a name ranked in the top 5000 by count can still be globally obscure.
3. **Asymmetric popularity** - `C` is observed 10x+ more often than this package, with the threshold floored at ten observations (`max(pkg_pop, 1) * 10`). A squat impersonates something bigger; without the floor a never-observed name would zero the bar and let any thin candidate through.
4. **Not a variant** - Expected suffixes (`-git`, `-bin`, `-debug`, `-lts`, `-stable`, `-beta`, `-svn`, `-hg`, `-bzr`, `-cvs`, `-wine`, `-appimage`, `-flatpak`, `-nightly`, `-devel`, `-common`) are stripped before comparison.
5. **Confusable, or genuinely popular** - The edit is classified from the stripped names. A **confusable** edit is an adjacent transposition (`sytsemd`/`systemd`), a substitution between confusable glyphs or digits (`openss1`/`openssl`, `0`/`o`, `1`/`l`), or a separator-only change (`cross-env`/`crossenv`); it fires at the floor in (2). A **plain** edit is everything else (`plow`/`glow`, `cflash`/`clash`); it is far weaker evidence, so it must clear the higher `[naming] h029_plain_min_observations` (default 1000). That high floor is the safety-first choice: a plain edit against a genuinely popular name still fires, at the cost of some false positives.

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

### H064: Provides/Replaces Scope Expansion {#h064}

- **Severity:** HIGH (weight 25) for an established package, MEDIUM (weight 15) for a widely-provided one
- **Category:** `dependency`
- **Condition:** A newly claimed `provides` or `replaces` names an established package (official repo or fallback observations) or a widely-provided one (observation count at or above `[h064] widely_provided_observations`, default 25).

Claiming another project's name redirects installs of that name to this
package. Relatedness suppresses the obvious false positive: variant, companion
and sibling stems of the package's own name never fire. Cold start cannot fire
either branch, since neither corpus nor pacman data exists to establish what is
established. H064 always runs; D004 covers the same ground and may
double-report when it is enabled (it is, by default).

Fire rate: 2 of 3739 (0.05 %), both established-name claims: `jpegli-git` conflicts `libjxl` and `llama.cpp-cuda-git` provides `ggml`.

**Known false positive: kernel module aliases.** A `linux*` split provides
module names many packages depend on - `KSMBD-MODULE`, `LINUX-HEADERS`, or
a lower-case `<module>-module` alias - and H064's widely-provided branch
fires on it (`linux-versioned-bin` provides `KSMBD-MODULE`). The name
belongs to the kernel ABI rather than to another project, so there is no
related project for `is_related_package` to accept. The trigger is kept:
the same shape is exactly how a package inserts itself in front of a name
the ecosystem relies on, and suppressing the class would blind the rule to
the real version of it. Treat it as a documented false positive to weigh,
not as a rule to silence; the [tuning guide](../../guides/tuning-false-positives.md#known-false-positives)
has the config for a package set that is mostly kernels.

### H048: Dependency Vendored Into Source {#h048}

- **Severity:** HIGH (weight 25) for a security-relevant library, MEDIUM (weight 15) otherwise
- **Category:** `dependency`
- **Condition:** A dependency was removed and a new source entry appeared whose project name matches the removed dependency name.

Narrowed to that mechanical case on purpose. Vendoring a library bypasses the
distribution's security updates for it, and `[patterns] security_relevant_libraries`
is what raises the severity.

### H053: Name/Host Consensus Divergence {#h053}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Condition:** An ecosystem-prefixed package (`python-`, `ruby-`, `nodejs-`, ...) is sourced from neither its ecosystem's canonical hosts nor a known forge.

### H059: Name/Repo Divergence {#h059}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Condition:** The package name and the repository it is built from share no meaningful token.
