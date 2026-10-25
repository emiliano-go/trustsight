<!-- description: Rules for a name being claimed, or a dependency set changing, in a way that redirects what actually gets installed. -->

# Naming and Dependencies

Where these rules come from and what a finding means: [Rule Nature](../nature/naming-and-dependency.md).

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

Dependency arrays are read in both assignment forms: a bare `depends=(...)`
and a compound `depends+=(...)`, including arch-suffixed spellings such as
`depends_x86_64+=(...)`. Appended names reach every D-rule and the dependency
change summary, so `+=` is not an evasion. D001/D002 need the corpus and the
main calibration gates run cold: the `warm` fixture group is scanned twice by
`gate_d_series_warm` - once with the committed dependency corpus, where the
labels must pass, and once cold, where D001/D002 must stay silent. The
D-series fire rates below are point-in-time measurements against the seeded
corpus.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [D001](#d001) | Novel Dependency Added | MEDIUM |
| [D002](#d002) | Typosquatted Dependency | HIGH |
| [D003](#d003) | New Network-Using Makedepends | MEDIUM |
| [D004](#d004) | Dependency Hijack Via Provides | HIGH |
| [D005](#d005) | Official-Repo Name Shadow | MEDIUM |
| [H006](#h006) | New Make/Opt/Check Dependency | - |
| [H029](#h029-rule) | Package-Name Typosquat | HIGH |
| [H048](#h048) | Dependency Vendored Into Source | HIGH |
| [H053](#h053) | Name/Host Consensus Divergence | MEDIUM |
| [H059](#h059) | Name/Repo Divergence | MEDIUM |
| [H064](#h064) | Provides/Replaces Scope Expansion | HIGH |
| [H104](#h104) | Placeholder Package | INFO |
<!-- /generated: page-index -->

### H006: New Make/Opt/Check Dependency {#h006}

<!-- name: New Make/Opt/Check Dependency -->

H006 is retained as a documentation anchor for a retired rule. It emits no
finding: a network-capable `makedepends` addition is scored by [D003](#d003),
and an `optdepends` addition is reported as a fact, never scored, without
corpus state.

### H029: Package-Name Typosquat {#h029-rule}

- **Target:** programmatic (package name against seeded candidate list)
- **Severity:** HIGH (weight 25) - corpus rate 0.00 % (0/202, package-name scan)
- **Category:** `naming`

<!-- name: Package-Name Typosquat -->

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

!!! note "H029 vs D002 - same mechanism, different graph position"
    H029 and [D002](#d002) are the same typosquat mechanism on different
    graph positions: H029 scans the package's **own name** against observed
    popularity, D002 walks the **dependency closure**. The series split is
    positional, not mechanical - that is the intended reading of "series =
    mechanism" (see [Rule Nature](nature.md)).

### D001: Novel Dependency Added {#d001}

- **Severity:** MEDIUM (weight 15)
- **Category:** `dependency`

<!-- name: Novel Dependency Added -->

- **Description:** A dependency name appears that has never been observed anywhere in the AUR. Either a typo or a package created specifically to be pulled in.

MEDIUM rather than HIGH: "never observed in the AUR" reads accumulated instrument history, so it is a prior - a quiet or cold corpus can make an ordinary new dependency look novel - and it is evidence to weigh, not a high-severity finding on its own. It stays scored, so poisoning the corpus can quiet it but never silence the structural rules.

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

<!-- name: Typosquatted Dependency -->

- **Description:** A novel dependency name within one or two edits (Damerau-Levenshtein, so transpositions count) of a popular package: `openss1` for `openssl`, `cur1` for `curl`.

D002 **refines D001**: only a name D001 has already found to be globally unknown is compared, and D002 is reported instead of D001 when it matches. That ordering is what makes the check both affordable and correct. A precomputed table of confusable pairs cannot work, because a table built from existing package names can only contain names that must *not* fire, while the names that should fire do not exist yet.

Popularity is taken from `observation_count`, so no separate package list is shipped. The distance threshold scales with length: short names sit close to many unrelated real packages, with `yay` one edit from `yak`, `yam`, `jay`, and `may`.

!!! note "D002 vs H029 - same mechanism, different graph position"
    D002 is the dependency-closure twin of [H029](#h029-rule): H029 scans
    the package's own name, D002 walks the dependency closure. Same
    mechanism, different graph position; the series split is positional,
    not mechanical (see [Rule Nature](nature.md)).

### D004: Dependency Hijack Via Provides {#d004}

- **Severity:** HIGH (weight 25)
- **Category:** `dependency`

<!-- name: Dependency Hijack Via Provides -->

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

<!-- name: New Network-Using Makedepends -->

- **Description:** `makedepends` gains a network-capable tool (`curl`, `wget`, `git`, `python-requests`, …) that was not there before, meaning the build can now fetch code that no checksum covers.

MEDIUM because adding `git` to fetch submodules is legitimate. It is a signal, not a verdict.

A VCS client the recipe already needs for its own source is not a *new*
network reach: when `source=` already carries `git+`/`svn+`/`hg+`/`bzr+`/
`fossil+`, or the package name is a `-git`/`-svn`/… variant, that client is
excluded from the finding. `waycentral-git` moving `git` from `depends` to
`makedepends` while keeping a `git+https://` source is a packaging
correction, not a fetch capability.

### H064: Provides/Replaces Scope Expansion {#h064}

- **Severity:** HIGH (weight 25) for an established package, MEDIUM (weight 15) for a widely-provided one
- **Category:** `dependency`

<!-- name: Provides/Replaces Scope Expansion -->

- **Condition:** A newly claimed `provides`, `replaces` or `conflicts` names an established package (official repo or fallback observations) or a widely-provided one (observation count at or above `[h064] widely_provided_observations`, default 25).

Claiming another project's name redirects installs of that name to this
package. A `conflicts` entry only refuses co-installation; it is HIGH when the
target is widely depended on and INFO at weight 0 when it is merely established,
which keeps a documented file collision from reading as a hijack. Relatedness
suppresses the obvious false positive: variant, companion and sibling stems of
the package's own name never fire. Cold start cannot fire either branch, since
neither corpus nor pacman data exists to establish what is established. H064
always runs; D004 owns the `provides`/`replaces` claim and may double-report
when it is enabled (it is, by default).

Fire rate: 2 on the v1 corpus (0.05 %), both established-name claims: `jpegli-git` conflicts `libjxl` and `llama.cpp-cuda-git` provides `ggml`.

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

<!-- name: Dependency Vendored Into Source -->

- **Condition:** A dependency was removed and a new source entry appeared whose project name matches the removed dependency name.

Narrowed to that mechanical case on purpose. Vendoring a library bypasses the
distribution's security updates for it, and `[patterns] security_relevant_libraries`
is what raises the severity.

### H053: Name/Host Consensus Divergence {#h053}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`

<!-- name: Name/Host Consensus Divergence -->

- **Condition:** An ecosystem-prefixed package (`python-`, `ruby-`, `nodejs-`, ...) is sourced from neither its ecosystem's canonical hosts nor a known forge.

H053 reads the name as a claim about where a package should come from, and checks
the source against it. A `python-`, `ruby-` or `nodejs-` package is normally
published on that ecosystem's own index (PyPI, RubyGems, npm), built straight
from a forge such as GitHub or GitLab, or downloaded from the project's own
distribution host (`nodejs.org` for Node.js, `cpan.org` and its subdomains for
Perl). The canonical set matches the host and its subdomains, so
`search.cpan.org` is the same ecosystem as `cpan.org`. This rule fires on a new
package whose name claims an ecosystem but whose source comes from a host that is
neither: a name pointing one way while the source points another is the shape of
a typosquat, or of a dependency silently redirected to somebody else's server. It
compares the name to the source, not the code, so a project that legitimately
mirrors its release elsewhere, or publishes only from a personal server, can trip
it. The finding names the prefix and the host so the reader can judge that call.

### H059: Name/Repo Divergence {#h059}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`

<!-- name: Name/Repo Divergence -->

- **Condition:** The package name and the repository it is built from share no meaningful token. A leading name token that is the acronym of consecutive words in the repository path (for example `qsc` for `Qualcomm Software Center`) counts as a match.

### H104: Placeholder Package {#h104}

- **Target:** programmatic (recipe text, 2-of-3 signals)
- **Severity:** INFO (weight 0, report-only)
- **Category:** `naming`

<!-- name: Placeholder Package -->

- **Condition:** **Two of three** signals: `pkgver` is `0.0.0`; every `package`/`package_*` body ships nothing (only `echo`/`printf`/`true`/`:`, no install verb and no write into `$pkgdir`); and the declared checksum is a dummy sentinel (`DUMMY-FOR-INITIALIZATION`, a single repeated character, `SKIP`) or there is neither a source nor a checksum.

A placeholder reserves a name in the AUR while installing nothing - it builds, runs, and ships an empty package. Individually it is inert, so the finding is not a payload claim: it states that the recipe claims a name it does not fill, which is worth a human's eye because a burst of them is a name-squatting campaign ([#41](https://github.com/emiliano-go/trustsight/issues/41)). The two-of-three threshold keeps a legitimate project pinned at a `0.0.0` release or an unusual-but-real package function from reading as a reservation. Weight 0 until the benign corpus calibrates it; read from the recipe text, so it fires identically whether the package is first seen, edited, or checked with `trustsight lint`.

### D005: Official-Repo Name Shadow {#d005}

- **Target:** programmatic (recipe text: pkgname/conflicts against official repos)
- **Severity:** MEDIUM (weight 0, report-only)
- **Category:** `dependency`

<!-- name: Official-Repo Name Shadow -->

- **Condition:** A ``pkgname`` output is exactly an established package, or a ``conflicts`` entry names an established package unrelated to this one.

H064 and D004 own the *added* ``provides``/``replaces``/``conflicts``. This rule owns the name the recipe carries now: a split output whose name pacman already resolves elsewhere, or a conflict whose target became an official package after the recipe declared it. The variant carve-out is the ordinary pattern - ``foo-git`` conflicting ``foo`` is suppressed - so the finding names a name claim that stands alone. "Established" is official-repo membership, falling back to the dependency observation proxy exactly as H064 does, and cold start fires nothing. Weight 0 until the benign corpus calibrates it; the recipe's current text is read on the fresh path, the incremental path and ``trustsight lint``.
