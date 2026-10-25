<!-- uid: TS-0085 -->
<!-- anchor: h029-rule -->
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
