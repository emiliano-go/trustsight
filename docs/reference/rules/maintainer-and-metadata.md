# Maintainer and Metadata

Who owns the package changed (R071, R090, R108, R126, C006), or a property
that held for a long run of observations changed (R083, R094, R096, R097,
R098, R102, R115).

The longitudinal rules do not read a diff at all. They read `PropertyBreak`
records from the corpus property layer, gated by `[longitudinal]
stability_floor` (default 10): a value must hold at least that many
consecutive observations before a change is reported. Every one of them is
silent on a cold database by construction, because the first observation of
a property only inserts it.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [C006](#c006) | Maintainer Change With New Source Domain | HIGH |
| [R071](#r071) | Untrusted Maintainer Takeover | HIGH |
| [R071](#r071-corpus) | Untrusted Maintainer Takeover (corpus path) | HIGH |
| [R083](#r083) | Long-Stable Property Changed | MEDIUM |
| [R090](#r090) | Ownership Transition | MEDIUM |
| [R096](#r096) | Source Host Changed | MEDIUM |
| [R097](#r097) | Version Scheme Changed | INFO |
| [R098](#r098) | Package Description Changed | MEDIUM |
| [R102](#r102) | Build System Changed | MEDIUM |
| [R108](#r108) | Maintainer Baseline Deviation | MEDIUM |
| [R115](#r115) | Epoch Introduced | MEDIUM |
| [R126](#r126) | Adopt-then-Modify | MEDIUM |
| [R141](#r141) | Adopted From Orphan | MEDIUM |
| [R143](#r143) | Adopted, Recipe Rewritten, Unpinned Fetch | HIGH |
<!-- /generated: page-index -->

### C006: Maintainer Change With New Source Domain {#c006}

- **Severity:** HIGH (weight 25)
- **Condition:** The maintainer changed **and** at least one added source URL is on a domain not present among the removed URLs.
- **Description:** Either signal alone is routine; maintainers change hands, domains migrate. Together they are the shape of an account takeover redirecting sources to attacker-controlled infrastructure. Requires maintainer metadata, so it fires only in the live path, not in offline corpus replay.

### R071: Untrusted Maintainer Takeover {#r071}

- **Target:** programmatic (maintainer delta + global novelty)
- **Severity:** HIGH (weight 25) - always on; corpus rate TBD (requires live git history)
- **Category:** `maintainer`
- **Condition:** `maintainer_changed` is true **AND** the new maintainer is
  **globally novel** (never seen in the database across any package).

This is C006 (maintainer change) × global novelty - the "local signal weighted
by global rarity" composition the accuracy work identified as the missing
multiplier. A *known* maintainer adopting a package is routine (orphan
adoptions happen constantly). An *unknown* maintainer taking over is the
account-compromise / hostile-takeover shape. The novelty gate is what turns a
noisy signal (all maintainer changes) into a precise one (takeovers by
strangers).

**Origin:** pnpm's `trustPolicy: no-downgrade` and Socket.dev's maintainer
behaviour analysis. pnpm refuses to install a package whose trust evidence has
weakened since the previous version; Socket flags packages where a new,
never-before-seen maintainer gains publish permissions - the most reliable
precursor to a malicious release. R071 composes those two ideas: maintainer
change (pnpm's "trust changed") gated by global novelty (Socket's "never seen
before"), applied to AUR maintainers instead of npm publishers.

**Cold-start gate:** On a fresh database every maintainer is globally novel,
so R071 fires on 100 % of maintainer-changed packages on first run. It is
suppressed until the maintainer table has enough history for "globally novel"
to mean something - gated identically to the other novelty signals via
[`maturity()` and `observation_count`](../../explanation/cold-start-and-maturity.md#maturity-gate).

### R115: Epoch Introduced {#r115}

- **Severity:** MEDIUM (weight 15), INFO for a bare `epoch=0`
- **Category:** `version`
- **Condition:** A diff introduces `epoch=` where the previous revision had none.

An epoch overrides normal version comparison, so introducing one forces an
upgrade regardless of what the version numbers say. A pre-existing epoch never
surfaces in a hunk, so bumping one is quiet.

Fire rate: 0 of 3246.

### R083: Long-Stable Property Changed {#r083}

- **Severity:** MEDIUM (weight 15)
- **Category:** `temporal`
- **Condition:** A tracked property with no more specific rule (`license`, `install_hook_present`) changed after a long stable run.

### R096: Source Host Changed {#r096}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Condition:** A long-stable `source_hosts` or `source_orgs` set changed.

### R097: Version Scheme Changed {#r097}

- **Severity:** INFO (weight 0)
- **Category:** `context`
- **Condition:** The package's version scheme changed (semver to date, and so on). Context only, by design.

### R098: Package Description Changed {#r098}

- **Severity:** MEDIUM (weight 15)
- **Category:** `integrity`
- **Condition:** A long-stable `pkgdesc` token set changed.

### R102: Build System Changed {#r102}

- **Severity:** MEDIUM (weight 15)
- **Category:** `build`
- **Condition:** Long-stable `build_system_markers` or `build_line_count` changed.

### R071: Untrusted Maintainer Takeover (corpus path) {#r071-corpus}

- **Severity:** HIGH (weight 25)
- **Category:** `maintainer`
- **Condition:** An ownership transition whose incoming maintainer maintained no package at all in the previous snapshot.

The per-package R071 asks the observation database whether an account has been
seen. On the corpus path the snapshot is the better witness: it names the
maintainer of every package in the AUR. R071 ships alongside R090 on the same
transition, as two findings on two pieces of evidence, so a handover between
established packagers carries R090 alone.

### R090: Ownership Transition {#r090}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`
- **Condition:** A package that existed in the previous snapshot changed to a different, non-empty maintainer.

A move to an empty maintainer is abandonment, which R093 and R111 handle as
orphan state rather than as a takeover.

### R108: Maintainer Baseline Deviation {#r108}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`
- **Condition:** A maintainer's activity this cycle deviates from their own recorded baseline by at least `[thresholds] r108.z_score` (default 2.0), once `r108.min_history_cycles` (default 3) cycles of their history exist.

### R126: Adopt-then-Modify {#r126}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`
- **Condition:** A package adopted this cycle also changed version in the same cycle, within `[thresholds] r126.window_days` (default 14).

R126 is the exception to the novelty ceiling described in
[what TrustSight cannot see](../../explanation/what-trustsight-cannot-see.md): it
fires on the **first** package of a campaign, from the maintainer field and
commit times alone, before any payload shape exists to recognise. Adoption
without a version change is quiet, and so is a change outside the window.

### R141: Adopted From Orphan {#r141}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`
- **Condition:** The AUR reported this package as orphaned on a previous run, and now reports a maintainer.

This is R126's property on the **single-package path**. R092, R093, R107, R111
and R126 all describe adoption, and every one of them needs a `full-aur`
cycle: somebody running `trustsight review` over their installed packages saw
none of them, and those are the people the June 2026 campaign hit. R141 needs
only the AUR metadata the review path already fetches.

The comparison is against a *recorded* prior observation. `aur_orphaned` is
tri-state (1 orphaned, 0 maintained, -1 never asked), and R141 requires 1: a
database that has never seen this package says nothing, because "no record"
is not evidence of adoption. Metadata that was unavailable on a run is
recorded as unknown rather than as either state, so a failed RPC cannot
manufacture an adoption or erase one.

Adoption is not by itself wrongdoing - packages are adopted honestly every
week, which is why this is MEDIUM. Its weight is in the
[R143](#r143) composition.

### R143: Adopted, Recipe Rewritten, Unpinned Fetch {#r143}

- **Severity:** HIGH (weight 25)
- **Category:** `takeover`
- **Condition:** All three of [R141](#r141) (adopted from orphan), [R142](integrity.md#r142) (recipe changed without upstream) and a build-time registry resolution (the `unpinned_build_deps` coverage gap's trigger) hold for the same diff.

This is the June 2026 campaign's chain in one rule, and it exists because none
of its three members can carry the weight alone.

Adoption is ordinary. A recipe-only change is ordinary. `npm install` inside
`prepare()` is so ordinary that R081 is deliberately scoped away from build
functions and a calibration gate keeps it there - the attack worked *because*
its build step looked like every other Node package's. Each part is under the
30 % benign fire-rate ceiling only by being mild.

Together they are not ordinary. A package that was orphaned last week, has a
new maintainer this week, whose upstream is byte-identical, and whose build
now resolves dependencies from a registry, is describing the attack chain
rather than resembling it. Scoring the conjunction is what lets the finding
clear the flag threshold without any single member spending fire rate it does
not have - the same reasoning [R082](count-based.md#r082) and
[R117](obfuscation.md#r117) use.

R143 does not replace the `unpinned_build_deps` coverage gap. The gap fires
whenever the build resolves from a registry, whether or not the other two
conditions hold, because the analysis genuinely could not see what will run.
R143 is a finding about this change; the gap is a statement about what was
never examined, and [B2](../../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)
keeps them separate.
