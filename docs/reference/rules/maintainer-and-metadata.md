<!-- description: Rules for a change of ownership, a long-stable property changing, a maintainer's activity deviating from their baseline, or a new epoch. -->

# Maintainer and Metadata

Where these rules come from and what a finding means: [Rule Nature](../nature/maintainer-and-metadata.md).

Who owns the package changed (H026, H044, H074, C006), a property that held
across a long run of observations changed (H037, H049, H050, H051, H054), a
maintainer's activity deviated from their baseline (H058), or an epoch was
introduced (H063).

The longitudinal rules on this page do not read a diff at all. They read
`PropertyBreak` records from the corpus property layer, gated by `[longitudinal]
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
| [C030](#c030) | Epoch Removed With Version Unchanged | INFO |
| [H026](#h026) | Untrusted Maintainer Takeover | HIGH |
| [H037](#h037) | Long-Stable Property Changed | MEDIUM |
| [H044](#h044) | Ownership Transition | MEDIUM |
| [H049](#h049) | Source Host Changed | MEDIUM |
| [H050](#h050) | Version Scheme Changed | INFO |
| [H051](#h051) | Package Description Changed | MEDIUM |
| [H054](#h054) | Build System Changed | MEDIUM |
| [H058](#h058) | Maintainer Baseline Deviation | MEDIUM |
| [H063](#h063) | Epoch Introduced | MEDIUM |
| [H074](#h074) | Adopt-then-Modify | MEDIUM |
| [H086](#h086) | Adopted From Orphan | MEDIUM |
| [H088](#h088) | Adopted, Recipe Rewritten, Unpinned Fetch | HIGH |
<!-- /generated: page-index -->

### C006: Maintainer Change With New Source Domain {#c006}

- **Severity:** HIGH (weight 25)

- **Condition:** The maintainer changed **and** at least one added source URL is on a domain not present among the removed URLs.
- **Description:** Either signal alone is routine; maintainers change hands, domains migrate. Together they are the shape of an account takeover redirecting sources to attacker-controlled infrastructure. Requires maintainer metadata, so it fires only in the live path, not in offline corpus replay.

### H026: Untrusted Maintainer Takeover {#h026}

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
precursor to a malicious release. H026 composes those two ideas: maintainer
change (pnpm's "trust changed") gated by global novelty (Socket's "never seen
before"), applied to AUR maintainers instead of npm publishers.

**Cold-start gate:** On a fresh database every maintainer is globally novel,
so H026 fires on 100 % of maintainer-changed packages on first run. It is
suppressed until the maintainer table has enough history for "globally novel"
to mean something - gated identically to the other novelty signals via
[`maturity()` and `observation_count`](../../explanation/cold-start-and-maturity.md#maturity-gate).

### H063: Epoch Introduced {#h063}

- **Severity:** MEDIUM (weight 15), INFO for a bare `epoch=0`
- **Category:** `version`

- **Condition:** A diff introduces `epoch=` where the previous revision had none. Under `--full-recipe` there is no previous revision, so the finding says `epoch=N present` rather than claiming the field is new.

An epoch overrides normal version comparison, so introducing one forces an
upgrade regardless of what the version numbers say. A pre-existing epoch never
surfaces in a hunk, so bumping one is quiet. `epoch=0` is INFO: it initialises
the field without changing the ordering.

Fire rate: 14 on the v1 corpus (0.37 %).

### C030: Epoch Removed With Version Unchanged {#c030}

- **Severity:** INFO (weight 0)
- **Category:** `version`

- **Condition:** A diff drops `epoch=` while `pkgver` and `pkgrel` are
  unchanged by resolved value.

Removing an epoch is usually legitimate, so this is annotation-tier: it
carries no score and only records that the version-ordering override
silently disappeared. `H063` owns the introduction; `C030` the removal.

### H037: Long-Stable Property Changed {#h037}

- **Severity:** MEDIUM (weight 15)
- **Category:** `temporal`

- **Condition:** A tracked property with no more specific rule (`license`, `install_hook_present`) changed after a long stable run.

### H049: Source Host Changed {#h049}

- **Severity:** MEDIUM (weight 15)
- **Category:** `source`

- **Condition:** A long-stable `source_hosts` or `source_orgs` set changed to a non-empty set.

Source removal is not a host change: when the new set is empty, H002 owns the finding and H049 stays quiet. When both `source_hosts` and `source_orgs` change in one cycle, they are two views of the same source set, so H049 emits one finding that shows both triggers and scores once.

A documentation source (`LICENSE`, `COPYING`, `README`, `CHANGELOG`, …) is not
build provenance. Adding one does not change the source-host set, so a
licence file added from a different host no longer reads as a source move
(nhiicc).

### H050: Version Scheme Changed {#h050}

- **Severity:** INFO (weight 0)
- **Category:** `context`

- **Condition:** The package's version scheme changed (semver to date, and so on). Context only, by design.

### H051: Package Description Changed {#h051}

- **Severity:** MEDIUM (weight 15)
- **Category:** `integrity`

- **Condition:** A long-stable `pkgdesc` token set changed.

A declared `pkgver`/`pkgrel`/`epoch` move is the ordinary reason a
description changes, so the rule stands down for that cycle. It still fires
when the description changes at a stable version, which is the shape worth a
prompt.

### H054: Build System Changed {#h054}

- **Severity:** MEDIUM (weight 15)
- **Category:** `build`

- **Condition:** Long-stable `build_system_markers` or `build_line_count` changed.

A declared `pkgver`/`pkgrel`/`epoch` move is the ordinary reason a build
recipe changes, so the rule stands down for that cycle. It still fires when
the build system changes at a stable version, which is the shape worth a
prompt.

### H026: Untrusted Maintainer Takeover (corpus path) {#h026-corpus}

- **Severity:** HIGH (weight 25)
- **Category:** `maintainer`

- **Condition:** An ownership transition whose incoming maintainer maintained no package at all in the previous snapshot.

The per-package H026 asks the observation database whether an account has been
seen. On the corpus path the snapshot is the better witness: it names the
maintainer of every package in the AUR. H026 ships alongside H044 on the same
transition, as two findings on two pieces of evidence, so a handover between
established packagers carries H044 alone.

### H044: Ownership Transition {#h044}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`

- **Condition:** A package that existed in the previous snapshot changed to a different, non-empty maintainer.

A move to an empty maintainer is abandonment, which H046 and H060 handle as
orphan state rather than as a takeover.

### H058: Maintainer Baseline Deviation {#h058}

- **Severity:** MEDIUM (weight 15)
- **Category:** `adoption`

- **Condition:** A maintainer's activity this cycle deviates from their own recorded baseline by at least `[thresholds] h058.z_score` (default 2.0), once `h058.min_history_cycles` (default 3) cycles of their history exist.

H058 watches how much a maintainer does, not what a package contains. TrustSight
counts how many packages each maintainer updates in a cycle, and after a few
cycles it knows that maintainer's own normal pace. A cycle far above that pace is
flagged, because a burst of updates is what a hijacked account, or an account
that has just changed hands, tends to produce: the attacker publishes everything
at once, under a name the reviewers already trust. This is a prompt to look, not
proof. A maintainer with a genuinely busy day, or one who legitimately adopted
several packages at once, can trip it; adoption is reported on its own by
[H074](#h074) and [H086](#h086) from the maintainer field, without needing a
burst. Bumping one project's own naming family in lockstep (a kernel's
`-docs`/`-headers` splits, `foo`/`foo-bin`/`foo-qt` released together) is one
logical update spread over several package names, not a deviation, so the
rule stands down when every active package belongs to a single
relatedness cluster. Split outputs are the same shape even when the common
name sits behind an ecosystem prefix (`ttf-kreativekorp-lisa-*`): the rule
compares the members' **package bases**, so one base or one variant family
(`sqldef` plus `sqldef-bin`) is one update, and the finding's member list
still carries every output. The same holds for a periodic refresh of every
auto-tracking recipe: `-git`, `-latest` and `-nightly` names, and packages
whose `source=` is a `.git` checkout, take a new `pkgver` from upstream on
each sweep, so one cycle touches unrelated upstreams by construction. When
every active package is auto-tracking the rule stands down; each rebuilt
package is still analysed on its own for content.

### H074: Adopt-then-Modify {#h074}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`

- **Condition:** A package adopted this cycle also changed version in the same cycle, within `[thresholds] h074.window_days` (default 14).

H074 is the exception to the novelty ceiling described in
[what TrustSight cannot see](../../explanation/what-trustsight-cannot-see.md): it
fires on the **first** package of a campaign, from the maintainer field and
commit times alone, before any payload shape exists to recognise. Adoption
without a version change is quiet, and so is a change outside the window.

### H086: Adopted From Orphan {#h086}

- **Severity:** MEDIUM (weight 15)
- **Category:** `maintainer`

- **Condition:** The AUR reported this package as orphaned on a previous run, and now reports a maintainer.

This is H074's property on the **single-package path**. H045, H046, H057, H060
and H074 all describe adoption, and every one of them needs a `full-aur`
cycle: somebody running `trustsight review` over their installed packages saw
none of them, and those are the people the June 2026 campaign hit. H086 needs
only the AUR metadata the review path already fetches.

The comparison is against a *recorded* prior observation. `aur_orphaned` is
tri-state (1 orphaned, 0 maintained, -1 never asked), and H086 requires 1: a
database that has never seen this package says nothing, because "no record"
is not evidence of adoption. The corpus path follows the same rule: a package
absent from the previous metadata snapshot is a first observation, not an
orphan that gained a maintainer. Metadata that was unavailable on a run is
recorded as unknown rather than as either state, so a failed RPC cannot
manufacture an adoption or erase one.

Adoption is not by itself wrongdoing - packages are adopted honestly every
week, which is why this is MEDIUM. Its weight is in the
[H088](#h088) composition.

### H088: Adopted, Recipe Rewritten, Unpinned Fetch {#h088}

- **Severity:** HIGH (weight 25)
- **Category:** `takeover`

- **Condition:** All three of [H086](#h086) (adopted from orphan), [H087](integrity.md#h087) (recipe changed without upstream) and a build-time registry resolution (the `unpinned_build_deps` coverage gap's trigger) hold for the same diff.

This is the June 2026 campaign's chain in one rule, and it exists because none
of its three members can carry the weight alone.

Adoption is ordinary. A recipe-only change is ordinary. `npm install` inside
`prepare()` is so ordinary that H035 is deliberately scoped away from build
functions and a calibration gate keeps it there - the attack worked *because*
its build step looked like every other Node package's. Each part is under the
30 % benign fire-rate ceiling only by being mild.

Together they are not ordinary. A package that was orphaned last week, has a
new maintainer this week, whose upstream is byte-identical, and whose build
now resolves dependencies from a registry, is describing the attack chain
rather than resembling it. Scoring the conjunction is what lets the finding
clear the flag threshold without any single member spending fire rate it does
not have - the same reasoning [H036](count-based.md#h036) and
[H065](obfuscation.md#h065) use.

H088 does not replace the `unpinned_build_deps` coverage gap. The gap fires
whenever the build resolves from a registry, whether or not the other two
conditions hold, because the analysis genuinely could not see what will run.
H088 is a finding about this change; the gap is a statement about what was
never examined, and [B2](../../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)
keeps them separate.
