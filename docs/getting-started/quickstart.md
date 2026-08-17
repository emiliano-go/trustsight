# Quickstart

This guide walks through the single happy path: install, run a review, and understand the output.

---

## 1. Install

```bash
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight/packaging/aur
makepkg -si
```

See [installation](installation.md) for details.

## 2. Run a review

```bash
trustsight review
```

This command:

1. Collects installed package names and versions from your system (foreign via `pacman -Qm`, or from local repos via `--repo`/`--all-repos`),
2. Compares them against an offline AUR metadata snapshot to find outdated packages (downloads the snapshot on first run, and refetches it once it is more than an hour old),
3. Clones each outdated package's repository,
4. Diffs the old and new PKGBUILD and `.install` files,
5. Applies the published R-series detection, C-series structural, D-series dependency, S-series sabotage, and X-series crossfire rules,
6. Classifies all new source URLs into trust buckets,
7. Checks novelty against the local database,
8. Calculates a deterministic score from 0-100,
9. Prints one panel per package, and a summary line.

## 3. Read the output

```
╭───────────────────────────── some-app-bin ─────────────────────────────╮
│  Version  3.1.0-1 → 3.1.1-2                                            │
│  Status   Only pkgver and sha256sums changed. Review the diff before   │
│           building.                                                    │
│  Changed  pkgver 3.1.0-1 -> 3.1.1-2                                    │
│           checksums added or changed                                   │
╰────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────── sketchy-package ────────────────────────────╮
│  Version  0.9.2-1 → 1.0.0-2                                            │
│  Status   The update is not trivial. Review it.                        │
│           PKGBUILD line 12  Checksum Disabled: sha256sums=('SKIP')     │
│           [R004]                                                       │
│           Source URL classified as unknown                             │
│           (https://sketchy-cdn.example.com/p.tar.gz) [SOURCE_BUCKET]   │
│  Changed  pkgver 0.9.2-1 -> 1.0.0-2                                    │
│           source host added: sketchy-cdn.example.com                   │
╰────────────────────────────────────────────────────────────────────────╯
2 package(s) needing update and reviewed out of 12 installed
```

### What a panel says

| Row | Meaning |
|--------|---------|
| **Version** | Installed version against what the AUR advertises. For a VCS package the two are not comparable and the row says so rather than drawing an arrow. |
| **Status** | The verdict, then one line per finding: the file, the line and the rule that produced it. |
| **Changed** | What moved in the recipe, whether or not a rule matched it. |
| **Required by** | Only under [`--deps`](#reviewing-the-dependencies-themselves): the packages that declare this one. |

The summary line counts what needed review separately from what was read, so a
run cut short by `--limit` says how many it left unread rather than reporting
the smaller number as the whole.

**There is no score column by default.** The default output is evidence - the
finding, the file, the line - because a number invites a glance where the
evidence invites a decision. Add `--score` for `Score  45/100 (Medium)`, or
`--risk` for the band alone.

### What the scores mean in context

- **0-20 (UNFLAGGED)**: No significant risk signals. Routine version bumps with checksum updates land here. **Most packages will score 0**; this is normal and expected.
- **21-50 (FLAGGED: Medium)**: One or more risk signals fired. Possible novelty, unknown domains, or a disabled checksum.
- **51-80 (FLAGGED: High)**: Multiple signals. Investigate with `trustsight inspect <name>`.
- **81-100 (FLAGGED: Critical)**: Strong structural signals, or FATAL rules triggered (R012/R013).
- **INCONCLUSIVE**: Either the score fell in the Medium range with nothing strong behind it and a cold database (fewer than 25 prior analyses of this package; novelty reaches full weight at 50), or the run could not examine the whole change (a truncated diff, an over-long line, an unavailable repository tree, or a `source=` URL computed at build time). Both mean the tool does not have enough to answer; this is **not** the same as UNFLAGGED.

### Key teaching moments

**"Novelty inactive on a cold database"**: The maturity gate scales novelty signals by the database-wide effective observation count divided by 50. At zero observations, novelty weight is 0; at 50, it reaches full weight. A verified seed normally warms an eligible first CLI `review` or `inspect`; without it, the database starts cold. Analyses of any packages contribute to the same global maturity count. Learn more at [cold start and maturity](../explanation/cold-start-and-maturity.md).

**Most packages score 0**: The vast majority of AUR updates are clean version bumps. If every package scores high, check your database state or look for systematic issues.

**A package scoring 35+**: Worth inspecting with `trustsight inspect <name>`. The detailed breakdown shows exactly which rules fired and why.

**No alerts is not a certificate**: An UNFLAGGED result means no published rule matched the evidence that was examined - nothing more. TrustSight is an instrument, not a judge; the update decision stays with you. The [security model](../security.md) is the exact statement of that boundary.

**INCONCLUSIVE is not UNFLAGGED**: When verdict reads "INCONCLUSIVE", the tool could not gather enough data to give a confident answer. Treat it as "look manually." See [what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md).

---

## 4. Dependencies are reviewed too

An AUR package's `depends` and `makedepends` can name other AUR packages, and
`makepkg` builds those on your machine in the same run. So by default
TrustSight also analyses the package's direct AUR dependencies, and each one
appears as a mini-card nested inside its parent's card:

```
╭──────────────────── some-trusted-tool ─────────────────────╮
│  Version       2.4.1-1 → 2.4.2-2                           │
│  Status        The update is not trivial. Review it.       │
│                PKGBUILD line 17  Install hook performs a   │
│                privileged operation [R062]                 │
│  Changed       pkgver 2.4.1-1 -> 2.4.2-2                   │
│                                                            │
│  Dependencies                                              │
│                ╭──────────── L1  libhelper ─────────────╮  │
│                │ Findings 2                             │  │
│                ╰────────────────────────────────────────╯  │
╰────────────────────────────────────────────────────────────╯
1 package(s) needing update and reviewed out of 1 installed
Tip: those dependencies are summarised, not reviewed.
`trustsight review --deps` reviews each as a package in its
own right and names what requires it; add `--depth n` for
deeper levels.
```

Each dependency is a full analysis in its own right - its own findings, its own
score, its own band. A dependency's risk is never folded into its parent's
score, so the card is a pointer, not a component of the parent's number. The
band is withheld here like everywhere else until you pass `--score` or
`--risk`; with `--risk` the card gains a `Risk  High` line.

### Reviewing the dependencies themselves

The card is a summary. To make the dependencies the subject - each with its own
panel, findings and verdict - use `--deps`:

```bash
trustsight review --deps            # the direct dependencies
trustsight review --deps --depth 2  # and theirs
```

Each one then reports **Required by**: the packages in the reviewed set that
declare it. A dependency three packages need is the one to read first.

```
╭──────────────────────────── libhelper ─────────────────────────────╮
│  Version      0.8.1-1 → 0.9.0-2                                    │
│  Status       The update is not trivial. Review it.                │
│               PKGBUILD line 8  Install hook performs a privileged  │
│               operation [R062]                                     │
│  Changed      pkgver 0.8.1-1 -> 0.9.0-2                            │
│  Required by  some-trusted-tool                                    │
│               sketchy-pkg                                          │
╰────────────────────────────────────────────────────────────────────╯
2 AUR dependencies reviewed for 3 installed package(s)
```

Control how far it goes:

```bash
trustsight inspect some-pkg --depth 0    # this package only
trustsight inspect some-pkg --depth 2    # two levels down
trustsight review --depth -1             # the whole closure
```

`-1` walks every level, bounded at 8 levels and 200 dependencies per run -
the dependency graph is written by the party under review, so it does not get
to decide how much work your machine does. If a walk stops early you are told:
the result carries a `deps_not_scanned` coverage gap and cannot report as
unflagged. A walk that finished the depth you asked for is not a gap.

To make a different depth permanent, put it in `config.toml`:

```toml
[depth]
levels = 2
```

---

## Next steps

- Read the [depth reference](../reference/configuration.md#depth) for the ceilings and the gap semantics.
- Learn to [read a full report](reading-a-report.md): understand every section of the inspect output.
- See [guides](../guides/index.md) for real workflows: CI integration, alerting, batch review.
