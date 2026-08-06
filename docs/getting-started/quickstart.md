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
2. Compares them against an offline AUR metadata snapshot to find outdated packages (downloads the snapshot on first run; subsequent runs reuse it),
3. Clones each outdated package's repository,
4. Diffs the old and new PKGBUILD and `.install` files,
5. Applies detection rules (R001-R013, R039-R131) and context rules (C001-C007, D001-D004),
6. Classifies all new source URLs into trust buckets,
7. Checks novelty against the local database,
8. Calculates a deterministic score from 0-100,
9. Prints a summary table.

## 3. Read the output

```
                               TrustSight Review
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package                  ┃ Risk Score ┃ Verdict                                   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ some-app-bin             │      0/100 │ Version bump. No structural changes.      │
│ sketchy-package          │     55/100 │ Checksum disabled (R004). New domain:     │
│                          │            │ sketchy-cdn.example.com (unknown).        │
│ first-run-pkg            │     25/100 │ New source URL first seen globally         │
│                          │            │ (novelty), no strong structural signals.   │
│ unknown-pkg              │     22/100 │ Source URL added from unknown domain.      │
└──────────────────────────┴────────────┴───────────────────────────────────────────┘
```

### Columns

| Column | Meaning |
|--------|---------|
| **Package** | Name of the AUR package with a newer version available |
| **Score** | Deterministic risk score from 0 to 100. Higher = more risk signals fired. |
| **Verdict** | Plain-English summary. Template-based, fully deterministic. |

### What the scores mean in context

- **0-20 (UNFLAGGED)**: No significant risk signals. Routine version bumps with checksum updates land here. **Most packages will score 0**; this is normal and expected.
- **21-50 (FLAGGED: Medium)**: One or more risk signals fired. Possible novelty, unknown domains, or a disabled checksum.
- **51-80 (FLAGGED: High)**: Multiple signals. Investigate with `trustsight inspect <name>`.
- **81-100 (FLAGGED: Critical)**: Strong structural signals, or FATAL rules triggered (R012/R013).
- **INCONCLUSIVE**: Either the score fell in the Medium range with nothing strong behind it and a cold database (fewer than 25 prior analyses of this package; novelty reaches full weight at 50), or the run could not examine the whole change (a truncated diff, an over-long line, an unavailable repository tree, or a `source=` URL computed at build time). Both mean the tool does not have enough to answer; this is **not** the same as UNFLAGGED.

### Key teaching moments

**"Novelty inactive on first run"**: The first time you run `trustsight review`, many packages may show novelty-based scores. The maturity gate scales novelty signals by `observation_count / 50`. At zero observations, novelty weight is 0. Scores only reflect novelty fully after 50 analyses of that package. Learn more at [cold start and maturity](../explanation/cold-start-and-maturity.md).

**Most packages score 0**: The vast majority of AUR updates are clean version bumps. If every package scores high, check your database state or look for systematic issues.

**A package scoring 35+**: Worth inspecting with `trustsight inspect <name>`. The detailed breakdown shows exactly which rules fired and why.

**No alerts is not a certificate**: An UNFLAGGED result means no published rule matched the evidence that was examined - nothing more. TrustSight is an instrument, not a judge; the update decision stays with you. The [security model](../security.md) is the exact statement of that boundary.

**INCONCLUSIVE is not UNFLAGGED**: When verdict reads "INCONCLUSIVE", the tool could not gather enough data to give a confident answer. Treat it as "look manually." See [what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md).

---

## Next steps

- Learn to [read a full report](reading-a-report.md): understand every section of the inspect output.
- See [guides](../guides/index.md) for real workflows: CI integration, alerting, batch review.
