<!-- description: Full documentation for TrustSight, the deterministic AUR PKGBUILD audit tool: installation, guides, the complete rule catalog, and the security model behind it. -->

# TrustSight


Audits AUR PKGBUILDs before you update: catches careless malice and structural risk, and tells you what it can't verify.

TrustSight is an **instrument, not a judge**. It reports evidence - and the
absence of evidence - and never substitutes its report for your decision. Absence
of alerts is not a promise of safety. The [security model](security.md) states
the boundaries behind that promise, and how each one is enforced.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white&style=for-the-badge)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-10AC84?style=for-the-badge)](https://github.com/emiliano-go/trustsight/blob/master/LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/emiliano-go/trustsight/test.yml?branch=master&style=for-the-badge&logo=github&label=Tests)](https://github.com/emiliano-go/trustsight/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/trustsight?logo=pypi&logoColor=white&style=for-the-badge)](https://pypi.org/project/trustsight/)

Ready to get started? Head over to the [Tutorial](tutorial/installation.md) for installation and your first review.

---

## What a run produces

Every review is a deterministic, structured **evidence report**, computed
locally from the bytes on disk. Findings come first:

- **Findings** - each is a named rule with the file, side and line it matched,
  and a plain-English description of what it saw.
- **The change summary** - what the update altered: modified files, source and
  checksum array moves, dependency additions, and maintainer or version changes.
- **Coverage gaps** - what the run could not fully assess, stated outright so an
  incomplete analysis is never mistaken for a clean one.
- **A template verdict** - the findings rendered into a review direction. It
  describes what fired; it never grants permission to skip review.

The default output is evidence, not a verdict, and nothing it prints is a
promise of safety. The evidence is what you decide on. See
[How TrustSight Works](explanation/index.md) for the full pipeline and the
[security model](security.md) for what a result does and does not claim.

!!! tip "Rules Reference"

    TrustSight ships 241 documented detection rules across eleven families: 37 R-series detection rules, 103 H-series heuristics, 32 C-series structural rules, four D-series dependency rules, eight S-series sabotage rules, 33 X-series crossfire rules, five M-series meta rules, three E-series entropy rules, three T-series temporal rules, and seven G-series correlation rules, and six U-series manifest rules. The identifier space is intentionally non-contiguous, so a range is not a count; the [catalog](reference/rules/index.md) is authoritative. Two further families are reported but never weighted: declared-practice findings P001-P008 (seven findings; P004 is skipped) and unverifiable findings W001-W010. The optional L9 build lane adds eight artifact rules A001-A008, reported outside the heuristic when enabled. Each rule has a severity, match target, and scope that determine how it fires and what it reports.

    [Browse the full rule catalog &rarr;](reference/rules/index.md)

---

## Assurance layers

Every rule also carries an **evidence layer**, `L1`-`L8`, naming the kind of
evidence a finding is. Layers are not ordered barriers: a finding at `L4` does
not mean `L1`-`L3` were passed, and a layer that stayed silent is not proof of
safety.

| Layer | The question its evidence answers | Rule families |
|---|---|---|
| `L1` Structural coherence | Does the change hang together as an honest edit? | `C`, `M` |
| `L2` Readability | Was anything hidden from the reader? | `W`, and the refusal rules `X026`/`X027` |
| `L3` Payload signature | Does it do a known-bad thing? | `R`, `S` |
| `L4` Evasion shape | Was it *written* to defeat reading? | `X`, `E` |
| `L5` Behavioral suspicion | Does the package's story make sense? | `H` |
| `L6` Ecosystem memory | Has the ecosystem seen this before? | `D`, `T` |
| `L7` Known indicators | Is it on the list? | `I` |
| `L8` Campaign correlation | Do other packages tell the same story? | `G` |

The report keeps detection and coverage independent - `L3 fired` records the
check that matched, `L1 passed` records that a check was read in full and stayed
silent, and `L8 not_applicable` records a check that could not run - and the
optional `L9` build lane inspects the built package rather than the diff.
[How TrustSight groups security evidence](assurance-layers.md) covers the labels,
the coverage states, and a worked report example.

---

## Tutorial

| Page | What it covers |
|------|----------------|
| [Installation](tutorial/installation.md) | Build the repository's PKGBUILD with `makepkg`. |
| [Quickstart](tutorial/quickstart.md) | Run your first review, read the output table, understand the verdicts. |
| [Reading a Report](tutorial/reading-a-report.md) | Deep dive into the findings, evidence tiers, rule firings, and novelty context. |

## Explanation

| Page | What it covers |
|------|----------------|
| [How TrustSight Works](explanation/index.md) | Full pipeline: parse, analyse, classify, translate. |
| [Assurance Layers](assurance-layers.md) | How rules group into L1-L8 evidence categories, detection vs coverage, and what a layer label does and does not mean. |
| [Security Model](security.md) | What TrustSight guarantees while reading hostile input, why every result is deterministic and reproducible, what a verdict claims, and how each invariant is enforced. |
| [Cold Start and Maturity](explanation/cold-start-and-maturity.md) | Why novelty is meaningless on run one; maturity gating. |
| [Corpus and Priors](explanation/corpus-and-priors.md) | AUR-wide snapshot, global priors, local novelty weighting. |
| [Fire Rates](explanation/fire-rates.md) | Per-rule false-positive rates on the benign corpus. |
| [What TrustSight Cannot See](explanation/what-trustsight-cannot-see.md) | The reasoned ceiling of the tool. |
| [Why Static Analysis](explanation/why-static-analysis.md) | SAST by design, customization surface. |
| [Benchmarks and Methodology](explanation/benchmarks-and-methodology.md) | Per-class separation, CI gates, reproducible evaluation. |
| [Recipe-Targeted User Rules](explanation/structural-user-rules.md) | A second rule kind that matches typed recipe structure, its five primitives, and the HIGH cap. |
| [Cross-File Consistency](explanation/cross-file-consistency.md) | How the recipe is compared against `.SRCINFO`, the committed tree and shipped hooks. |
| [The Typed Core](explanation/the-typed-core.md) | Why the diff and the PKGBUILD are each read once, so every finding cites the real file, side and line and unreadable structure is reported, never guessed. |

## Guides

| Guide | When to use it |
|-------|----------------|
| [Auditing Before Update](guides/auditing-before-update.md) | Everyday workflow: scan AUR packages before `yay -Syu`. |
| [Using in CI](guides/using-in-ci.md) | Gate package installs in CI/CD on the JSON report. |
| [Acting on a Flag](guides/acting-on-a-flag.md) | A package flagged above the review bar or returned INCONCLUSIVE - next steps. |
| [Configuring Rules and Weights](guides/configuring-rules-and-weights.md) | Edit `rules.toml` or `config.toml` to match your threat model. |
| [Tuning False Positives](guides/tuning-false-positives.md) | A rule is firing too often on your packages - identify and fix it. |

## Reference

| Page | What it covers |
|------|----------------|
| [Rules](reference/rules/index.md) | Complete R/H/C/D/S/X catalog with severity, weight, and description. |
| [Rule Nature](reference/rules/nature.md) | How each series detects: Regex, Heuristic, Check, Dependency, Sabotage, Crossfire, Practice, and Warning. |
| [CLI](reference/cli.md) | Full command reference for review, inspect, history, config. |
| [Configuration](reference/configuration.md) | config.toml and its sibling rule, host, pattern, naming, threshold, and domain files. |
| [Report Schema](reference/report-schema.md) | Stored PackageFact and CLI/API report JSON shapes. |
| [Glossary](reference/glossary.md) | The vocabulary: rule family, subject, evidence category, evidence tier, detection, coverage, boundary. |
| [Evidence Tiers](reference/evidence-tiers.md) | A/B/C/D evidence taxonomy with maturity gating. |
| [Exit Codes](reference/exit-codes.md) | 0 (analysis completed), 2 (error), and why a flag is not an exit code. |

## Contributing

| Page | What it covers |
|------|----------------|
| [Development Setup](contributing/development-setup.md) | Set up a local dev environment. |
| [Writing a Rule](contributing/writing-a-rule.md) | R-series regex, H-series heuristic and C-series rule guidelines. |
| [Re-baselining](contributing/re-baselining.md) | Update benchmarks after detection changes. |

---

[Changelog](changelog.md) &middot; [Security](security.md) &middot; [License](license.md)
