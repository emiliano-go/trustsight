# TrustSight

<img src="https://raw.githubusercontent.com/emiliano-go/trustsight/refs/heads/master/docs/assets/images/trustsight-banner.png" alt="TrustSight" width="700"/>

Audits AUR PKGBUILD updates before you install: detects structural changes, suspicious commands, typosquatting, and novelty signals, then produces a deterministic risk score with a plain-English explanation.

<p align="center">
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white&style=for-the-badge" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-10AC84?style=for-the-badge" alt="License">
  </a>
  <a href="https://deepwiki.com/emiliano-go/trustsight/">
    <img src="https://img.shields.io/badge/DeepWiki-8A2BE2?logo=readthedocs&logoColor=white&style=for-the-badge" alt="DeepWiki">
  </a>
  <a href="https://github.com/emiliano-go/trustsight/actions/workflows/test.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/emiliano-go/trustsight/test.yml?branch=master&style=for-the-badge&logo=github&label=Tests" alt="Tests">
  </a>
  <a href="https://pypi.org/project/trustsight/">
    <img src="https://img.shields.io/pypi/v/trustsight?logo=pypi&logoColor=white&style=for-the-badge" alt="PyPI">
  </a>
</p>

---

## Setup

```bash
# 1. Install
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight/packaging/aur
makepkg -si

# 2. Scan your outdated AUR packages
trustsight review
```

Requires **Python 3.11+** and **Arch Linux** (the tool discovers packages via `pacman -Qm`, `pacman -Sl` for local repos, or `--repo`/`--all-repos` flags).

The score is always deterministic and calculated locally. Verdicts are template-based, describing each finding in plain English, for example `"Version bump. modified PKGBUILD, .SRCINFO. Signals: checksum disabled; novel dependency 'pyfoo' added in depends."`

> **Not published to the AUR yet.** Build from the PKGBUILD in this repository.
> Also installable via `pip install trustsight`.

---

## What it detects

| Attack / Risk | How TrustSight catches it |
|---|---|
| **Piped shell scripts** (`curl \| bash`, `base64 \| sh`) | Scans every new or changed line for command-subprocess pipelines (R001, ~100% recall on known cases) |
| **Obfuscated commands** (encoded strings, environment subversion like `LD_PRELOAD`) | Resolves variables and decodes known obfuscation patterns; flags build-environment tampering (R007, R070) |
| **Checksum disabled or removed** | Compares old vs new `sha256sums` / `md5sums` arrays (R004, R005) |
| **Source URL typosquatting** (`githab.com` instead of `github.com`) | Character-level edit distance against known forge domains (R008) |
| **Package-name typosquatting** (e.g. `libuvc` resembling `libuv`) | Edit-distance comparison against more popular packages in the seed database (R074) |
| **URL swapped without a version bump** | Tracks source URL changes that are not accompanied by a new version (C003) |
| **Novel / never-before-seen URLs or maintainers** | Compares against a bundled seed of 178,491 known AUR source URLs; flags first-seen domains and maintainers (novelty tier) |
| **Unicode bidi override attacks** (invisible characters that change how text displays) | Detects directionality overrides and homoglyph codepoints in PKGBUILD content (R013) |
| **LLM prompt injection** in package metadata | Pattern-matches common injection templates; primary defense is structural (the LLM cannot change the score) (R012) |
| **GPG verification removed** | Detects when `validpgpkeys` was populated and is now empty (R069) |
| **Untrusted maintainer takeover** | A maintainer change to someone never seen before (R071) |
| **Stale package revived** | A package with no updates for over a year suddenly gets one (R067) |
| **Accelerated release cadence** | 3+ commits in the last 24 hours (R073, informational) |

## What it cannot detect

| Limitation | Why |
|---|---|
| **Malicious upstream release tarballs** | TrustSight audits the PKGBUILD, not the binaries it downloads. A clean build file can point to a compromised tarball. |
| **Deliberately unremarkable attacks** | If no commands are added, no URLs change, and no checksums are disabled, there is no diff signal. The update is invisible to this kind of analysis. |
| **Build-dependency attacks** | A malicious `makedepends` or `depends` entry is outside TrustSight's scope. It audits the recipe, not the second-order supply chain. |
| **Runtime attacks** | The tool never executes the PKGBUILD, never runs extracted commands, and never modifies your system. |
| **Zero-day structural attacks** | Rules are pattern-based and calibrated against a known corpus. A novel attack that leaves no matching pattern will not fire. |

The output is a **risk assessment**, not a proof of safety. A clean score means no known risk signals fired, not that the package is safe. See the [trust model](docs/explanation/trust-model.md) for details.

---

## The 30-second example

```bash
trustsight review
```

```
                        TrustSight Review
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package         ┃ Risk Score   ┃ Verdict                                   ┃
┃                 ┃              ┃                                           ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ chez-scheme-bin │   0/100      │ Version bump. No structural changes.      │
├─────────────────┼──────────────┼───────────────────────────────────────────┤
│ sketchy-pkg     │  35/100      │ R004 HIGH  Checksum disabled (SKIP).      │
│                 │              │ C003 INFO  Source URL changed without     │
│                 │              │            version bump.                  │
│                 │              │ SOURCE_BUCKET MEDIUM  New domain:         │
│                 │              │   sketchy-cdn.invalid (unknown).          │
│                 │              │ NOVELTY HIGH  Source URL first seen       │
│                 │              │   globally.                               │
│                 │              │ PINNING INFO  Source pinning: unpinned.   │
│                 │              │ Verdict: Checksum disabled; sources       │
│                 │              │   replaced with content from an unknown,  │
│                 │              │   never-before-seen domain.               │
├─────────────────┼──────────────┼───────────────────────────────────────────┤
│ obsidian-beta   │  15/100      │ INCONCLUSIVE. Only 2 prior observations;  │
│                 │              │ no high-severity signals from a cold DB.  │
└─────────────────┴──────────────┴───────────────────────────────────────────┘
```

The tiered evidence display is the differentiator: every signal (rule, bucket, novelty, pinning, verification) is shown with its contribution and severity. You see **why** the score is what it is.

---

## Commands

| Command | What it does |
|---|---|
| [`trustsight review`](docs/reference/cli.md) | Scan outdated AUR packages and produce a scored table with tiered evidence. Supports `--repo`, `--foreign`, `--all-repos`, `--verbose` flags. |
| [`trustsight inspect <package>`](docs/reference/cli.md) | Deep-dive on a single package: full score breakdown, source URLs, resolved commands, novelty context. |
| [`trustsight history <package>`](docs/reference/cli.md) | Show past analysis results for a package. |
| [`trustsight config set`](docs/reference/cli.md) | Set individual config keys. |
| [`trustsight seed-db`](docs/reference/cli.md) | Import the bundled URL database for novelty detection. Runs automatically on first review. |
| [`trustsight list`](docs/reference/cli.md) | List all packages tracked in the database. |
| [`trustsight status`](docs/reference/cli.md) | Show database and system health statistics. |
| [`trustsight db`](docs/reference/cli.md) | Database maintenance (`check`, `vacuum`, `backup`). |
| [`trustsight override`](docs/reference/cli.md) | Suppress a rule that misfires on your packages. |
| [`trustsight lint-rules`](docs/reference/cli.md) | Check `rules.toml` for unreachable or malformed rules. |

---

## How scoring works

Scoring is fully deterministic: same input always produces the same score. The pipeline is:

1. **Diff** the old and new PKGBUILD
2. **Apply rules** to detect structural changes, suspicious commands, typosquatting, etc.
3. **Classify URLs** into trust buckets (official, self-hosted, unknown, homograph)
4. **Check novelty** against the local database of known URLs and maintainers
5. **Calculate score** from 0-100 by summing weighted contributions across four evidence tiers

Signals come from 13 detection rules (R001-R013), 44 code-emitted rules (R039-R082), 4 dependency-graph rules (D001-D004), and 7 code-structure rules (C001-C007), all calibrated against a 3,322+ diff corpus of benign AUR updates.

Verdicts are template-based, describing each triggered finding in plain English. The score is never influenced by the verdict text.

See [scoring-philosophy.md](docs/explanation/scoring-philosophy.md).

---

## Security model

TrustSight is **evidence-producing**, not proof-of-safety. It audits and does not install. The tool never runs the PKGBUILD, never executes extracted commands, and never modifies your system. Every finding is traceable to a specific diff line, URL, or novelty record. The output is a structured risk assessment to inform your decision, not a gate. See [trust-model.md](docs/explanation/trust-model.md).

---

## License

MIT

---

## Documentation hub

| Section | Description |
|---|---|
| [Getting Started](docs/getting-started/) | One-tutorial path from install to first review |
| [Full documentation](docs/index.md) | Docs landing page |
| [Contributing](CONTRIBUTING.md) | How to report bugs, contribute code, improve docs |
| [Security](docs/security.md) | Vulnerability disclosure policy |
| [License](docs/license.md) | MIT full text |
