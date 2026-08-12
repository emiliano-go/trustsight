# TrustSight

<img src="https://raw.githubusercontent.com/emiliano-go/trustsight/refs/heads/master/docs/assets/images/trustsight-banner.png" alt="TrustSight" width="700"/>

Audits AUR PKGBUILD updates before you install: detects structural changes, suspicious commands, typosquatting, and novelty signals, then produces a deterministic evidence report.

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

> Not published to the AUR yet: `aur.archlinux.org/trustsight.git` does not exist. Build from the PKGBUILD in this repository.

```bash
# 1. Install
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight/packaging/aur
makepkg -si

# 2. Scan your outdated AUR packages
trustsight review
```

Requires **Python 3.11+** and **Arch Linux** (the tool discovers packages via `pacman -Qm`, `pacman -Sl` for local repos, or `--repo`/`--all-repos` flags).

The analysis is deterministic and calculated locally. Verdicts are template-based, describing each finding in plain English, for example `"Version bump. modified PKGBUILD, .SRCINFO. Signals: checksum disabled; novel dependency 'pyfoo' added in depends."`

Baselines ship as signed GitHub release assets (`baseline-seed.tar.gz`, IOC baselines, the corpus). On first use the tool downloads the novelty seed and imports it only after its ed25519 signature verifies against the pinned distribution key; when offline, the attempt is skipped silently and the run starts cold. See [installation](https://trustsight.emiliano-go.com/getting-started/installation/) for details.

---

## Security model

TrustSight is **evidence-producing**, not proof-of-safety. Read the [full security model](https://trustsight.emiliano-go.com/security/) for the threat model, invariants, and enforcement gates. It audits and does not install. The tool never runs the PKGBUILD, never executes extracted commands, and never modifies your system. Every finding is traceable to a specific diff line, URL, or novelty record. The output is a structured evidence report, not a gate. See [what TrustSight cannot see](https://trustsight.emiliano-go.com/explanation/what-trustsight-cannot-see/).

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
| **Novel / never-before-seen URLs or maintainers** | Compares against the release-channel seed (about 180,000 known source URLs and 35,587 hashed maintainer identities, verified against the pinned key on import); flags first-seen domains and maintainers (novelty tier) |
| **Known-bad indicators** | Matches package URLs and strings against signed, federated IOC baselines from the release channel; reported in the IOC tier, outside the heuristic score |
| **Unicode bidi override attacks** (invisible characters that change how text displays) | Detects directionality overrides and homoglyph codepoints in PKGBUILD content (R013) |
| **Prompt injection** in package metadata | Pattern-matches common injection templates; primary defense is structural (R012) |
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

The default review output shows findings and a verdict, not score or risk columns. Add `--score` or `--risk` when you want the numeric band in the terminal. A clean score means no known risk signals fired, not that the package is safe. See [what TrustSight cannot see](https://trustsight.emiliano-go.com/explanation/what-trustsight-cannot-see/) for details.

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
| [`trustsight review`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-review) | Scan outdated AUR packages and produce a findings table with tiered evidence. Supports `--repo`, `--foreign`, `--all-repos`, `--verbose` flags. |
| [`trustsight inspect <package>`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-inspect-package) | Deep-dive on a single package: findings, source URLs, resolved commands, novelty context. |
| [`trustsight history <package>`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-history-package) | Show past analysis results for a package. |
| [`trustsight forget <package>`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-forget-package) | Remove a tracked package and all its history, or prune packages that no longer exist in the AUR (`--prune`). |
| [`trustsight list`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-list) | List all packages tracked in the database. |
| [`trustsight status`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-status) | Show database and system health statistics. |
| [`trustsight config`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-config) | Manage configuration (`show`, `set`, `sync-rules`). |
| [`trustsight seed-db`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-seed-db) | Import a novelty seed (`.db`, `.db.gz`, or a v2 `.tar.gz`). The release-channel seed imports automatically on first review. |
| [`trustsight seed`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-seed) | Inspect the hashed maintainer seed, fetch the verified release-channel seed, or migrate legacy plaintext rows. |
| [`trustsight db`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-db) | Database maintenance (`check`, `vacuum`, `backup`). |
| [`trustsight override`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-override) | Suppress a rule that misfires on your packages. |
| [`trustsight lint-rules`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-lint-rules) | Check `rules.toml` for unreachable or malformed rules. |
| [`trustsight full-aur`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-full-aur) | Bootstrap or update the full-AUR baseline corpus; `--watch` runs repeated cycles on an interval. |
| [`trustsight baseline`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-baseline) | Build or import a full-AUR baseline artifact, optionally signed with your key. |
| [`trustsight import-baseline`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-import-baseline) | Verify and import a signed baseline artifact. |
| [`trustsight ioc`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-ioc) | Manage IOC federation baselines (`update`, `list`, `export`, `sources`). |
| [`trustsight corpus`](https://trustsight.emiliano-go.com/reference/cli/#trustsight-corpus) | Corpus-wide queries over the full-AUR baseline (`pivot`, `import`, `export`). |

---

## Use it from Python

Every flow above is available as a library through [`trustsight.api`](https://trustsight.emiliano-go.com/reference/python-api/), which returns dataclasses instead of printing. Nothing else under `trustsight.` is public.

```python
from trustsight import TrustSight

ts = TrustSight()

report = ts.inspect("some-package")
print(report.risk_label, report.verdict)

result = ts.review(limit=25)
for r in result.flagged:
    print(r.package, r.risk, r.verdict)
for failure in result.failures:
    print("NOT VETTED:", failure.package, failure.error)

for cycle in ts.watch(interval=1800):     # full-aur --watch, as a generator
    for package, rule_id in cycle.new_alerts:
        print(rule_id, package)
```

Two rules carry over from the CLI. Use `report.risk`, never a band re-derived from `report.score`: an analysis that could not read the whole change reports `Inconclusive` regardless of the number. And check `result.failures`, because a package that could not be analysed is a result, not an absence.

---

## How scoring works

Scoring is fully deterministic: same input always produces the same score. The pipeline is:

1. **Diff** the old and new PKGBUILD
2. **Apply rules** to detect structural changes, suspicious commands, typosquatting, etc.
3. **Classify URLs** into trust buckets (official, self-hosted, unknown, homograph)
4. **Check novelty** against the local database of known URLs and maintainers
5. **Calculate score** from 0-100 by summing weighted contributions across four evidence tiers

Signals come from 13 core detection rules (R001-R013), the expanded TOML set (R039-R059), code-emitted rules (R060+), 4 dependency-graph rules (D001-D004) and 7 code-structure rules (C001-C007), all calibrated against a 3,246-diff benign corpus and a 3,322-diff stratified corpus of real AUR updates.

Verdicts are template-based, describing each triggered finding in plain English. The score is never influenced by the verdict text.

See [scoring philosophy](https://trustsight.emiliano-go.com/explanation/scoring-philosophy/).

---

## License

MIT

---

## Documentation hub

| Section | Description |
|---|---|
| [Getting Started](https://trustsight.emiliano-go.com/getting-started/) | One-tutorial path from install to first review |
| [Full documentation](https://trustsight.emiliano-go.com/) | Docs landing page |
| [Contributing](https://trustsight.emiliano-go.com/contributing/) | How to report bugs, contribute code, improve docs |
| [Security](https://trustsight.emiliano-go.com/security/) | Vulnerability disclosure policy |
| [License](https://trustsight.emiliano-go.com/license/) | MIT full text |
