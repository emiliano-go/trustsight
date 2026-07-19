# TrustSight

<img src="https://raw.githubusercontent.com/emiliano-go/trustsight/refs/heads/master/docs/assets/images/trustsight-banner.png" alt="TrustSight" width="700"/>

Audits AUR PKGBUILDs before you update: catches careless malice and structural risk, and tells you what it can't verify.

<p align="center">
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white&style=for-the-badge" alt="Python">
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

## The 30-second example

```bash
trustsight review
```

```
                        TrustSight Review
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package         ┃ Risk     ┃ Verdict                                     ┃
┃                 ┃ Score    ┃                                             ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ chez-scheme-bin │   0/100  │ Version bump. No structural changes.       │
├─────────────────┼──────────┼─────────────────────────────────────────────┤
│ sketchy-pkg     │  35/100  │ R004 HIGH  Checksum disabled (SKIP).       │
│                 │          │ C003 INFO  Source URL changed without       │
│                 │          │            version bump.                    │
│                 │          │ SOURCE_BUCKET MEDIUM  New domain:           │
│                 │          │   sketchy-cdn.invalid (unknown).           │
│                 │          │ NOVELTY HIGH  Source URL first seen         │
│                 │          │   globally.                                 │
│                 │          │ PINNING INFO  Source pinning: unpinned.     │
│                 │          │ Verdict: Checksum disabled; sources         │
│                 │          │   replaced with content from an unknown,    │
│                 │          │   never-before-seen domain.                 │
├─────────────────┼──────────┼─────────────────────────────────────────────┤
│ obsidian-beta   │  15/100  │ INCONCLUSIVE. Only 2 prior observations;   │
│                 │          │ no high-severity signals from a cold DB.    │
└─────────────────┴──────────┴─────────────────────────────────────────────┘
```

The tiered evidence display is the differentiator: every signal (rule, bucket, novelty, pinning, verification) is shown with its contribution and severity. You see **why** the score is what it is.

---

## What it catches / what it can't

| Detected by TrustSight | Outside TrustSight's scope |
|---|---|
| **Careless malice**: `curl \| bash`, `base64 \| sh`, wget pipe sh (R001 recall ~100%). Obfuscated casing, embedded URLs in function bodies. | **Signed upstream payload**: the PKGBUILD is not the binary. A benign build file can fetch a tampered release tarball. |
| **Structural risk**: checksums disabled (R004), checksums emptied (R005), URL typosquatting (`githab.com`), source URLs swapped without a version bump (C003). | **Deliberately-unremarkable PKGBUILDs**: no added commands, no new URLs, no checksum changes; no signal. The update is invisible to diff analysis. |
| **Anomaly-vs-history**: first-seen URLs (global or per-package), first-seen maintainer, low-observation-count gating with INCONCLUSIVE verdict. | **Build-dependency attacks**: a malicious `makedepends` or `depends` is outside PKGBUILD scope. TrustSight audits the recipe, not the supply chain's second-order dependencies. |
| **Reviewer manipulation**: Unicode bidi overrides (R013, 88% recall) that make displayed text differ from executed text. Prompt injection in comments/descriptions (R012, 17% recall; kept as tripwire; primary defense is verdict-integrity assertions). | **Unpinned sources** result in INCONCLUSIVE. A `source=($pkgname-$pkgver.tar.gz)` with no checksum, tag, or commit pin is reported as structurally weak, not silently accepted. |

---

## Install

```bash
pip install trustsight
```

AUR: `trustsight` (dogfood: TrustSight audits its own updates).

From source:

```bash
git clone https://github.com/emiliano-go/trustsight
cd trustsight
pip install -e .
```

Requires **Python 3.12+**.

---

## Commands

| Command | What it does |
|---|---|
| [`trustsight review`](docs/reference/cli.md) | Scan all outdated AUR packages and produce a scored table with tiered evidence. |
| [`trustsight inspect <package>`](docs/reference/cli.md) | Deep-dive on a single package: full score breakdown, source URLs, resolved commands, novelty context. |
| [`trustsight history <package>`](docs/reference/cli.md) | Show past analysis results for a package, with optional `--score-breakdown`. |

---

## How scoring works

Scoring is deterministic: same input always produces the same score. A core of 13 detection rules (R001 to R013) and 3 code-structure rules (C001 to C003) produces signals across four evidence tiers: **A** (structural, rules on PKGBUILD lines), **B** (priors/context, URL classification and forge trust), **C** (history/novelty, first-seen URLs and maintainers gated by observation count), and **D** (verification, checksums, PGP keys, GPG verify, which **subtract** from the score). The LLM is entirely optional and never calculates; it translates the deterministic breakdown into English, and verdict-integrity assertions gate its output. See [scoring-philosophy.md](docs/explanation/scoring-philosophy.md).

---

## Security model

TrustSight is evidence-producing, not proof-of-safety. It audits and does not install. The tool never runs the PKGBUILD, never executes extracted commands, and never modifies your system. Every finding is traceable to a specific diff line, URL, or novelty record. The output is a structured risk assessment to inform your decision, not a gate. See [trust-model.md](docs/explanation/trust-model.md).

---

## License

MIT. Deliberately permissive to encourage adoption, auditing, and fork-investigation by the Arch Linux and security communities.

---

## Documentation hub

| Section | Description |
|---|---|
| [Getting Started](docs/getting-started/) | One-tutorial path from install to first review |
| [Full documentation](docs/index.md) | Docs landing page |
| [Contributing](CONTRIBUTING.md) | How to report bugs, contribute code, improve docs |
| [Security](docs/security.md) | Vulnerability disclosure policy |
| [License](docs/license.md) | MIT full text |
