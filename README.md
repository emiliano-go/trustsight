# TrustSight


Audits AUR PKGBUILD updates before you install: detects structural changes, suspicious commands, typosquatting, and novelty signals, then produces a deterministic evidence report.

<p align="center">
  <a href="https://docs.trustsight.org/">
    <img src="https://img.shields.io/badge/Docs-docs.trustsight.org-2C7BE5?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation">
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white&style=for-the-badge" alt="Python">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-10AC84?style=for-the-badge" alt="License">
  </a>
  <a href="https://deepwiki.com/emiliano-go/trustsight">
    <img src="https://img.shields.io/badge/Ask-DeepWiki-007ec6?style=for-the-badge" alt="Ask DeepWiki">
  </a>
  <a href="https://github.com/emiliano-go/trustsight/actions/workflows/test.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/emiliano-go/trustsight/test.yml?branch=master&style=for-the-badge&logo=github&label=Tests" alt="Tests">
  </a>
  <a href="https://pypi.org/project/trustsight/">
    <img src="https://img.shields.io/pypi/v/trustsight?logo=pypi&logoColor=white&style=for-the-badge&cacheSeconds=300" alt="PyPI">
  </a>
</p>

---

## What is TrustSight

TrustSight is a **static security auditing tool** for Arch Linux’s AUR that analyzes package updates across the `PKGBUILD`, `.SRCINFO`, `.install` hooks, Makefiles, and other committed repository files. It **combines** pattern matching, behavioral heuristics, structural checks, dependency analysis, sabotage detection, and cross-file correlation to flag suspicious commands, obfuscation, risky installation behavior, source URL and checksum changes, dependency anomalies, maintainer changes, and previously unseen sources. It compares versions and repository history, producing evidence-linked findings and a deterministic report. TrustSight does not execute build scripts, fetch declared package sources, or inspect downloaded archives, so a clean result cannot guarantee safety.

<p align="center">
  <a href="https://docs.trustsight.org/">
    <img src="https://img.shields.io/badge/docs-docs.trustsight.org-2C7BE5?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation">
  </a>
  <a href="https://watcher.trustsight.org/">
    <img src="https://img.shields.io/badge/watcher-watcher.trustsight.org-8250DF?style=for-the-badge&logo=linux&logoColor=white" alt="Live watcher">
  </a>
  <a href="https://ntfy.sh/trustsight-aur-1d8a3fd2">
    <img src="https://img.shields.io/badge/alert_feed-ntfy.sh-00897B?style=for-the-badge&logo=rss&logoColor=white" alt="Alert feed">
  </a>
  <a href="https://harness.trustsight.org/">
    <img src="https://img.shields.io/badge/harness-harness.trustsight.org-C2410C?style=for-the-badge&logo=target&logoColor=white" alt="Adversarial harness">
  </a>
</p>

## Setup

> **TrustSight is available on the AUR, maintained by this project.** The `trustsight` AUR package is built from `packaging/aur/PKGBUILD` in this repository. It gets no special trust for being the author's: it is an AUR package like any other, so inspect its PKGBUILD before installing. Source remains the recommended install, below.

```bash
# 1. Import the release signing key once (makepkg verifies the tarball's
#    detached signature; without the key it reports "unknown public key")
gpg --keyserver hkps://keys.openpgp.org \
  --recv-keys F759D6D49B0A395AB922414A5CC3B4C50D37E793

# 2. Install the latest release tag (the PKGBUILD pins one version)
git clone --depth 1 --branch "$(git ls-remote --tags --refs --sort=-v:refname \
  https://github.com/emiliano-go/trustsight.git 'v*' | head -1 | cut -d/ -f3)" \
  https://github.com/emiliano-go/trustsight.git
cd trustsight/packaging/aur
makepkg -si
# Or build the checkout in place, with no second download:
#   cd trustsight/packaging/local && makepkg -si

# 3. Scan your outdated AUR packages
trustsight review

# 4. Scan a package before install
trustsight inspect PACKAGE_NAME --allow-uninstalled --full-recipe
```

Requires **Python 3.11+** and **Arch Linux** (the tool discovers packages via `pacman -Qm`, `pacman -Sl` for local repos, or `--repo`/`--all-repos` flags).


---

## Security model

TrustSight is **evidence-producing**, not proof-of-safety. Read the [full security model](https://docs.trustsight.org/security/) for the threat model, invariants, and enforcement gates. It audits and does not install. The tool never runs the PKGBUILD, never executes extracted commands, and never modifies your system. Every finding is traceable to a specific diff line, URL, or novelty record. The output is a structured evidence report, not a gate. See [what TrustSight cannot see](https://docs.trustsight.org/explanation/what-trustsight-cannot-see/).

> **Why static analysis?** TrustSight is a SAST tool by design: it never executes PKGBUILDs or fetches URLs declared by them, and runs before `makepkg`. Its only network egress is the AUR metadata snapshot and the signed baseline channel - never a source the package declares. For how to customize the detection surface, see [Why Static Analysis](https://docs.trustsight.org/explanation/why-static-analysis/).

---

## What it detects

| Attack / Risk | How TrustSight catches it |
|---|---|
| **Piped shell scripts** (`curl \| bash`, `base64 \| sh`) | Scans every new or changed line for command-subprocess pipelines (R001 / R002 / R003; 100% on the labelled fixtures) |
| **Obfuscated commands** (encoded strings, environment subversion like `LD_PRELOAD`) | Resolves variables and decodes known obfuscation patterns; flags build-environment tampering (H025, H036; decode-and-execute: X001/R003) |
| **Checksum disabled or removed** | Compares old vs new `sha256sums` / `md5sums` arrays (H001, H002, C004) |
| **Source URL typosquatting** (`githab.com` instead of `github.com`) | Character-level edit distance against known forge domains (confusable-domain pipeline) |
| **Package-name typosquatting** (e.g. `libuvc` resembling `libuv`) | Edit-distance comparison against more popular packages in the seed database (H029) |
| **URL swapped without a version bump** | Tracks source URL changes that are not accompanied by a new version (C003) |
| **Novel / never-before-seen URLs or maintainers** | Compares against the release-channel seed (185,902 known source URLs, 36,912 hashed maintainer identities and 215,504 dependency names, verified against the pinned key on import); flags first-seen domains and maintainers (novelty tier) |
| **Known-bad indicators** | Matches package URLs and strings against signed, federated IOC baselines from the release channel; reported in the IOC tier, outside the heuristic score |
| **Unicode bidi override attacks** (invisible characters that change how text displays) | Detects directionality overrides and homoglyph codepoints in PKGBUILD content (R013) |
| **Reviewer-directed instruction templates** in package metadata | Flags common reviewer-manipulation templates as a high-severity tripwire (R012); a match requires review, not an inference about author intent |
| **GPG verification removed** | Detects when `validpgpkeys` was populated and is now empty (H024) |
| **Untrusted maintainer takeover** | A maintainer change to someone never seen before (H026) |
| **Stale package revived** | A package with no updates for over a year suddenly gets one (H022) |
| **Accelerated release cadence** | 3+ commits in the last 24 hours (H028, informational) |
| **Sabotage payloads** (fork bombs, `rm -rf /`, disk wiping, permission sabotage, service disruption, coin miners, log wiping) | Command-position matching that distinguishes the build sandbox from the system: `rm -rf "$srcdir/x"` is housekeeping, `rm -rf /` is not (S001-S008) |
| **Orphan hijacking** (a package adopted from orphan, then its recipe rewritten with no upstream change) | The AUR maintainer field against the last recorded state, plus a recipe-only-change signature and the composition of both with an unpinned build fetch (H086-H088) |
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

The default review output shows findings and a verdict, not score or risk columns. Add `--score` or `--risk` when you want the numeric band in the terminal. The default review profile flags scores above 20; on the locked benign corpus that is about **1 in 12** review workload items. `quiet` and `strict` profiles change the queue without changing scores or bands. A clean score means no known risk signals fired, not that the package is safe. This is a point-in-time corpus measurement, not a universal false-positive rate. See [what TrustSight cannot see](https://docs.trustsight.org/explanation/what-trustsight-cannot-see/) for details.

---

## How it works

A run is deterministic: the same diff, effective configuration, and stored observation history always produce the same evidence record. The pipeline is:

1. **Diff** the old and new PKGBUILD, then read the post-patch end state
2. **Resolve** variable references in `source`, `sha256sums`, `pkgver`, `pkgrel`, and `package()`; anything not statically resolvable becomes a coverage gap
3. **Apply rules** for structural changes, suspicious commands, typosquatting, evasion and hidden text, install-script and persistence behaviour, and the `U`-series upstream manifests
4. **Classify URLs** into trust buckets (trusted forge, official, raw hosting, unknown, homograph)
5. **Check novelty** against the local database of known URLs and maintainers, and follow the AUR dependency closure to its configured depth
6. **Read declared verification**; checksums, PGP keys, signature sources, and commit/tag pins are reported at weight 0
7. **Report** the findings, the change summary, and any coverage gaps

Verdicts are template-based, describing each triggered finding in plain English. All output is deterministic and generated locally.

### The evidence layers

Every rule carries an **evidence layer**, `L1`-`L8`, naming the *kind* of evidence a finding is - not a stage an attacker passed through. A finding at `L4` does not mean `L1`-`L3` were cleared, and a layer with no finding is not a safety certificate.

| Layer | The question its evidence answers | Rule families |
|---|---|---|
| `L1` Structural coherence | Does the change hang together as an honest edit? | `C`, `P` |
| `L2` Readability | Was anything hidden from the reader? | `W`, and the refusal rules `X026`/`X027` |
| `L3` Payload signature | Does it do a known-bad thing? | `R`, `S`, `U` |
| `L4` Evasion shape | Was it *written* to defeat reading? | `X`, `E` |
| `L5` Behavioral suspicion | Does the package's story make sense? | `H` |
| `L6` Ecosystem memory | Has the ecosystem seen this before? | `D`, `T` |
| `L7` Known indicators | Is it on the list? | `I` |
| `L8` Campaign correlation | Do other packages tell the same story? | `G` |

The report keeps detection and coverage separate: `L3 fired` says the payload-signature check matched, `L1 passed` says the structural check was read in full and stayed silent (not that the update is safe), and `L8 not_applicable` says the check could not run on a single package. `M` reasons about other findings and fires *at* their layer, so it owns no layer of its own. The optional `L9` build lane (`A001`-`A008`) inspects the built package and is not one of the eight. See [How TrustSight groups security evidence](https://docs.trustsight.org/assurance-layers/).

Signals come from 257 documented rules across eleven rule families: 37 detection rules (R-series, TOML-configurable), 104 heuristic rules (H-series), 32 code-structure rules (C001-C032), 5 dependency-graph rules (D001-D005), 8 sabotage rules (S001-S008), 34 crossfire anti-evasion rules (X001-X034), 6 meta rules (M001-M006), 3 entropy rules (E001-E003), 5 temporal rules (T001-T003, T006-T007), 13 correlation rules (G001-G010, G012-G014), and 10 manifest rules (U001-U010). Two further families are reported but never weighted: declared practice (P001-P009) and unverifiable (W001-W012), the latter naming what an analysis could not read. The optional L9 build lane adds eight artifact rules (A001-A008), reported outside the heuristic when enabled. Calibration uses a locked, point-in-time 8,393-diff benign corpus of real AUR updates and 207 self-authored, labelled malicious fixtures; it is regression evidence, not an independent recall claim. See [Benchmarks and Methodology](https://docs.trustsight.org/explanation/benchmarks-and-methodology/) and the [blinded-evaluation intake](https://docs.trustsight.org/contributing/blinded-evaluation/) for scope.

---

## License

MIT

---

## Documentation hub

| Section | Description |
|---|---|
| [Tutorial](https://docs.trustsight.org/tutorial/installation/) | One-tutorial path from install to first review |
| [Full documentation](https://docs.trustsight.org/) | Docs landing page |
| [Contributing](https://docs.trustsight.org/contributing/) | How to report bugs, contribute code, improve docs |
| [Security](https://docs.trustsight.org/security/) | Vulnerability disclosure policy |
| [License](https://docs.trustsight.org/license/) | MIT full text |
