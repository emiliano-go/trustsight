# Fire Rates

Fire rates measure the false-positive rate of each rule: how often it fires on a benign corpus where nothing malicious is happening. A rule that fires on every benign diff cannot distinguish malice from ordinary packaging; a rule that fires on none is either very precise or never tested.

## What a fire rate is

```
fire_rate = hits / n_diffs
```

Where `hits` is the number of corpus diffs where the rule fired at least once, and `n_diffs` is the total number of diffs in the stratum (or corpus). The aggregate figures below use the current 3,246-diff locked corpus; individual historical hit counts are labelled with their source corpus.

Fire rates are **false-positive rates within this corpus**: every diff in the benign corpus is a real package update that passed its maintainer's review. A hit is a rule that fired on ordinary packaging, not on malice. They are point-in-time corpus measurements, not a claim about all AUR updates.

## The 30 % gate

Any scored rule (severity other than `INFO`) whose fire rate exceeds **30 %** on the benign corpus must be demoted to `INFO` (weight 0). A rule that fires on one third of all benign updates is not a useful signal; it is census data, not a finding.

This is enforced during development, and again in CI: `scripts/calibration_gates.py` replays the benign corpus against the shipped configuration with a cold database and exits nonzero if any scoring rule crosses the gate. See [Writing a Rule](../contributing/writing-a-rule.md#fire-rate-gate).

Calibration is one of two gate suites. The other, `scripts/security_gates.py`, enforces [the security model](../security.md): what the tool guarantees while reading hostile input, and what a verdict is allowed to claim. Neither suite can pass on behalf of the other.

In practice the shipped rules sit far below the gate. The worst scoring rule measures 0.039, and the rules added after the core set are mostly at zero: the working standard for a new rule is no benign fires at all, with any exception named and explained in the [rules reference](../reference/rules/system.md#experimental-fire-rates).

## Which corpus

Fire rates are measured against the one locked corpus:

| Corpus | Diffs | Packages | What it covers |
|--------|-------|----------|----------------|
| Benign (lock) | 3,246 | ~180 | Staged diffs from real AUR package updates across 9 strata (source_patched, bin_repack, vcs_git, lang_ecosystem, data_fonts, dkms_kernel, autotools, large_electron, unknown). |

The corpus is pinned by `corpus.lock` and regenerated deterministically from
the AUR git mirror (CI rebuilds it before the calibration gates; a local
checkout may carry a larger un-pruned superset on disk). See [Corpus and
Priors](corpus-and-priors.md) and [Benchmarks and Methodology](benchmarks-and-methodology.md).

## Core rules (R001-R013)

The aggregate baseline is current at 3,246 diffs. Detailed rule rows below retain their historical measurement source unless explicitly marked otherwise.

| Rule | Name | Sev | Fire rate | Notes |
|------|------|-----|-----------|-------|
| R001 | Remote Script Execution | CRITICAL | ~0 % | Extremely rare on benign diffs |
| R002 | Wget Pipe to Shell | CRITICAL | ~0 % | |
| R003 | Base64 Decode and Execute | CRITICAL | ~0 % | |
| H001 | Checksum Disabled | HIGH/INFO | <1 % | Corpus-dependent |
| H002 | Checksum Emptied | HIGH | ~0 % | |
| H003 | Insecure Download Protocol | LOW | Not yet published | Added `http://` source without newly added checksum backing; programmatic, diff-aware rule |
| R007 | Install File Modification | MEDIUM | <2 % | |
| R008 | Unexpected File Download | HIGH | ~0 % | |
| H004 | Privilege Escalation | CRITICAL | <1 % | Function-body scoped |
| R010 | Uses curl in PKGBUILD | LOW | <2 % | |
| R011 | Uses wget in PKGBUILD | LOW | <2 % | |
| R012 | LLM Prompt Injection | FATAL | ~0 % | Reviewer-directed template tripwire; 17% detection on labelled injection fixtures, not proof of author intent |
| R013 | Unicode Bidi Override | FATAL | 0.06 % | 2/3246 benign diffs carry zero-width joiners in localized text; the ASCII-neighbour guard keeps them quiet |

## Expanded rules (R039-R059)

## Aggregate distribution

Per-rule rates are below. The aggregate figures the security model cites are:

| Measure | Value |
|---------|-------|
| benign corpus size | 3,246 diffs |
| benign median | 0 |
| benign 95th percentile | 35 |
| benign diffs scoring 0 | 68.4% |
| benign diffs above the 20-point threshold | 13.1% |
| percentile at which 20 sits | 86.9th |
| malicious 5th percentile | 60 |
| malicious minimum | 40 |

These are a **point-in-time measurement**, taken after
[B10](../security.md#b10-positive-evidence-is-reported-never-credited) removed
the verification credits. They are not recomputed on every push: the calibration
gates assert only the property that matters for separation, `benign_p95 <
malicious_p5`, and print those two numbers. Re-derive the rest with
`python scripts/rebaseline.py` after any scoring change, and update this table
in the same commit.

The 13.1% threshold rate is the practical workload figure: on this locked
benign corpus, about **1 in 8** updates would be flagged for review. It is more
useful for capacity planning than the zero-rate, and must not be generalized
beyond this corpus snapshot and configuration.

Calibrated against the current 3,246-diff locked corpus. 14 of 21 fire on zero benign diffs. Enabling the full set costs 0.5 percentage points of zero-rate and leaves p95 unchanged.

| Rule | Name | Sev | Fire rate | Notes |
|------|------|-----|-----------|-------|
| R039 | Eval With Dynamic Content | CRITICAL | 0.00 % | |
| R040 | Shell -c With Dynamic Payload | CRITICAL | 0.00 % | |
| R041 | Shell Network Redirection | CRITICAL | 0.00 % | |
| R042 | Download Then Execute | CRITICAL | 0.00 % | |
| R043 | Base64 Blob Decode | CRITICAL | 0.00 % | |
| R044 | Interpreter One-Liner With Network | HIGH | 0.00 % | |
| R045 | Binary Encoding Pipe | MEDIUM | 0.00 % | |
| R046 | Source URL Uses IP Address | MEDIUM | <1 % | added_only |
| R047 | Source URL Non-Standard Port | LOW | <1 % | |
| R048 | Free Registrar TLD | LOW | 0.00 % | |
| R049 | Compiler Plugin/Loader Override | MEDIUM | 0.00 % | |
| R050 | Compiler Hardening Disabled | MEDIUM | 0.00 % | |
| R051 | Network Access In pkgver | HIGH | <1 % | |
| R052 | Dotfile Written To User Profile | HIGH | <1 % | |
| R053 | Setuid/Setgid In Package Root | MEDIUM | >0 % | Fires on Electron/Chromium packages (legitimate sandbox helper); MEDIUM by design so no risk-band changes |
| R054 | Persistence Unit Outside Root | HIGH | <1 % | |
| R055 | Git Clone With Variable Branch | MEDIUM | 0.00 % | |
| R056 | Download Then Source | CRITICAL | 0.00 % | |
| R057 | TLS Verification Disabled | HIGH | 0.00 % | |
| R058 | Write Outside Package Root | HIGH | <1 % | |
| R059 | Setuid Outside Package Root | HIGH | <1 % | |

## D-series dependency rules

Measured against the 3246-diff benign corpus with a 209,909-name dependency seed. All are enabled by default.

| Rule | Name | Sev | Fire rate | Hits | Notes |
|------|------|-----|-----------|------|-------|
| D001 | Novel Dependency Added | HIGH | 0.15 % | 5/3246 | The 5 hits are real package names that nothing else in the AUR depends on (`kde-rounded-corners-x11`, `python2-gevent-eventemitter`, `udfclient-fuse3`), not parser noise |
| D002 | Typosquatted Dependency | HIGH | 0.00 % | 0/3246 | Refined by D001; bounded by edit-distance threshold |
| D003 | New Network-Using Makedepends | MEDIUM | 0.46 % | 15/3246 | Almost all `git` added to fetch submodules, the legitimate case the MEDIUM severity anticipates |
| D004 | Dependency Hijack Via Provides | HIGH | 0.00 % | 0/3246 | 2084 corpus diffs declare `provides` or `replaces`; zero fire |
| H030 | Dependency-Set Expansion | MEDIUM | 0.34 % | 11/3246 | Measured with a seeded database (209,909-name seed). Well under the 30% gate. |

## Code-emitted rules (H015-H019)

Measured against the 3246-diff benign corpus. All are enabled by default.

| Rule | Name | Sev | Fire rate | Hits | Notes |
|------|------|-----|-----------|------|-------|
| H015 | Build Function Modified | INFO | 21.4 % | 694/3246 | INFO severity, weight 0. No narrowing reaches triage quality: restricting to unchanged `pkgver` still leaves 11.6 %; a version bump that also edits `build()` is 9.8 %. Harmless at weight 0, useful as reviewer context |
| H016 | Hidden Network Fetch In Build | HIGH | 0.22 % | 7/3246 | Real build-time downloads (apple-fonts, ttf-ms-win-\*, gamescope-nvidia): the behaviour the rule exists to surface |
| H017 | Install Hook Fetches/Executes | HIGH | 0.09 % | 3/3246 | All `mullvad-vpn-bin`, which sets a setuid bit and enables a systemd unit from `post_install()`. Real privileged behaviour |
| H018 | Patch From Outside Build Tree | HIGH | 0.00 % | 0/3246 | Asks *where* the input comes from rather than whether it is declared in `source=()`. The broader "not in source()" form measured 2.13 % |
| H019 | Source URL HTTPS→HTTP Downgrade | MEDIUM | 0.03 % | 1/3246 | `transset-df`: a genuine https to http downgrade |

## Temporal context rules (H020-H022)

These rules inspect git commit timestamps rather than diff content, so they
are inherently time-of-run dependent and cannot be calibrated against the
static corpus. Fire rates vary per database and per run.

| Rule | Name | Sev | Condition | Notes |
|------|------|-----|-----------|-------|
| H020 | Very Recent Update | INFO | HEAD commit < 72 h old | Depends on when you run the tool. |
| H021 | Brand New Package | INFO | Root commit < 30 days old | Small shifting set; not corpus-calibrated. |
| H022 | Stale Package Revived | MEDIUM | Gap to last analyzed > 365 days | Depends on age of your local database. |

## Install, maintainer, and naming rules (H023-H027, H029, H035-H036)

These rules are defined in `src/trustsight/analysis/build.py`,
`src/trustsight/analysis/temporal.py`, and `src/trustsight/analysis/pipeline.py`.
Fire rates marked "TBD" require a live git
repository and cannot be measured against the static corpus; H026
falls in this category.

The measured-fire-rate table in the [rules reference](../reference/rules/system.md#experimental-fire-rates)
records the remaining code-emitted rules (H037-H079) that were calibrated after this page was written;
they are not repeated here.

| Rule | Name | Sev | Fire rate | Hits | Notes |
|------|------|-----|-----------|------|-------|
| H023 | Install Hook Present | INFO | 20.95 % | 680/3246 | INFO weight 0; 30% gate does not apply. 1 in 5 PKGBUILDs declare an install hook. |
| H024 | GPG Verification Removed | HIGH | 0.03 % | 1/3246 | Near-zero; matches the predicted rate. Well under the 30% gate. |
| H025 | Build Env Subversion | HIGH/MED | 0.25 % | 8/3246 | All HIGH (LD_ vars). No MEDIUM (CFLAGS/MAKEFLAGS/PATH) fires in corpus. Well under 30% gate. |
| H026 | Untrusted Maintainer Takeover | HIGH | TBD | - | Corpus does not replay maintainer changes; requires live repo. Predicted low on warm DB. |
| H027 | Capability Density Anomaly | INFO | 15.87 % | 515/3246 | INFO weight 0; 30% gate does not apply. 1 in 6 diffs have hits in 3+ categories. |
| H029 | Package-Name Typosquat | HIGH | 1.12 % | 2/179 pkgs | Measured via package-name scan over corpus packages with seeded DB. Well under the 30% gate. Fires on `dosbox-x` and `electron36`. |
| H035 | Foreign Pkg Manager In Hook | HIGH | 0.00 % | 0/3243 | Zero false positives. |
| H036 | Shell Obfuscation Density | MEDIUM | 0.00 % | 0/3243 | Zero false positives. |

## Temporal metadata rule (H028)

H028 is metadata only; it is never appended to `triggered_rules` and
contributes nothing to the score. It requires live git history and cannot
be measured against the static corpus.

| Rule | Name | Type | Fire rate | Hits | Notes |
|------|------|------|-----------|------|-------|
| H028 | Accelerated Release Cadence | metadata | - | - | 3+ ancestors in 24 h; never a scored finding. Not corpus-measurable. |

## Structural rules (C001-C009)

These depend on the shape of a diff rather than a single-line pattern, so their fire rates are corpus-dependent and not reported as a single number. They appear per-stratum in `baseline.json`.

## How to measure a new rule's fire rate

1. Rebuild the corpus from the lock file (see [Re-baselining](../contributing/re-baselining.md)).
2. Run `python scripts/rebaseline.py`.
3. Read the per-stratum `rules` map in `baseline.json` for the new rule's ID.
4. If the aggregate (weighted by stratum size) exceeds 30 %, demote to INFO.

The rebaseline script records fire rates per stratum so that a rule that fires only in one package shape (e.g. only on `large_electron`) is visible rather than being averaged into the aggregate.
