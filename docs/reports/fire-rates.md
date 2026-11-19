<!-- description: Per-rule false-positive rates measured on the locked benign corpus: how each is measured, what a high rate costs, and which rules are gated on theirs. -->

# Fire Rates

Fire rates measure the false-positive rate of each rule: how often it fires on a benign corpus where nothing malicious is happening. A rule that fires on every benign diff cannot distinguish malice from ordinary packaging; a rule that fires on none is either very precise or never tested.

## What a fire rate is

```
fire_rate = hits / n_diffs
```

Where `hits` is the number of corpus diffs where the rule fired at least once, and `n_diffs` is the total number of diffs in the stratum (or corpus). The aggregate figures below use the current 8,393-diff locked corpus; individual historical hit counts are labelled with their source corpus.

Fire rates are **false-positive rates within this corpus**: every diff in the benign corpus is a real package update that passed its maintainer's review. A hit is a rule that fired on ordinary packaging, not on malice. They are point-in-time corpus measurements, not a claim about all AUR updates.

## The 30 % gate

Any scored rule (severity other than `INFO`) whose fire rate exceeds **30 %** on the benign corpus must be demoted to `INFO` (weight 0). A rule that fires on one third of all benign updates is not a useful signal; it is census data, not a finding.

This is enforced during development, and again in CI: `scripts/calibration_gates.py` replays the benign corpus against the shipped configuration with a cold database and exits nonzero if any scoring rule crosses the gate. See [Writing a Rule](../contributing/writing-a-rule.md#fire-rate-gate).

Calibration is one of two gate suites. The other, `scripts/security_gates.py`, enforces [the security model](../security-design/security-model.md): what the tool guarantees while reading hostile input, and what a verdict is allowed to claim. Neither suite can pass on behalf of the other.

In practice the shipped rules sit far below the gate. The worst scoring rule (C005) measures 0.031, and the rules added after the core set are mostly at zero: the working standard for a new rule is no benign fires at all, with any exception named and explained in the [rule series](../rules/series.md).

## Which corpus

Fire rates are measured against the one locked corpus:

| Corpus | Diffs | Packages | What it covers |
|--------|-------|----------|----------------|
| Benign (lock) | 8,393 | 426 | Staged diffs from real AUR package updates across 16 strata (the original eight plus persist_surface, signed_sources, multi_client_fetch, maintainer_churn, dependency_heavy, vcs_other, appimage_repack and lang_deep). The next lock adds `runtime_carriers`. |

The corpus is pinned by `corpus.lock` and regenerated deterministically from
the AUR git mirror (CI rebuilds it before the calibration gates; a local
checkout may carry a larger un-pruned superset on disk). See [Corpus and
Priors](../explanation/historical-and-behavioral-analysis.md) and [Benchmarks and Methodology](benchmarks-and-methodology.md).

## Core rules (R001-R013, H001-H004)

The aggregate baseline is current at 8,393 diffs. Detailed rule rows below retain their historical measurement source unless explicitly marked otherwise.

| Rule | Name | Sev | Fire rate | Notes |
|------|------|-----|-----------|-------|
| R001 | Remote Script Execution | CRITICAL | ~0 % | Extremely rare on benign diffs |
| R002 | Wget Pipe to Shell | CRITICAL | ~0 % | |
| R003 | Base64 Decode and Execute | CRITICAL | ~0 % | |
| H001 | Checksum Disabled | HIGH/INFO | <1 % | Corpus-dependent |
| H002 | Checksum Emptied | HIGH | ~0 % | |
| H003 | Insecure Download Protocol | LOW | 0.31 % | 26/8,393 benign diffs; added `http://` source without newly added checksum backing. Programmatic, diff-aware rule |
| R007 | Install File Modification | MEDIUM | <2 % | |
| R008 | Unexpected File Download | HIGH | ~0 % | |
| H004 | Privilege Escalation | CRITICAL | <1 % | Function-body scoped |
| R010 | Uses curl in PKGBUILD | LOW | <2 % | |
| R011 | Uses wget in PKGBUILD | LOW | <2 % | |
| R012 | LLM Prompt Injection | FATAL | ~0 % | Reviewer-directed template tripwire; fires on all 22 labelled injection fixtures, not proof of author intent |
| R013 | Unicode Bidi Override | FATAL | 0 % | 2/8393 benign diffs carry zero-width joiners in localized text, but the ASCII-neighbour guard keeps them from firing |

## Aggregate distribution

Per-rule rates are below. The aggregate figures the security model cites are:

| Measure | Value |
|---------|-------|
| benign corpus size | 8,393 diffs |
| benign median | 0 |
| benign 95th percentile | 30 |
| benign diffs scoring 0 | 75.8% |
| benign diffs above the 20-point threshold | 6.3% |
| percentile at which 20 sits | 93.7th |
| malicious 5th percentile | 40 |
| malicious minimum | 20 |

These are a **point-in-time measurement**, taken after
[B10](../security-design/security-model.md#b10-positive-evidence-is-reported-never-credited) removed
the verification credits. They are not recomputed on every push: the calibration
gates assert only the property that matters for separation, `benign_p95 <
malicious_p5`, and print those two numbers. Re-derive the rest with
`python scripts/rebaseline.py` after any scoring change, and update this table
in the same commit. `rebaseline.py` scans under the shipped config, the same
isolation the gates use, so its distribution figures and the gate's separation
numbers come from one basis.

The 6.3% threshold rate is the practical workload figure: on this locked
benign corpus, about **1 in 15** updates would be flagged for review. It is more
useful for capacity planning than the zero-rate, and must not be generalized
beyond this corpus snapshot and configuration.

Calibrated against the current 8,393-diff locked corpus. 15 of 21 fire on zero benign diffs. Enabling the full set costs 0.5 percentage points of zero-rate and leaves p95 unchanged.

| Rule | Name | Sev | Fire rate | Notes |
|------|------|-----|-----------|-------|
| R039 | Eval With Dynamic Content | CRITICAL | 0.35 % | |
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

Measured against the 8393-diff benign corpus with the published 215,504-name dependency seed (`baseline-2026-09-24`). All are enabled by default.

| Rule | Name | Sev | Fire rate | Hits | Notes |
|------|------|-----|-----------|------|-------|
| D001 | Novel Dependency Added | HIGH | 0.27 % | 10/8393 | The hits are real package names that nothing else in the AUR depends on (`kde-rounded-corners-x11`, `python-hindsight-client`, `python-parallel-web`, `python-pytest-enabler`, `python2-pytest-flake8`, `python2-gevent-eventemitter`, `udfclient-fuse3`), not parser noise |
| D002 | Typosquatted Dependency | HIGH | 0.00 % | 0/8393 | Refined by D001; bounded by edit-distance threshold |
| D003 | New Network-Using Makedepends | MEDIUM | 0.46 % | 39/8393 | Mostly `git` added to fetch submodules, the legitimate case the MEDIUM severity anticipates; the transfer-client expansion (2026-10-26) raised the count without changing the rate. |
| D004 | Dependency Hijack Via Provides | HIGH | 0.05 % | 2/8393 | 2084 corpus diffs declare `provides` or `replaces`; `jpegli-git` conflicts `libjxl` and `llama.cpp-cuda-git` provides `ggml`, both established unrelated names |
| H030 | Dependency-Set Expansion | MEDIUM | 0.13 % | 5/8393 | Measured with the published seed. Well under the 30% gate. |

## Code-emitted rules (H015-H019)

Measured against the 8393-diff benign corpus. All are enabled by default.

| Rule | Name | Sev | Fire rate | Hits | Notes |
|------|------|-----|-----------|------|-------|
| H015 | Build Function Modified | INFO | 19.7 % | 738/8393 | INFO severity, weight 0. No narrowing reaches triage quality: restricting to unchanged `pkgver` still leaves 11.6 %; a version bump that also edits `build()` is 9.8 %. Harmless at weight 0, useful as reviewer context |
| H016 | Hidden Network Fetch In Build | HIGH | 0.21 % | 8/8393 | Real build-time downloads (apple-fonts, ttf-ms-win-\*, gamescope-nvidia): the behaviour the rule exists to surface |
| H017 | Install Hook Fetches/Executes | HIGH | 0.11 % | 4/8393 | Three are `mullvad-vpn-bin`, which sets a setuid bit and enables a systemd unit from `post_install()`; the fourth is `claude-desktop-bin`, reached through the call graph. Real privileged behaviour |
| H018 | Patch From Outside Build Tree | HIGH | 0.00 % | 0/8393 | Asks *where* the input comes from rather than whether it is declared in `source=()`. The broader "not in source()" form measured 2.13 % |
| H019 | Source URL HTTPS→HTTP Downgrade | MEDIUM | 0.03 % | 1/8393 | `transset-df`: a genuine https to http downgrade |

## Cycle-level correlation (G011)

G011 reads recorded cycles, not one diff, so it has no static per-diff fire
rate comparable to the tables above. Its benign calibration is the 65-record
H104 triage shape in `tests/fixtures/g011/benign-bursts.json`: the 18
`nabbisen` reservations, six `tiouo` aliases and 41 single-package
maintainers produce **0** G011 findings. A first-seen maintainer with five
placeholder packages produces one HIGH finding; the same burst with fewer
placeholders stays MEDIUM.

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
`src/trustsight/analysis/composition.py`, `src/trustsight/analysis/maintainer.py`,
and `src/trustsight/analysis/pipeline/__init__.py`.
Fire rates marked "TBD" require a live git
repository and cannot be measured against the static corpus; H026
falls in this category.

The measured-fire-rate table below records the remaining code-emitted rules (H037-H079) that were calibrated after the per-family tables on this page were written.

| Rule | Name | Sev | Fire rate | Hits | Notes |
|------|------|-----|-----------|------|-------|
| H023 | Install Hook Present | INFO | 20.57 % | 769/8393 | INFO weight 0; 30% gate does not apply. 1 in 5 PKGBUILDs declare an install hook. |
| H024 | GPG Verification Removed | HIGH | 0.03 % | 1/8393 | Near-zero; matches the predicted rate. Well under the 30% gate. |
| H025 | Build Env Subversion | HIGH/MED | 0.27 % | 10/8393 | All HIGH (LD_ vars). No MEDIUM (CFLAGS/MAKEFLAGS/PATH) fires in corpus. Well under 30% gate. |
| H026 | Untrusted Maintainer Takeover | HIGH | TBD | - | Corpus does not replay maintainer changes; requires live repo. Predicted low on warm DB. |
| H027 | Capability Density Anomaly | INFO | 7.54 % | 282/8393 | INFO weight 0; 30% gate does not apply. 1 in 13 diffs have hits in 3+ categories. |
| H029 | Package-Name Typosquat | HIGH | 0.00 % | 0/202 pkgs | Package-name scan over corpus packages with the seeded DB. The absolute candidate floor (100 observations) and the plain-edit floor (1000) removed the prior `dosbox-x` and `electron36` false positives while keeping the confusable-edit detections (`openss1`/`openssl`, `sytsemd`/`systemd`). Well under the 30% gate. |
| H092 | Metadata Names A Source The Recipe Does Not | HIGH | not replayable | - | The stateless corpus replay passes no `.SRCINFO`, so the host comparison never runs; the review path reads it at HEAD, and the full-AUR corpus path has always run it. |
| H098 | Naming/Deception Cluster | HIGH | not replayable | - | Depends on H029, which needs the seeded DB, so the stateless corpus replay does not exercise it. |
| H099 | Source Host Swapped Under A Kept Local Name | HIGH | 0.08 % | 3/8393 | Three fires, all true-but-benign host moves under a stable version (a mirror change, a redirect consolidation). Well under the 30% gate. |
| H100 | Install Hook Added Or Retargeted | HIGH/MED | 0.32 % | 12/8393 | Packages do gain `install=` legitimately (fonts, dkms, desktop integration); the finding is factual and marks the hook for review. In line with D003 (0.48 %). |
| H101 | Source Pinning Lost | MEDIUM | 0.03 % | 1/8393 | One fire, a true-but-benign move from a commit pin to a branch on a -git package. Well under the 30% gate. |
| H102 | Maintainer Change With Signing Key Change | HIGH | not replayable | - | Needs a maintainer change plus H078; the stateless corpus replay has no maintainer history. Unit and integration tests pin both directions. |
| H103 | Metadata And Recipe Disagree | HIGH | not replayable | - | The stateless corpus replay passes no `.SRCINFO`, so the comparison never runs; the review path reads it at HEAD, and a full-AUR cycle compares the fetched metadata. Unit and integration tests pin both directions. |
| H035 | Foreign Pkg Manager In Hook | HIGH | 0.00 % | 0/8393 | Zero false positives. |
| H036 | Shell Obfuscation Density | MEDIUM | 0.00 % | 0/8393 | Zero false positives. |

## Temporal metadata rule (H028)

H028 is metadata only; it is never appended to `triggered_rules` and
contributes nothing to the score. It requires live git history and cannot
be measured against the static corpus.

| Rule | Name | Type | Fire rate | Hits | Notes |
|------|------|------|-----------|------|-------|
| H028 | Accelerated Release Cadence | metadata | - | - | 3+ ancestors in 24 h; never a scored finding. Not corpus-measurable. |

## Structural rules (C001-C035)

These depend on the shape of a diff rather than a single-line pattern, so their fire rates are corpus-dependent and not reported as a single number. They appear per-stratum in `baseline.json`.

## Measured code-emitted rules

The corpus-dependent rows below (D-series, H029, H030) were measured against the 8,393-diff benign corpus with the published 215,504-name dependency corpus (`baseline-2026-09-24`); the stateless rows are the cold-database replay counts. They are per-rule hit counts from a single run and are not regenerated on each push. All D-series, H016-H019, and H035-H036 rules are **on by default**, as are the code-emitted rules H037-H079. These are **false-positive rates**: every hit is a benign package.

The numbers are enforced, not just recorded. `scripts/calibration_gates.py` replays the corpus against the *shipped* configuration in a temporary directory with a cold database, and fails the build if any scoring rule exceeds a 0.30 fire rate, if benign p95 reaches the malicious p5, if a weight-0 annotation starts scoring, or if a labelled attack fixture stops being detected. It runs on every push. Class C and Class D rules are absent from this table because they cannot fire on a stateless diff at all, which is itself one of the gates.

For a complete reference including the core and expanded rules, see [the per-family tables above](#fire-rates).

| Rule | Severity | Fires | Rate | Read |
|------|----------|-------|------|------|
| D004 | HIGH | 2 | 0.05 % | Across the 2084 corpus diffs that declare `provides`/`replaces`, `jpegli-git` conflicts `libjxl` and `llama.cpp-cuda-git` provides `ggml`; both name an established package they are unrelated to, which is the shape the rule describes. |
| H017 | HIGH | 4 | 0.11 % | Three are `mullvad-vpn-bin`, which sets a setuid bit and enables a unit from `post_install()`. The fourth is `claude-desktop-bin`, whose `_fix_sandbox()` helper - reached only by following the call graph - sets 4755 on the Electron sandbox binary. Real privileged behaviour in both, which is the point. |
| H018 | HIGH | 0 | 0.00 % | Zero, because it asks where the patch comes from rather than whether it is declared. The broad "not in `source=()`" form measured 2.13 %. |
| H019 | MEDIUM | 1 | 0.03 % | `transset-df`, a genuine https to http downgrade. |
| H020 | INFO | - | - | Not calibrated: fires on any recent update, which is inherently time-of-run dependent. |
| H021 | INFO | - | - | Not calibrated: fires on packages < 30 days old, which is a small and shifting set. |
| H022 | MEDIUM | - | - | Not calibrated: fires when the user's last analysis is > 1 year old, which varies per database. |
| H023 | INFO | - | - | Not calibrated: zero-weight metadata; context only. |
| H024 | HIGH | 1 | 0.03 % | Near-zero; matches the predicted rate. |
| H025 | HIGH/MED | 10 | 0.27 % | All HIGH (LD_ vars). No MEDIUM fires in corpus. |
| H026 | HIGH | - | TBD | Not corpus-measurable; requires live git history. |
| H027 | INFO | 282 | 7.54 % | INFO weight 0; not a scoring impact. |
| H029 | HIGH | 0/202 pkgs | 0.00 % | Measured via package-name scan with seeded DB. The confusable/plain observation floors removed the `dosbox-x` and `electron36` false positives. |
| H030 | MEDIUM | 5 | 0.13 % | Measured with the published seed. Well under the 30% gate. |
| D001 | MEDIUM | 10 | 0.27 % | The ten hits are real package names that nothing else in the AUR depends on (`kde-rounded-corners-x11`, `python-hindsight-client`, `python-parallel-web`, `python-pytest-enabler`, `python2-pytest-flake8`, `python2-gevent-eventemitter`, `udfclient-fuse3`), not parser noise. MEDIUM: "never observed in the AUR" is an instrument-history prior, not a high-severity finding on its own. |
| D002 | HIGH | 0 | 0.00 % | No false positive anywhere in the corpus. Bounded by D001, which it refines. |
| D003 | MEDIUM | 18 | 0.48 % | Almost all are `git` added to fetch submodules, the legitimate case the MEDIUM severity anticipates. |
| H015 | INFO | 738 | **19.7 %** | Why it is INFO. No narrowing reaches triage quality, so it carries weight 0 and reports context instead of scoring. Harmless at that weight, hence on by default. |
| H016 | HIGH | 8 | 0.21 % | The hits are real build-time downloads (`apple-fonts`, `ttf-ms-win-*`, `gamescope-nvidia`), which is the behaviour the rule exists to surface rather than noise. |
| H031 | MEDIUM | 1 | 0.03 % | Needs both an unsafe literal version and its interpolation into a source URL. |
| H032 | HIGH | 0 | 0.00 % | No benign write reaches the build/install-function scope in the current corpus. |
| H033 | HIGH/MED | 4 | 0.11 % | Maintainers tracking a moving patch branch under a fixed version, which is the shape the rule describes. |
| H034 | MEDIUM | 7 | 0.19 % | Schemes outside the shipped allowlist. |
| H038 | HIGH | 0 | 0.00 % | `mktemp -d` is excluded wholesale, so private scratch directories never count. |
| H041 | HIGH | 0 | 0.00 % | The one paste-host reference in the corpus is a gist download, which is H016's. |
| H039 | HIGH | 0 | 0.00 % | Reads the unit's `ExecStart`, not its filename. |
| H040 | INFO | 0 | 0.00 % | `env` was dropped after a `sed` expression read as a command position. |
| H042 | HIGH | 0 | 0.00 % | Deliberately the quietest of the persistence group. |
| H043 | INFO | 0 | 0.00 % | A benign diff with one or two hits cannot reach three distinct stages. |
| H056 | tiered | 0 | 0.00 % | With the shipped (empty) list and with a synthetic one. A positive control (`github.com`) fires on 1561 diffs, so the surface extraction is real. |
| H062 | MEDIUM | 4 | 0.11 % | Packages that legitimately ship pacman hooks. |
| H063 | MEDIUM | 14 | 0.37 % | All fourteen are benign `epoch=` introductions; an unchanged epoch never surfaces in a hunk. |
| H064 | HIGH/MED | 2 | 0.05 % | Related name shapes suppress; both hits name an established package from the official repos. |
| H065 | INFO | 58 | 1.55 % | Weight 0; benign recipes reconstruct literals routinely, so this is context, not a finding. |
| H067 | HIGH | 0 | 0.00 % | Architecture checks are not probes. |
| H068 | HIGH | 0 | 0.00 % | A type check on decoded bytes, so encodings do not need enumerating. |
| H069 | HIGH | 0 | 0.00 % | Heredoc bodies are excluded from command scanning. |
| H071 | HIGH | 0 | 0.00 % | Command-position anchored; a client in `makedepends` is a declaration. |
| H072 | HIGH | 0 | 0.00 % | Still zero after the execution match was widened to a path with arguments. |
| H076 | HIGH | 0 | 0.00 % | A representative backdoor fixture goes from 25 to 50 with it. |
| H077 | HIGH | 3 | 0.08 % | One package resolving a redirect with `curl` at the top level, which really does fetch on a metadata refresh. |
| H078 | HIGH/MED/INFO | 6 | 0.16 % | Two introductions and four upstream key rotations. |
| H079 | HIGH/MED | 3 | 0.08 % | One wine package that genuinely disables FORTIFY_SOURCE. |

## Measurement notes

The corpus-dependent rows in the tables above (D-series, H029, H030) were measured against
the 8,393-diff benign corpus with the published 215,504-name dependency corpus
(`baseline-2026-09-24`); the stateless rows are the cold-database replay
counts. They are per-rule hit counts from a single run and are not regenerated
on each push. All D-series, H016-H019, and H035-H036 rules are on by default,
as are the code-emitted rules H037-H079. These are false-positive rates: every
hit is a benign package.

The numbers are enforced, not just recorded. `scripts/calibration_gates.py`
replays the corpus against the shipped configuration in a temporary directory
with a cold database, and fails the build if any scoring rule exceeds a 0.30
fire rate, if benign p95 reaches the malicious p5, if a weight-0 annotation
starts scoring, or if a labelled attack fixture stops being detected. It runs
on every push. Class C and Class D rules are absent from this table because
they cannot fire on a stateless diff at all, which is itself one of the gates.

Getting D001 from 5.95% to 0.15% at the time of the fix took two extractor
fixes, both found by this measurement rather than by review:

- An unbounded fallback for unquoted array entries read shell fragments
  (`if`, `[[`, `!`) out of a `package()` body as dependency names.
- Comments inside dependency arrays contributed every word of the note
  (`required`, `because`, `disabled`).

Both are covered by regression tests in `tests/test_deps_rules.py`.

## How to measure a new rule's fire rate

1. Rebuild the corpus from the lock file (see [Re-baselining](../contributing/re-baselining.md)).
2. Run `python scripts/rebaseline.py`.
3. Read the per-stratum `rules` map in `baseline.json` for the new rule's ID.
4. If the aggregate (weighted by stratum size) exceeds 30 %, demote to INFO.

The rebaseline script records fire rates per stratum so that a rule that fires only in one package shape (e.g. only on `large_electron`) is visible rather than being averaged into the aggregate.
