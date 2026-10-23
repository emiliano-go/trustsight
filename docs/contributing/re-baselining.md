<!-- description: When and how to regenerate the score-distribution baseline over the pinned corpus after a scoring change, and how to read the resulting diff. -->

# Re-baselining

The baseline (`tests/fixtures/baseline.json`) records the expected score distribution over the pinned corpus. It must be regenerated whenever the scoring logic changes.

## When to re-baseline

Trigger a re-baseline after any of the following:

- A **weight** change in `config.toml`
- A **rule addition**, **removal**, or **severity** change
- A **pattern** change in `rules.toml`
- Fixing a **bug** that affects scoring

If in doubt, re-baseline. The monthly **Corpus Drift Detection** workflow downloads the packed corpus release asset, re-derives the baseline and opens an issue when it no longer matches, so a stale baseline surfaces eventually, but nothing blocks a merge on it.

## Materialise the corpus first

The corpus is **not** committed: `*.diff` is gitignored, so `tests/fixtures/benign-corpus/` is absent on a fresh clone and in CI. `rebaseline.py` does not fetch it: it exits with `Corpus not found` if the directory is missing.

Rebuild it from the lock first:

```bash
uv run python scripts/build_corpus.py --from-manifest \
  --manifest tests/fixtures/corpus.lock \
  --out tests/fixtures/benign-corpus
```

This regenerates the exact diffs recorded in the lock (426 packages, ~9 minutes cold; the fetched objects are cached under `~/.cache/trustsight/aur.git`). The selection is deterministic: the same lock names the same packages and diffs on any machine. The reconstructed *bytes* are not byte-identical across git versions, though - `git diff -W` output is not byte-stable, which is why the calibration workflows download the packed release asset rather than rebuilding from the lock (see `.github/workflows/corpus-drift.yml`).

Do **not** use plain `build_corpus.py --strata ...` for this. That mode re-selects packages by current AUR popularity and rewrites the lock, producing a different corpus each run.

## How to run

```bash
uv run python scripts/rebaseline.py
```

The script:

1. Reads every `*.diff` under `--corpus`, grouping by package.
2. Replays each package's diffs in true commit order, following the `old_sha -> new_sha` chain in the lock (`--order filename` restores the legacy SHA-hex sort). Order matters because novelty detection is order-dependent.
3. Runs the full analysis pipeline on each diff, under the **shipped** config (the `shipped_config()` isolation the calibration gates use) rather than the machine's `rules.toml`, so the baseline is reproducible and comparable to the enforced numbers.
4. Computes per-**stratum** statistics, where a stratum is a package *shape* (`bin_repack`, `vcs_git`, `lang_ecosystem`, `data_fonts`, `dkms_kernel`, `source_patched`, `autotools`, `large_electron`) as assigned by the lock:
   - `n_diffs`, `n_pkgs`
   - `p95` score
   - `zero_pct` : fraction of diffs scoring 0
   - `rules` : per-rule fire rate
5. Writes the new `tests/fixtures/baseline.json`, recording `corpus_content_sha256` so a baseline can be tied to the corpus it came from.

`rebaseline.py` only reports these numbers; it does not enforce thresholds or fail on regression.

## The coverage ledger

Every catalog id must be accounted for exactly once as `measured`,
`zero_fire`, `cold_only` or `adversarial_only`. The ledger is built from the
same replay as the baseline (no second corpus scan) plus the sibling sources:

```bash
uv run python scripts/coverage_ledger.py --jobs 8
```

It writes `tests/fixtures/coverage-ledger.json`. A measured rule records the
source and strata that exercised it; a zero-fire rule names the shape it
expects; a cold-only rule points at the history/warm replay; an
adversarial-only rule points at its attack fixtures. The `coverage ledger is
complete` gate fails when an id is missing, a state is outside the closed set,
or a non-measured rule has no reason.

The ledger also records `benign_sources`, `benign_strata`, `benign_state`,
`expected_met`, and the reviewed `disposition` for each id. `benign_state`
separates a rule that fired on a benign source from one measured only by the
malicious fixtures.

`strata.toml` carries `expected_rules` per stratum. A rule not yet exercised
by a benign source must have an entry in
`tests/fixtures/coverage-dispositions.json`:

- `deferred` with a plan such as `add_benign_shape`, `add_history_or_warm`,
  `attack_only`, `not_measurable`, or `known_false_positive`;
- `resolved` once the plan has been applied. A resolved `attack_only` or
  `not_measurable` plan must not still appear in `strata.toml` as a benign
  expectation.

The `coverage expectations are met or dispositioned` gate is a ratchet. It
passes while current gaps are deferred, and fails when an expected rule
appears without a disposition. When the debt is paid down, remove the
deferred entries and the gate becomes strict.

Run the coverage gates after building the ledger:

```bash
uv run python scripts/calibration_gates.py --coverage-only \
  --coverage-ledger tests/fixtures/coverage-ledger.json
```

`coverage_ledger.py --check` rebuilds the ledger and fails when the committed
file is stale. `--check-existing` compares an already-built ledger and is what
CI uses, so it does not replay the corpus twice.

`ledger_audit` remains the before/after corpus-delta view. It does not check
whether the current ledger meets expectations; use `unmet_expectations` or the
coverage gate for that.

A stratum that moves no expected row is either redundant or its predicate is
wrong; both are findings, not a reason to add a rule-targeted package.

## Provenance screen

The corpus is a negative control, so a package or diff already on a known-bad
list must never enter it. The screen runs at build time over the lock and in
CI over the reconstructed diffs:

```bash
uv run python scripts/corpus_provenance.py --lock tests/fixtures/corpus.lock
uv run python scripts/corpus_provenance.py --corpus tests/fixtures/benign-corpus
```

It checks compromised-package lists, IOC package/hash/domain/path/pattern
entries, the official watchlist and known malicious commits, and records the
indicator-source digest and `N of M` exclusion counts in the lock/report.

## Warm replay

`rebaseline.py --warm` runs a second pass over the corpus against the first
pass's observation state. State is seeded from the corpus itself, never a
downloaded seed. The cold rates remain the gate; the `warm` block is the
second measurement for novelty and corpus-behavioral rules.

## Artifact manifests

Diffs never exercise the A-series. `tests/fixtures/artifact-corpus/` carries
one reviewed manifest per stratum plus negative controls, and the
`artifact corpus` gate checks every expected finding and requires the font
manifest to trip nothing. Real manifests can be imported from the out-of-tree
build lane with:

```bash
python scripts/build_artifact_corpus.py --from-dir /tmp/manifests
```

## Reading the strata table

The script prints a line per stratum. The counts scale with the corpus snapshot
and the `p95`/`zero` values with the ruleset, so the numbers here are an example
from an earlier corpus snapshot rather than a fixed expectation:

```
  source_patched: 554 diffs, p95=15, zero=86.6%
  bin_repack: 1034 diffs, p95=20, zero=89.6%
  data_fonts: 185 diffs, p95=20, zero=74.6%
```

Treat a falling `zero` or a rising `p95` as a signal that a rule has become too aggressive. Thresholds are a review judgement, not something the script checks.

## The projection baseline

`baseline.json` records the score distribution; the parse itself is pinned
by `tests/fixtures/diffdoc-projections.json.gz`. Regenerate it after a
deliberate change to the diff parse (`diffdoc.py` and what it feeds), or
after the locked corpus moves:

```bash
uv run python tests/harness/diffdoc_parity.py \
  --write tests/fixtures/diffdoc-projections.json.gz
```

The header pins the corpus by `corpus_content_sha256`; a baseline that does
not match the corpus fails the run, and the mismatch is reported alongside the
projection diffs. A parse
change that moves no finding still needs the baseline regenerated in the
same commit as the parser change, reviewed on its own. The baseline is
checked by the sampled suite (`tests/test_diffdoc_parity.py`) and whole by
the calibration CI job.

## Parallel analysis

The calibration gate and the two analysis-heavy parity harnesses accept
`--jobs`, which defaults to `min(8, CPUs)`:

```bash
uv run python scripts/calibration_gates.py --jobs 8
uv run python tests/harness/finding_parity.py --check <baseline> --jobs 8
uv run python tests/harness/typed_core_parity.py --check <baseline> --jobs 8
```

Packages are analysed in worker processes, with each package's global URL
prefix precomputed exactly and its diffs kept in order, so a full-corpus run
drops from roughly fifty minutes to a few. Pattern-safety verdicts (including
the generated `R013`/`R047`/`R048`/`R152` patterns) are decided once in the
parent before the workers start, so a rule cannot vanish under pool load.
Library callers stay serial. `rebaseline.py` and the cheap `diffdoc_parity.py`
and `change_parity.py` harnesses take no `--jobs`.

## After re-baselining

1. **Update** `tests/fixtures/baseline.json` with the newly generated file.
2. **Update** any malicious/fixture `expected.json` scores if they changed.
3. **Commit** the baseline change **separately** from the rule or config change that caused it. This keeps the commit history clean and makes reverts easier.

```bash
git add tests/fixtures/baseline.json
git commit -m "re-baseline after <description of change>"
```
