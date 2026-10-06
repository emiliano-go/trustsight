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

This regenerates the exact diffs recorded in the lock (~200 packages, ~11 minutes cold; the fetched objects are cached under `~/.cache/trustsight/aur.git`). The selection is deterministic: the same lock names the same packages and diffs on any machine. The reconstructed *bytes* are not byte-identical across git versions, though - `git diff -W` output is not byte-stable, which is why the calibration workflows download the packed release asset rather than rebuilding from the lock (see `.github/workflows/corpus-drift.yml`).

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

The header pins the corpus by `corpus_content_sha256`, so a baseline that
does not match the corpus fails before any projection is compared. A parse
change that moves no finding still needs the baseline regenerated in the
same commit as the parser change, reviewed on its own. The baseline is
checked by the sampled suite (`tests/test_diffdoc_parity.py`) and whole by
the calibration CI job.

## After re-baselining

1. **Update** `tests/fixtures/baseline.json` with the newly generated file.
2. **Update** any malicious/fixture `expected.json` scores if they changed.
3. **Commit** the baseline change **separately** from the rule or config change that caused it. This keeps the commit history clean and makes reverts easier.

```bash
git add tests/fixtures/baseline.json
git commit -m "re-baseline after <description of change>"
```
