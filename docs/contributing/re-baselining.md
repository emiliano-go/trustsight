---
description: When and how to regenerate the score-distribution baseline over the pinned corpus after a scoring change, and how to read the resulting diff.
---

# Re-baselining

The baseline (`tests/fixtures/baseline.json`) records the expected score distribution over the pinned corpus. It must be regenerated whenever the scoring logic changes.

## When to re-baseline

Trigger a re-baseline after any of the following:

- A **weight** change in `config.toml`
- A **rule addition**, **removal**, or **severity** change
- A **pattern** change in `rules.toml`
- Fixing a **bug** that affects scoring

If in doubt, re-baseline. The monthly **Corpus Drift Detection** workflow rebuilds the corpus and opens an issue when the stored baseline no longer matches, so a stale baseline surfaces eventually, but nothing blocks a merge on it.

## Materialise the corpus first

The corpus is **not** committed: `*.diff` is gitignored, so `tests/fixtures/benign-corpus/` is absent on a fresh clone and in CI. `rebaseline.py` does not fetch it: it exits with `Corpus not found` if the directory is missing.

Rebuild it from the lock first:

```bash
python scripts/build_corpus.py --from-manifest \
  --manifest tests/fixtures/corpus.lock \
  --out tests/fixtures/benign-corpus
```

This regenerates the exact diffs recorded in the lock (~180 packages, ~11 minutes cold; the fetched objects are cached under `~/.cache/trustsight/aur.git`). It is deterministic: the same lock produces byte-identical diffs on any machine.

Do **not** use plain `build_corpus.py --strata ...` for this. That mode re-selects packages by current AUR popularity and rewrites the lock, producing a different corpus each run.

## How to run

```bash
python scripts/rebaseline.py
```

The script:

1. Reads every `*.diff` under `--corpus`, grouping by package.
2. Replays each package's diffs in true commit order, following the `old_sha -> new_sha` chain in the lock (`--order filename` restores the legacy SHA-hex sort). Order matters because novelty detection is order-dependent.
3. Runs the full analysis pipeline on each diff.
4. Computes per-**stratum** statistics, where a stratum is a package *shape* (`bin_repack`, `vcs_git`, `lang_ecosystem`, `data_fonts`, `dkms_kernel`, `source_patched`, `autotools`, `large_electron`) as assigned by the lock:
   - `n_diffs`, `n_pkgs`
   - `p95` score
   - `zero_pct` : fraction of diffs scoring 0
   - `rules` : per-rule fire rate
5. Writes the new `tests/fixtures/baseline.json`, recording `corpus_content_sha256` so a baseline can be tied to the corpus it came from.

`rebaseline.py` only reports these numbers; it does not enforce thresholds or fail on regression.

## Reading the strata table

The script prints a line per stratum:

```
  source_patched: 554 diffs, p95=15, zero=86.6%
  bin_repack: 1034 diffs, p95=20, zero=89.6%
  data_fonts: 185 diffs, p95=20, zero=74.6%
```

Treat a falling `zero` or a rising `p95` as a signal that a rule has become too aggressive. Thresholds are a review judgement, not something the script checks.

## After re-baselining

1. **Update** `tests/fixtures/baseline.json` with the newly generated file.
2. **Update** any malicious/fixture `expected.json` scores if they changed.
3. **Commit** the baseline change **separately** from the rule or config change that caused it. This keeps the commit history clean and makes reverts easier.

```bash
git add tests/fixtures/baseline.json
git commit -m "re-baseline after <description of change>"
```
