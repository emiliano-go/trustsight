# Re-baselining

The baseline (`tests/fixtures/baseline.json`) records the expected score distribution over the pinned corpus. It must be regenerated whenever the scoring logic changes.

## When to re-baseline

Trigger a re-baseline after any of the following:

- A **weight** change in `config.toml`
- A **rule addition**, **removal**, or **severity** change
- A **pattern** change in `rules.toml`
- Fixing a **bug** that affects scoring

If in doubt, re-baseline. CI will reject a stale baseline anyway.

## How to run

```bash
python scripts/rebaseline.py
```

The script:

1. Checks out the corpus pinned in `tests/fixtures/corpus.lock`.
2. Runs the full analysis pipeline on every package.
3. Computes per-**stratum** (benign, malicious, synthetic) statistics:
   - Zero-rate : fraction of packages scoring 0
   - p5, p50, p95 scores
4. Validates **CI gates**:
   - **CRITICAL recall** = 100% : every malicious/synthetic fixture must trigger at least one CRITICAL rule
   - **CRITICAL p5 > benign p95**: the 5th-percentile CRITICAL score on malicious/synthetic must exceed the 95th-percentile on benign
   - **Zero-rate ≥ 80%**: at least 80% of benign packages must score 0 on every scored rule
5. Writes the new `tests/fixtures/baseline.json`.

## Reading the strata table

The script prints a strata table similar to:

```
Stratum         Packages    Zero-rate    p5    p50    p95
benign          1,234       91.2%        0     0      8
malicious       47          0.0%         42    68     95
synthetic       89          0.0%         38    72     98
```

Each stratum should clear the **70% zero-rate target** for benign packages. If a stratum falls below 70%, investigate whether a rule is too aggressive.

## After re-baselining

1. **Update** `tests/fixtures/baseline.json` with the newly generated file.
2. **Update** any malicious/fixture `expected.json` scores if they changed.
3. **Commit** the baseline change **separately** from the rule or config change that caused it. This keeps the commit history clean and makes reverts easier.

```bash
git add tests/fixtures/baseline.json
git commit -m "re-baseline after <description of change>"
```
