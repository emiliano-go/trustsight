---
description: How to integrate TrustSight into CI/CD pipelines.
---

# Using TrustSight in CI

TrustSight is designed to be scripted. The exit code and the review table give you everything you need to gate a pipeline; no JSON parser required, though one is planned.

## Exit codes

| Code | Meaning |
|------|---------|
| **0** | All packages scored CLEAN (≤20) |
| **1** | One or more packages have a FLAGGED verdict (>20) |
| **2** | An error occurred |

A minimal CI step:

```bash
trustsight review
if [ $? -eq 1 ]; then
  echo "One or more AUR packages flagged; investigate before updating."
  exit 1
fi
```

## Policy gating

Decouple the score from your pass/fail decision. TrustSight's verdict threshold (20) is a sensible default but your team's tolerance may differ.

```bash
trustsight review --min-score 40
```

This exits 1 only if at least one package scores above **40**; useful for a CI pipeline that wants to ignore minor novelty bumps.

You can also set a custom threshold in `config.toml`:

```toml
[policy]
fail_threshold = 40
```

## JSON output (future)

A `--json` flag is planned for the `review` and `inspect` commands. The output will expose the full `PackageFact` structure (per-package scores, triggered rules, bucket classifications, and evidence breakdown) for consumption by downstream tooling.

Until then, capture the terminal table or parse the exit code.

## Per-class CI regression

For teams that want a statistical gate, TrustSight publishes benchmark distributions for each severity class on the [benchmarks page](../explanation/benchmarks-and-methodology.md):

| Class | Metric | Value |
|-------|--------|-------|
| CRITICAL | p5 (5th percentile) | **40** |
| Benign | p95 (95th percentile) | **20** |
| Zero-rate (benign scored >0) | percentage | **81.5%** |
| Test count | total | **267** |

**The gate:** if a CRITICAL-class package consistently scores at or above its p5 (40) and no benign package exceeds its p95 (20), the classifier achieves clean separation with no overlap.

To set up your own gate:

1. **Run a baseline** against your package set after initial configuration. See the [re-baselining guide](../contributing/re-baselining.md).
2. **Choose a threshold**: typically 30–40, depending on your tolerance for benign novelty signals.
3. **Add a CI check** that compares regression scores against the baseline. Any package whose score moves from CLEAN to FLAGGED without a corresponding PKGBUILD change is a regression.

The CRITICAL recall of **100%** means every CRITICAL-class malice sample in the corpus scores ≥40. A gate at 40 catches all known CRITICAL patterns and passes benign bumps that score ≤20 at the 95th percentile.

## Nightly vs per-commit

- **Per-commit**: run `trustsight review` on every PR that touches a PKGBUILD or a `rules.toml` change. Use exit code gating.
- **Nightly**: run a full review of all installed AUR packages and diff the output against the previous night. Detects drift over time.

## Config in CI

Check in your `config.toml`, `rules.toml`, and the TrustSight database alongside your code. The `trustsight review` command respects the local config tree automatically.

See also:
- [Configuring rules and weights](configuring-rules-and-weights.md)
- [Exit codes reference](../reference/exit-codes.md)
