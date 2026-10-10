<!-- Keep it short. Delete sections that do not apply. -->

## What this changes

<!-- One or two sentences. If it adds or changes a rule, name it. -->

## If this adds or changes a rule: the three axes (Addendum 5 §5)

- **Mechanism (series):** R / H / C / X / E / T / G / I / M
- **Subject (category):** the reference page that owns it
- **Trajectory hole (layer):** which layer the attack would otherwise pass
- **Diversity vs redundancy:** if another layer's series covers the same
  attack, why is this a *different* mechanism rather than a redundant one?
  (If it is redundant, file it as an instance of the existing mechanism.)

## Checks

- [ ] `uv run pytest` passes (the locked-corpus replay is byte-identical, or
      every difference is adjudicated in the changelog).
- [ ] A new H-series id is **not** added while the live count is above the
      reduction target (Addendum 3 intake freeze).
- [ ] New detection rules ship with a benign fixture pair and a
      calibration-gate entry; thresholds are published, not guessed.
- [ ] `docs/reference` is updated, and `uv run python scripts/build_rules_index.py`
      was run if the catalog changed.
