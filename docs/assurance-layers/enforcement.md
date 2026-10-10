<!-- description: Every layer invariant mapped to the gate that fails the build when it stops being true, and the adversarial harness that measures whether the layers' holes align. -->

# Part 4: Enforcement

Everything in Parts 1 to 3 is a claim. This part is the proof. **A claim
without a gate is a claim this project does not make.**

The layer gates live in `scripts/security_gates.py`, which CI runs on every
push and every pull request and which exits non-zero when any gate fails.
Run them whole with:

```bash
python scripts/security_gates.py
```

| Gate | Invariant |
|------|-----------|
| `every rule carries exactly one layer` | Addendum 5 §2: `layer_of` is a total, single-valued lookup over the categorised rules; L1-L7 are non-empty; M and A intentionally have no static layer. |
| `the layer profile is gap-precise and additive` | Addendum 5 §3: a history gap blinds only L6, a tokenizer refusal L1-L4, content truncation every layer; L8 is `not_exercised` on a single-package run; a finding marks its own layer `fired`. |
| `boundaries forbid clean exactly when coverage gaps exist` | Addendum 2 W1 / B2: `forbids_clean(boundaries_from_fact(f))` equals `bool(coverage_gaps)`; a W-only boundary does not forbid a clean verdict. |
| `the indicator tier mirrors ioc_matches` | Addendum 5 §6.4 / B1: the promoted `indicators` array mirrors `ioc_matches` and never moves the score. |
| `H-series intake is frozen` | Addendum 3: no new H id is added above the reduction target. |

The registry itself is also pinned by the suite: `tests/test_layers.py`
asserts every non-M/A rule has exactly one layer, that the refusal family and
the observational overrides land where Parts 1 and 2 say, and that the L1-L7
layers are non-empty. `tests/test_boundaries.py` and `tests/test_meta.py`
pin the boundary and meta behavior beside it.

## The adversarial harness: measuring hole alignment

The security gates prove the invariants hold. The **adversarial harness**
(`trustsight-harness`) measures whether the layers' holes actually align, by
attacking the tool and watching which layers stop each attempt.

Every harness attempt records `layers_traversed`: the ordered layers it
passed, and the layer that stopped it (the outermost layer whose rules
fired, or every layer for a bypass). Those records roll up into the
**minimum layer-cut** - the smallest set of layers whose intersection stops
every recorded attack class. A minimum cut of one means a single regression
reopens every trajectory in the class; the target is **at least two**, so no
single failure reopens a path.

The campaign record carries the minimum layer-cut as a scalar, the
**minimum-cut distribution** across attempts, and the **aligned-hole depth**
of each bypass - the number of layers whose holes had to align for it to
succeed. This is the layer model as an instrument - not a claim that the
layers are independent, but a measurement of how independent they proved
against the attacks recorded.

## What this part does not claim

- It does not claim the gates are complete. A gate with no entry on the
  [security enforcement map](../security/enforcement-map.md) is an unstated
  guarantee; the map-sync gate fails the build on either a missing or an
  extra row.
- It does not claim the harness has exhausted the attack space. The
  minimum-cut is a lower bound over recorded classes, and a new class can
  lower it until a layer catches it.

## See Also

- [Part 3: Reporting](reporting.md)
- [The security enforcement map](../security/enforcement-map.md) - the
  threat-model gates this section complements
- [Fire rates](../explanation/fire-rates.md) - the calibration gates
