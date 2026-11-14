<!-- description: Tests and adversarial evaluation: what the gates prove about the layer model's implementation, and what the harness measures about detection diversity. -->

# Part 4: Tests and adversarial evaluation

This page answers: what do the automated tests actually establish?

Three different claims are often confused. This page keeps them apart:

| Claim | What substantiates it | Status |
|---|---|---|
| The layer model is **implemented correctly** | The security gates in `scripts/security_gates.py` | Gated in CI |
| The mechanisms give **complementary coverage** | The adversarial harness (`trustsight-harness`) | Measured; results not yet published here |
| The tool **performs well on real threats** | Independent, ideally blinded evaluation | External, not claimed |

Passing the gates establishes only the first. A gate that passes is not
evidence that a malicious package will be detected.

```
implemented correctly ── security gates ──────────────── Gated in CI
        ▲ a passing gate says nothing about
complementary coverage ── adversarial harness ────────── Measured, not published
        ▲ a harness number says nothing about
real-world performance ── independent, blinded eval ──── Not claimed
```

Each row is established only by its own method. A green build does not move
down the list. The vocabulary these pages share is defined once in the
[glossary](../reference/glossary.md).

## Implementation gates

The layer model's invariants are enforced by gates that fail the build:

| Gate | Invariant |
|------|-----------|
| `every rule carries exactly one layer` | Every categorised rule maps to exactly one evidence category; M and A have none by design. The L9 artifact lane is outside this set: artifact findings are reported separately and are never assigned an L1-L8 layer. |
| `layer detection and coverage are independent` | A fired category and an incomplete category are reported as separate facts. |
| `every rule names its shared dependencies` | Every rule has a mechanism, subject, evidence source and shared-dependency entry. |
| `docs layer mapping matches the registry` | The Part 1 table is generated from `trustsight.layers`; prose cannot drift from code. |
| `layer overrides stay within the closed set` | A `[layers]` config override cannot move a rule outside L1-L8. |
| `boundaries are the coverage view` | Every coverage gap maps to a boundary; the two representations cannot diverge. |

Run them whole with:

```bash
python scripts/security_gates.py
```

The `every rule names its shared dependencies` gate reads
`trustsight.detectors`, which records each family's mechanism, evidence source
and shared infrastructure (tokenizer, history database, corpus, ...). This is
what makes common-mode failure visible: two different mechanisms that share a
dependency can go blind together.

## Adversarial evaluation (the harness)

The **adversarial harness** (`trustsight-harness`) attacks the tool and records
which evidence categories fire on each attempt. For each attempt it records
`observed_layers` - the categories that actually fired - and rolls the
campaign up into:

- **minimum layer-cut**: the exact smallest set of fired categories that covers
  every caught attempt (enumerated, not approximated; `exact_minimum_cut` is
  the same function under its explicit name). A fully-bypassed attempt
  (nothing fired) is uncuttable and is reported separately as a bypass
  (`layers_fully_bypassed` is the count).
- **single-layer-failure**: for each category, how many caught attempts fire
  *only* in that category - disable it and they pass. This is the empirical
  "does one layer's failure reopen a path" number.
- **resilience distribution**: the histogram of how many distinct categories
  caught each caught attempt. A campaign whose mass sits at `1` is one
  regression from a bypass regardless of its minimum cut.
- **bypasses**: attempts that fired nothing (`fully_bypassed`).

An earlier version of this metric inferred a traversal path, which made every
path contain L1 and the minimum cut structurally one. It is now a projection
of the categories that fired, and the cut is exact.

The harness's own gates are unchanged: it never executes package code (a
`bash -n` syntax check at most), and its records are telemetry only.

## What is published, and what is not

The harness's CLI now prints a `layer_resilience` summary for every campaign:
attempts, outcome counts, bypasses, the exact minimum layer-cut, the
single-layer-failure counts, the resilience distribution, and the campaign's
declared attack-set **limitations** (`limitations` in the record). Those
numbers are per campaign and depend on the attack set; the limitations travel
beside them so a rate is never read as a whole-corpus claim.

What is **not** on this page is a single rolled-up figure across every
campaign. A cross-campaign published number would have to state its combined
attack-set limitations; until that exists, treat the "complementary coverage"
claim as a hypothesis the harness is built to test, not an established
property - and note the third level, real-world performance, is external
evaluation this project does not claim.

An illustrative summary (the numbers depend entirely on the attack set):

```json
"layer_resilience": {
  "attempts": 12,
  "outcomes": {"blocked": 10, "bypassed": 2},
  "bypasses": 2,
  "minimum_layer_cut": 2,
  "single_layer_failure": {"L3": 4, "L5": 1},
  "resilience_distribution": {"1": 5, "2": 3, "3": 2},
  "layers_fully_bypassed": 2,
  "limitations": ["no Windows toolchain", "no network access during the attempt"],
  "cofire_health": []
}
```

and the CLI's two-line form of the same record:

```
layer resilience: minimum layer-cut 2, single-layer failures {'L3': 4, 'L5': 1}, bypasses 2
attack-set limitations: no Windows toolchain; no network access during the attempt
```

Read it: two categories (`L3`, `L5`) cover every caught attempt, so the minimum
cut is 2. `L5` alone holds up one attempt (`single_layer_failure: {"L5": 1}`), so
disabling it reopens a path. Five caught attempts fired exactly one category
(`resilience_distribution: {"1": 5}`), each one regression from a bypass. The
two remaining attempts fired nothing and are counted as bypasses. The
`limitations` list travels beside the numbers so a rate is never read as a
whole-corpus claim.

## See Also

- [Part 3: Reporting](reporting.md)
- [The security enforcement map](../security/enforcement-map.md) - the
  threat-model gates this section complements
- [Fire rates](../explanation/fire-rates.md) - the calibration gates
