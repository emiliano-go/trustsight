<!-- description: Why the H (heuristic) series is under an intake freeze, how the co-fire audit decides a merge, and why nothing has been retired yet. -->

# Reducing the H-Series

The H series is TrustSight's catch-all. A rule lands in H by **exclusion**:
if a detection is not a regex (`R`), a structural check (`C`), a dependency
rule (`D`), a sabotage rule (`S`), a crossfire rule (`X`), a signature match
(`T`), a correlation (`G`) or an entropy measure (`E`), it is a heuristic, and
heuristics are H. That default is why the series grew to 103 ids - and why some
of them overlap, some are corpus-dependent, and some have never fired on the
locked corpus.

This page explains the plan to shrink it, the two mechanisms that enforce the
plan, and why the retirement map is still empty.

## The problem: an unbounded drawer

Two H rules can describe the same behaviour from slightly different angles.
`H026` (maintainer change to a never-seen identity) is a strict subset of
`H044` (ownership transition): every `H026` firing is also an `H044` firing.
Left alone, that is two ids, two doc entries, two config overrides and two
weights for one phenomenon - and a reviewer who sees both cannot tell whether
they are looking at one signal or two.

The reduction plan is to **merge rules that co-fire** and shrink the live,
emitting surface to a target band of **55-65 ids**.

## How a merge is decided

`scripts/h_reduction_audit.py` measures, for each candidate pair, the co-fire
ratio

```
|A & B| / min(|A|, |B|)
```

over the benign corpus, the labelled malicious fixtures and the replayable
history cycles. The published decision rule: a pair co-firing at or above the
epsilon (default **0.95** of the rarer rule's firings) *may* merge, with the
higher-severity id surviving. The script **measures only**; it never retires an
id. The output is evidence a human adjudicates in the changelog.

## Why nothing was retired

The audit measured nine candidate pairs. The strongest co-firers are either

- **strict subsets** - `H026` is contained in `H044`, so there is nothing to
  merge that `H044` does not already say; or
- **different mismatches** - `H053` (name/host consensus) and `H059`
  (name/repo path) share a name but describe different disagreements, and a
  merge would erase which one fired.

The rest are distinct. So `RETIRED_RULE_IDS` stays empty: the mechanism ships
ready, but the map is a **data change no evidence currently supports**.

The zero-fire ledger is not a retirement licence either. It includes rules with
no fixture that still carry real detection value - the temporal and correlation
families, `H083`-`H085`, `H089`/`H090`/`H093`/`H094`. Retiring from a count
alone would delete detections the security model does not license removing.

## The two mechanisms

### Intake freeze (hard)

`FROZEN_H_IDS` is the explicit set `H001`-`H103`, taken at the start of the
reduction. `tests/test_h_reduction.py` and the `H-series intake is frozen`
security gate fail a PR that adds a new H id. A new detection must be filed as
an instance of an existing H family, or into the series that fits its mechanism
(`T` for history-backed rules, `T001`/`T002`; `C`, `D`, `X`, `E`, `I` or `M`
otherwise). The freeze set only ever shrinks: a retired id moves to
`RETIRED_RULE_IDS` and stays out of the freeze, so its former id is never
re-issued.

### Residue report (advisory until the ceiling)

The `H-series reduction residue` gate reports the live (emitting) count against
the target band but **fails only above the frozen ceiling** - the frozen set
minus the retained documentation anchors (`H005`-`H014`, `H028`, which emit
nothing and exist so reference links resolve):

```
ceiling = len(FROZEN_H_IDS) - len(ANCHOR_RULE_IDS) = 103 - 11 = 92
```

A count that is merely **above the target band does not fail**. No
evidence-supported merger remains, so failing on the number would force a
change the evidence does not license. Only exceeding the ceiling - a new id
slipping past the freeze - is a hard failure.

## If a merge is later supported

1. Add the pair to `RETIRED_RULE_IDS` (`retired_id -> survivor_id`).
2. Remove the retired id from `FROZEN_H_IDS` (it never returns).
3. The survivor keeps emitting. A `config.toml` override keyed to the retired
   id still suppresses the survivor: `survivor_id` resolves a retired id to its
   survivor and then through `RENAMED_RULE_IDS`, and
   `override.filter_triggered_rules` applies it.
4. The retired id's reference entry becomes a one-paragraph stub, and
   `sync-rules` never resurrects it.

See also [Rule Nature](../reference/rules/nature.md#h-series-heuristic-behavioral-analysis)
and the [Rule System](../reference/rules/system.md).
