<!-- description: How to add a useful new detector: the intake checklist, shared dependencies, and why complementary coverage is not the same as independent coverage. -->

# Part 2: How to add a useful new detector

This page answers: what does a new rule have to demonstrate before it ships?
The four labels it names are defined once in the
[glossary](../../reference/glossary.md).

## The intake checklist

A proposed rule names four things:

1. **Mechanism (family).** How it reaches its conclusion - a regex, a
   structural invariant, a heuristic, a statistic, and so on.
2. **Subject (category).** What behaviour or property it is concerned with;
   this is the closed category that owns its reference page.
3. **Evidence category (layer).** Which evidence label groups its findings.
4. **Shared dependencies.** The infrastructure it relies on - the tokenizer,
   parser, history database, corpus, or indicator baseline.

It must also answer one question: **what attack variation does this rule catch
that the existing rules miss?** If a rule on another category already covers
the same attack, file the change as an instance of that rule instead, or argue
why the new mechanism adds *complementary* coverage.

### The checklist on a concrete proposal

A proposed invariant: "the `.SRCINFO` `depends` set names a package the
PKGBUILD never mentions." Filled in:

| Field | Value |
|---|---|
| Mechanism (family) | `C`, a structural invariant over two parsed documents |
| Subject (category) | integrity |
| Evidence category (layer) | `L1` (the `C`-series default: the change does not hang together) |
| Shared dependencies | the tokenizer and the `.SRCINFO` parser |
| Attack variation | `H103` compares `depends` only when both documents state the field and neither carries an unresolved variable, so a variable-guarded divergence evades it |

The last row is the question intake exists to force. If no answer holds, the
change is an instance of an existing rule, not a new one.

## Complementary is not the same as independent

Different algorithms are **not** automatically independent. Two rules that use
different logic can share a failure mode:

```
        ┌───────────┐            ┌────────────┐
        │   R001    │            │   H082     │
        │  (regex)  │            │(heuristic) │
        └─────┬─────┘            └─────┬──────┘
              │                        │
              └────────────┬───────────┘
                           ▼
                    ┌─────────────┐
                    │  tokenizer  │   one failure blinds both
                    └─────────────┘
```

R001 matches `curl ... | bash`; H082 reasons about a fetch that is then
executed. Both depend on the **tokenizer**. If the tokenizer folds a construct
incorrectly, both can go blind together. Their family labels differ; their
failure is correlated. The dependency is recorded in
[`trustsight.detectors`](enforcement.md) and named at intake, so common-mode
failure is visible rather than assumed away.

Independence is therefore a **hypothesis to test**, not a property inherited
from a different family name. [Part 4](enforcement.md) describes the
adversarial harness that measures how often bypassing one mechanism also
bypasses another.

## Where one category tends to catch what another misses

No evidence category is universal. The table is a set of **hypotheses about
coverage complementarity**, not guarantees: each row names a variation that
tends to evade one mechanism and surface in another. Every row is a claim to
test, not a result the tool has proven - the adversarial harness
([Part 4](enforcement.md)) is what would turn a row into a measurement. A row
whose "Status" is a fixture name is exercised; `hypothesis` is not yet.

| Tends to evade… | …and surface in | Why (hypothesis) | Status |
|---|---|---|---|
| R (regex) | X (refusals) | evading a pattern needs constructs the tokenizer will not fold | hypothesis |
| X (refusals) | E (entropy) | resolving cleanly but weirdly is statistically visible | hypothesis |
| E (statistics) | C (invariants) | normalised statistics cannot repair a violated invariant | hypothesis |
| C (invariants) | T/G (ecosystem) | a coherent diff can still be anomalous against history and neighbours | hypothesis |
| T/G (ecosystem) | M (claims contradiction) | fitting the ecosystem while contradicting your own declarations is detectable | hypothesis |

A proposed rule that claims to cover a row must say whether it is *adding*
that coverage or *re-testing* it; the intake checklist below is where that
argument belongs.

## What a new rule must ship with

- A **positive fixture** it must fire on.
- A **benign lookalike** it must stay silent on (the S-series fixture-pair
  gate enforces this for sabotage rules; it is good practice for all).
- A **calibration gate entry**: its benign-corpus fire rate is measured and
  published before its threshold ships.
- A **shared-dependencies entry** so the gate `every rule names its shared
  dependencies` passes.

## The H intake freeze

New heuristic (H) rule ids are frozen while the H series is above its
reduction target. New detections must be an instance of an
existing family (a C-series invariant, an X-series refusal, an E-series
statistic, ...) rather than another H id. See
[Rule Series](../../rules/series.md).

## See Also

- [Evidence Categories](../../reference/evidence-categories.md)
- [Part 3: Reporting](reporting.md)
- [Writing a rule](../../contributing/writing-a-rule.md)
