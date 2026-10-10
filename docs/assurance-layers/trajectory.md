<!-- description: The L1-L8 layers an update passes, the series that guards each, and what "a finding carries the layer where it caught" means for the profile. -->

# Part 1: The trajectory

A change reaches the user's machine by passing every layer in order. Each
layer answers one question, and a rule that answers it is filed there. The
layer is not what the rule protects; it is where the evidence sits.

| Layer | Name | Question | Default series |
|---|---|---|---|
| L1 | Structural coherence | Does the change hang together as an honest edit? | C, M |
| L2 | Readability | Was anything hidden from the reader? | W (and X026/X027) |
| L3 | Payload signature | Does it do a known-bad thing? | R, S |
| L4 | Evasion shape | Was it *written* to defeat reading? | X, E |
| L5 | Behavioral suspicion | Does the package's story make sense? | H |
| L6 | Ecosystem memory | Has the ecosystem seen this before? | D, T |
| L7 | Known indicators | Is it on the list? | I (the IOC tier) |
| L8 | Campaign correlation | Do other packages tell the same story? | G |

## The layer where it caught

The single rule that makes the profile worth reading: **a finding carries the
layer where it caught, not the layer it guards.** A rule that detects an
evasion (L4) is protecting the payload space (L3), but it reports L4. The
profile then shows "L4 fired, L3 passed" - which is the truth - rather than
folding the two into one reassuring line.

This is what distinguishes the layer profile from a severity grade. A
severity answers "how bad"; a layer answers "how far in did the attacker
get, and where was it stopped".

## Series-to-layer defaults and overrides

`trustsight.layers` holds the mapping as data: a per-series default, and a
short table of per-rule overrides for the rules whose mechanism diverges from
their series.

- **C** defaults to L1, **R** and **S** to L3, **X** to L4, **H** to L5,
  **D** to L6, **T** to L6, **E** to L4, **G** to L8, **P** to L1, **W** to
  L2.
- **Overrides**: the refusal family X026/X027 fires at the readability
  boundary (L2) rather than as an evasion shape; the observation-database H
  rules (H020, H021, H022, H026, H028, H037, H044, H045, H046, H058, H060,
  H073, H074, H086, H088) read stored history and belong to L6; H056 is an
  indicator match and belongs to L7.
- **No static layer**: the **M** series fires *at* the layer of its inputs
  (it records which findings composed), and the **A** series is the reserved
  L9 build lane, not an L1-L8 layer at all. Both return no single layer, and
  that is by design, not an omission.

## Where the profile comes from

The report's `layers` object is a projection of the finding set, keyed
`L1`..`L8`, each `{name, status, findings}`. A finding is filed under
`layer_of(rule_id)`, so no consumer re-derives the mapping and no two
surfaces can disagree about a rule's layer. The statuses and what makes a
layer `unreadable` are [Part 3](reporting.md)'s subject.

## What this part does not claim

- It does not claim every attack is caught at a layer. A layer with no
  finding is `passed` only when the run was fully read; otherwise it is
  `unreadable`, and that distinction is the point.
- It does not claim the layers are equally strong. `L4` is where the
  statistical and refusal mechanisms overlap most; the diversity argument in
  [Part 2](diversity.md) is what keeps that overlap from being redundancy.

## See Also

- [Part 2: Diversity and intake](diversity.md)
- [Rule Nature](../reference/rules/nature.md) - the series in full
