<!-- description: The assurance onion: an attacker's trajectory through layers, why the layers' mechanisms must be independent, and which series guards which layer. -->

# The Assurance Layers

TrustSight's rules are organised two ways. The **series** axis says what
kind of mechanism a rule uses (regex, heuristic, invariant, refusal,
statistics). The **layer** axis says *where on the path from repository text
to a running machine* the rule's evidence sits. The two are independent by
design, and this page explains why.

## The trajectory

A change reaches the user's machine only by passing every layer:

| Layer | Name | Question | Primary series |
|---|---|---|---|
| L1 | Structural coherence | Does the change hang together as an honest edit? | C, M |
| L2 | Readability | Was anything hidden from the reader? | X (refusals), W |
| L3 | Payload signature | Does it do a known-bad thing? | R, S |
| L4 | Evasion shape | Was it *written* to defeat reading? | X, E |
| L5 | Behavioral suspicion | Does the package's story make sense? | H |
| L6 | Ecosystem memory | Has the ecosystem seen this before? | D, T |
| L7 | Known indicators | Is it on the list? | I (IOC) |
| L8 | Campaign correlation | Do other packages tell the same story? | G |

P (claims) and W (boundaries) are render surfaces, not trajectory layers:
P maps to L1 as *input* (a claims ledger), W maps to L2 as *boundary
reporting*. A finding carries the layer where it **caught**, not the layer
it protects, so an evasion-shape rule caught at L4 reports L4 even though
the payload it would have shielded lives at L3.

## The integrity rule

**Each layer's mechanism must be independent of its neighbors'.** Diversity
is what makes holes fail to align. That is why the same series can sit at
two layers (X at L4, X026 at L2) and why two series can share a layer (X and
E both at L4 - refusal-based versus statistical; the difference *is* the
point). The series axis is the diversity guarantee; the layer axis is the
coverage guarantee. Neither may imply the other.

## The transcendence table

Each mechanism is beaten by the next, which is why the stack is layered
rather than one clever rule:

| Evades… | …caught by | Because |
|---|---|---|
| R (regex) | X (refusals) | evading patterns needs constructs the tokenizer won't fold |
| X (refusals) | E (entropy) | resolving cleanly but weirdly is statistically visible |
| E (statistics) | C (invariants) | normalized statistics can't repair a violated invariant |
| C (invariants) | T/G (ecosystem) | a coherent diff can still be anomalous against history and neighbors |
| T/G (ecosystem) | M (claims contradiction) | fitting the ecosystem while contradicting your own declarations is detectable |

## What the report shows

The JSON report (CLI and API) carries a `layers` object: per layer,
`status` (`fired` / `passed` / `unreadable`) and the rule ids that fired
there. `unreadable` is reserved for layers a coverage gap left
unexercised - a truncated diff blinds the layers that read content. The
verdict names the deepest layer hit; the flat findings remain beneath it.

The adversarial harness reads the same projection: each attempt records the
layers it traversed and the layer that stopped it, and the campaign rollup
reports the **minimum layer-cut** - the smallest layer set that stops every
recorded attack class. A target of at least two is the goal: no single
regression should reopen a trajectory.

## See Also

- [Rule Nature](../reference/rules/nature.md) - the series taxonomy
- [Rules Reference](../reference/rules/index.md) - the catalog by category
