<!-- description: The assurance onion: an attacker's trajectory through layers, why the layers' mechanisms must be independent, and how the layer model is reported, enforced and measured. -->

# The Assurance Layers

TrustSight's rules are organised two ways, and only one of them is obvious
from the rule list. The **series** axis says what kind of mechanism a rule
uses - regex, heuristic, invariant, refusal, statistics, history,
correlation, indicator, meta. The **layer** axis says *where on the path
from repository text to a running machine* the rule's evidence sits. The two
are independent by design, and that independence is the whole point.

This section states the layer model the way the [security model](security.md)
states the threat model: a thesis here, then the parts that make it precise,
each backed by an executable gate. Nothing below is aspirational. Every
invariant has a check in `scripts/security_gates.py` (which CI runs on every
push, and which fails the build), in `scripts/calibration_gates.py`, or in
the suite. A claim without a gate is a claim this project does not make.

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

A finding carries the layer where it **caught**, not the layer it protects,
so an evasion-shape rule caught at L4 reports L4 even though the payload it
would have shielded lives at L3. That is the whole reason the axis is useful:
the profile then shows "L4 fired, L3 passed" - the honest swiss-cheese
picture - rather than a single reassuring verdict.

## The integrity rule

**Each layer's mechanism must be independent of its neighbors'.** Diversity
is what makes holes fail to align: an attacker who evades the regex family
needs a different construct to evade the refusal family, and a different one
again to evade the invariant family. If two layers shared a mechanism, a
single evasion would open both, and the layered picture would be a fiction.

That is why the same series can sit at two layers (X at L4, X026 at L2) and
why two series can share a layer (X and E both at L4 - refusal-based versus
statistical; the difference *is* the point). The series axis is the diversity
guarantee; the layer axis is the coverage guarantee. Neither may imply the
other.

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

## Parts 1 to 4

The model is split across the rest of this section. The thesis above stays
here; each part below has its own page:

- **[Part 1: The trajectory](assurance-layers/trajectory.md)** - the L1-L8 layers, the
  series-to-layer defaults and overrides, and what "the layer where it
  caught" means precisely.
- **[Part 2: Diversity and intake](assurance-layers/diversity.md)** - why the layers'
  mechanisms must stay independent, and the three-axis intake rule that keeps
  a new rule honest about mechanism, subject and trajectory hole.
- **[Part 3: Reporting](assurance-layers/reporting.md)** - the `layers` object, its
  `fired`/`passed`/`unreadable`/`not_exercised` statuses, and the
  deepest-layer verdict.
- **[Part 4: Enforcement](assurance-layers/enforcement.md)** - every layer invariant
  mapped to the gate that fails when it stops being true, and the adversarial
  harness that measures whether the holes align.

The layer taxonomy is the theory; the four parts are the enforcement.

## See Also

- [Rule Nature](reference/rules/nature.md) - the series taxonomy in full
- [Rules Reference](reference/rules/index.md) - the catalog by category
- [The security model](security.md) - the threat model this section
  complements
