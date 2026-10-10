<!-- description: Why the layers' mechanisms must stay independent, how one series can span layers, and the three-axis intake rule that keeps a new rule from being redundancy. -->

# Part 2: Diversity and intake

The layer model is only worth anything if the layers are *independently*
beaten. That is the integrity rule, and it constrains both the existing rules
and every new one.

## The independence rule

**Each layer's mechanism must be independent of its neighbors'.** An attacker
who evades the regex family (R, L3) defeats a pattern match; the refusal
family (X, L4) catches the construct they had to use to do it. Those are
different mechanisms, so defeating one does not defeat the other, and the
holes fail to align. If two layers shared a mechanism, one evasion would open
both, and the "layered" picture would be a drawing rather than a defence.

Two consequences follow, and both look like contradictions until the axis is
clear:

- **One series can span two layers.** X sits at L4, but X026/X027 - the
  refusal family - fire at L2, the readability boundary, because a construct
  the tokenizer cannot read is a boundary before it is a technique.
- **Two series can share a layer.** X and E both sit at L4: refusal-based
  versus statistical evasion detection. The difference *is* the point.
  Resolving cleanly but weirdly defeats X and is exactly what E measures.

The series axis is the diversity guarantee; the layer axis is the coverage
guarantee. Neither may imply the other.

## M owns no layer

The **M** series reasons about other findings, so it has no layer of its own:
it fires *at* the layer of its inputs and records which findings composed the
conclusion. A claims contradiction (M001) or a weak-signal span (M002) is a
claim about the profile, not about a step the attacker took, and forcing it
into a fixed layer would be a category error.

**P** (claims) and **W** (boundaries) are the same kind of thing: render
surfaces, not trajectory layers. P maps to L1 as *input* - the claims ledger
M reads - and W maps to L2 as *boundary reporting*. None of them is a step
the attacker passes.

## The intake rule

A proposed rule names three things, and the intake review checks all three:

1. **Mechanism (series).** What kind of thing detects it - regex, heuristic,
   invariant, refusal, statistics, history, correlation, indicator, meta.
2. **Subject (category).** The single closed category it belongs to, which
   owns its reference page.
3. **Trajectory hole (layer).** Which layer the attack it targets would
   otherwise pass.

If a mechanism on a **different** layer already covers the same attack, the
proposal must argue why the new one adds *diversity* rather than *redundancy*
- or file it as an instance of the existing mechanism instead. This is the
independence rule applied at the boundary of the rule set: a new rule that is
redundant with an existing layer is not a second line of defence, it is the
same line drawn twice. The rule is recorded in
[writing a rule](../contributing/writing-a-rule.md) and enforced by the
[enforcement map](enforcement.md).

## See Also

- [Part 1: The trajectory](trajectory.md)
- [Part 3: Reporting](reporting.md)
