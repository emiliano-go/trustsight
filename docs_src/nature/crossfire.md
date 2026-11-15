<!-- description: Where the crossfire rules come from (military interlocking fire against evasion) and what a finding means. -->

# Crossfire

Mechanics live on the [Crossfire category page](crossfire.md).

## Where it comes from

The name is taken from **military crossfire**: two guns sited so that their
fields of fire overlap on the same ground. A defender who slips past the first
gun walks straight into the second, because there is no seam between them to
thread. The crossfire is what closes the gap a single gun leaves.

Crossfire rules are TrustSight's second gun. The payload rules (R, H, C, S)
are the first: they fire when a command *resolves* to something recognisable -
a fetch, an execution, a write. An attacker dodges that gun by defeating the
tokenizer, writing a command the analyser cannot reduce to a literal, so the
payload rules see nothing and stay silent. Crossfire is trained on exactly
that ground. It fires on *how* a thing was written rather than on what it
does, so the same evasion that silences the payload rules trips the crossfire
rules instead. Dodging one gun is walking into the other.

This is why a single diff can legitimately produce findings from both
families, scored independently: the payload rule catches what resolved, and
the crossfire rule catches the attempt to keep it from resolving. Evasion and
alarm become the same event, instead of evasion and silence.

The family is a function of refusal, so any tokenizer improvement that
resolves more constructs shrinks its detection surface. That is the intended
way it shrinks - measured per release and recorded, with a changelog
adjudication whenever a technique leaves the family's view.

## What a finding means

- The finding names the evasion technique, not the payload it hid. Read it as
  "this was written so the analyser could not see it", which is evidence on
  its own, whatever was hidden.
- Crossfire pairs with the payload families: crossfire names *how* the thing
  was hidden, a payload rule names *what* it does. Read them together.
- The finding assumes the technique itself is the signal, which is exactly
  why the sandboxed tokenizer exists; where the tokenizer could not read, the
  refusal is what fires.

## See also

- [Sandboxing the Tokenizer](../explanation/static-analysis-and-resolution.md)
- [Crossfire category page](crossfire.md)
