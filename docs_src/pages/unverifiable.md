<!-- description: W-series findings report what the analysis could not check, at weight 0 and always shown. A claim about the analysis, not about the recipe. -->

# Unverifiable


W rules report **what the analysis could not check**.

Every other rule says "this recipe does something". A W finding says "this
analysis could not verify something", attached to the line it applies to. It
is the same statement as a [coverage gap](../reference/report-schema.md), moved from
the run to the line.

This is a reference page. For how weight and scope work, see
[Rule Mechanics](mechanics.md).

## Reading a W finding

- It never changes the score, the risk band, or the flagged decision.
- It is always shown, unlike other weight-0 findings, because a statement
  whose only value is to a reader is worthless if filtered.
- It is not evidence of wrongdoing and must not be reported as such.

## Why W rules carry no weight

The behaviour they describe is what packaging is. A recipe that unpacks a
declared, checksummed archive and runs something from inside it is following
the format. The checksum proves the bytes arrived unaltered; it says nothing
about what they do.

Pricing that would put a finding on a large share of the ecosystem and make
the number mean less, which is what [B10](../security-design/security-model.md) prevents: a gap
must not add points. Silence is the other option, and silence is what the
boundary documentation had to describe as something TrustSight cannot see.

A W finding tells a reader something specific: *this* line runs *that* file,
and nobody - not the checksum, not this tool - has read it.

## Where the scored counterpart lives

Some W surfaces have a subset narrow enough to score. Those are separate
rules, because a W is weight-0 by construction:

| W rule | Scored counterpart |
|---|---|
| [W001](#w001) executes unread code | [H094](fetch-and-execution.md#h094), the same act during `package()` |
| [W004](#w004) unread manifest | [X020](crossfire.md#x020), the recipe writing one |
| [W006](#w006) unread generated config | [X022](crossfire.md#x022), the same config handed to a tool |

---
