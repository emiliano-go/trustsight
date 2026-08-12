# Crossfire

**Nothing here is implemented.** No `X`-series rule exists in the shipped
ruleset, none is emitted by any code path, and `RuleCategory.CROSSFIRE` is
the one member whose `implemented` property is false. This page exists so
the category has a definition and the identifier range has an owner, not
because there is behaviour to document.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

## What a crossfire rule would claim {#definition}

Every rule TrustSight ships compares a package against one of three things:
itself before the diff (the C-series, the Class B and Class C rules), a
pattern (the R-series), or the corpus in aggregate (the Class D rules).

A crossfire rule would compare **two packages against each other**. Not
against the corpus mean, which is what [corpus
behavioral](corpus-behavioral.md) already does, but pairwise: two packages
that changed in the same cycle, sharing evidence neither one's own history
would make remarkable.

The distinction matters because the corpus rules are cluster-shaped by
construction. R100 fires when at least three otherwise unrelated packages
share a source repository; R092 fires when one maintainer submits ten
packages in a week. Both need a *quorum*. A pair does not reach one, and a
coordinated campaign starts as a pair.

## Why the range is reserved and empty {#reserved}

`X001` to `X008` are held for this category. No individual identifier is
assigned, and none should be until the detection it names has been
specified and measured, for the same reason
[R015 and R026-R038](system.md#not-rules) are held apart: an id that
appears in a release is an id that appears in user baselines and
`overrides.json` entries, and reassigning it later silently changes what a
stored suppression means.

Two gates apply before anything lands here, both of which the existing
Class D rules already have to pass:

- **`fire_rate(no_baseline) == 0`.** A pairwise rule with no prior snapshot
  has every package looking novel against every other, which is the
  cold-start failure [R071 is gated
  against](../../explanation/cold-start-and-maturity.md#maturity-gate).
- **Under 0.30 on the benign corpus**, enforced by
  `scripts/calibration_gates.py` on every push. Pairwise comparison over
  3,246 diffs generates a large candidate space, and a rule that fires on a
  measurable share of it is a census on active maintainers rather than a
  detection.

## What to read instead {#see-also}

Until this category has rules, the nearest shipped signals are:

| Question | Rule |
|----------|------|
| Do unrelated packages share a source repository? | [R100](count-based.md#r100) |
| Did one maintainer submit many packages at once? | [R092](count-based.md#r092) |
| Did one maintainer modify many packages at once? | [R105](count-based.md#r105) |
| Was a package adopted and then immediately changed? | [R126](maintainer-and-metadata.md#r126) |
| Did several kill-chain stages co-occur on one package? | [R089](composition.md#r089) |

The limit these share is described in
[what TrustSight cannot see](../../explanation/what-trustsight-cannot-see.md):
each needs either a quorum or a prior observation, so the first package of
a campaign is the one they are least able to speak about.
