<!-- description: The immune-system ideas TrustSight borrows, what each one means in code, and the one idea it deliberately rejects: runtime gain control. -->

# Immune-Inspired Design

The immune system is not a metaphor pasted onto TrustSight; it is a set of
solutions to the same problem the tool has. An audit engine must decide what
to look at, remember what it has seen, raise its posture without accusing any
one package, and say when it is blind. These are the borrowings, and the one
inspiration that is rejected.

## Missing-self (NK cells)

The immune system does not wait for a foreign antigen. It kills cells that
stopped proving they are themselves. TrustSight's corpus says what packages
*already have*; the missing-self axis says what they *stopped having*.

- **T004 Vouch Surface Removed** - a partial `validpgpkeys` removal with no
  replacement.
- **T005 Scheme Downgrade** - the same source host falls from TLS while the
  URL path also changes, the shape H019's exact-match rule misses.
- **C033 Context Bleed** - a diff guts a large fraction of the recipe's
  comment prose.
- **C034 Metadata Inconsistency** - committed `.SRCINFO` and PKGBUILD
  disagree on the version fields.

T004 and T005 are the T-axis twin of G008: G008 watches *who arrived*;
T004/T005 watch *what disappeared when they did*.

## Danger over stranger (Matzinger)

The system responds to damage signals, not foreignness. The Contact Ledger
is already built on this: a first contact is recorded, not attacked. C033 and
C034 extend the same posture to the host's own tissue: the recipe's prose and
its generated metadata are damage signals about reviewability, not evidence
that a payload exists.

## Opsonization (complement)

Tag first, clear later. Weight-0 tag events - first contacts, campaign
context, entropy bumps, annotations, techniques - are not indecision. They
are the coating that makes later detection cheap. The report's `tag_panel`
is the one grouped surface for that coating, and `TAG_CONVERGENCE` is the
bounded escalation: N distinct kinds on one diff earns one INFO ledger entry,
never a score.

## Sickness behavior

Systemic infection changes the whole organism's posture. When G006/G007
declare a campaign perimeter, a standing boundary note on an in-perimeter
package (W009, another W finding, or a coverage gap) becomes visible as
`W013` until the campaign TTL expires. Fever is not a verdict about any one
cell, and W013 is not an accusation: it is context, weight 0, and
escalation-only. `campaign_hold` is the same posture in machine-readable
form; enforcement is outside the tool.

## Refractory period

A neuron that could re-fire every millisecond would convey nothing. One spike
per stimulus is what makes a signal informative. The emission layer enforces
one alert per `(rule, campaign-cell)` per window, and the refractory state is
part of the cycle's audit record. Debounce is not suppression; it is
semantics. Lateral inhibition is the rendering half: when N packages share
one campaign finding, the single alert names all members, sorted.

## Nociception

Pain is prioritization without a damage claim. A package with repeated
unresolved review verdicts earns a tender point in the report header: "N
unresolved in M months; a human should look once." It never says the package
is broken, and it never scores.

## Interoception

An organism that cannot feel its own state confuses blindness with safety.
The report's `self_state` block names cold/warm mode, observation counts,
ruleset versions, channel tags and observation-clock ages, federation and
contact availability, campaign state, and a sorted `blind` list. A blind run
must never masquerade as a clean one.

## Rejected: gain control

Gain control - continuously adapting a threshold to the recent signal - is
rejected as a runtime mechanism. It would make the same diff score
differently depending on where the epoch happened to sit, breaking B1
(fingerprint reproducibility) and cold-replay determinism. Thresholds are
re-derived at release time from the pinned corpus, committed to config, and
covered by the fingerprint. Gain control survives only as a release-process
note and as this documented rejected inspiration.

## Two-signal activation

A detection shape is not evidence that the shape is calibrated. A new rule
ships anergic: visible, weight 0, listed in the anergy ledger with the signal
it is waiting for. Promotion is explicit, measured, and changelogged. The
state is queryable with `trustsight admin anergic`.
