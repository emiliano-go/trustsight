<!-- description: Where the meta rules come from (the immune system's self-tolerance and corroboration) and what an M finding means. -->

# Meta and Confluence

Mechanics live on the [Meta category page](meta.md).

## Where it comes from

An immune system that attacks the body it lives in is an **autoimmune
disease**: the danger is not the pathogen but the response. The meta family is
TrustSight's self-tolerance. Every other rule is a claim about the *package*;
meta is a claim about the *run*: too many alerts for one window, a matcher
that fired suspiciously often, a campaign class re-arming again and again.
These are tool-health observations, and they exist so the analysis can admit
when it is not itself trustworthy. They never score against the package,
because a detector's own over-excitement is not evidence about the diff.

The name "confluence" is the other half, and it is the immune system at work
again. A single immune cell binding an antigen is not enough to launch a full
response; it needs **corroboration** from other cells before the alarm is
real. M003 reports exactly that: independent families agreeing on the same
package, a statement about agreement rather than about any one rule. Both
halves answer the same question - "how much should this run's own output be
trusted?".

## What a finding means

- An M finding is about TrustSight, not the package under review. It never
  scores against the package and is excluded from the package's risk band.
- `M001` (volume), `M002` (a noisy matcher), and `M004` to `M006`
  (cycle/campaign health) are alerts to the operator to retune or
  investigate filters.
- `M003` (confluence) is the exception that reads a package: several distinct
  families agreeing is a real signal, and it is scored as such.
- `M006` specifically flags a campaign re-armed too often: the state is still
  refreshed, but the churn is reported so a chronic campaign does not inflate
  the alert stream.

## See also

- [Kinds of Alerts](../explanation/detection-and-evidence.md); operator-facing
  versus package-facing findings
- [Alert Budget](../explanation/detection-and-evidence.md)
- [Meta category page](meta.md)
