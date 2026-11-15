<!-- description: Where the indicator rules come from (signed, dated observables) and what a finding means. -->

# Indicators

Mechanics live on the [Indicators category page](indicator.md).

## Where it comes from

An indicator is a **wanted poster**. It does not reason about behaviour; it
is a specific, named observable - a face, a plate number, a fingerprint - that
someone with authority has put on a list. The indicator family matches those
specific observables rather than shapes: a known-bad host, a known campaign's
literal, a specific metadata endpoint. These are the atomic facts that the
collective correlation rules (G-series) aggregate, and the ones a maintainer
can override when a stated use is legitimate.

A wanted poster needs a signature and a date for the same reason. Indicators
age: a host that was malicious last year may be a recycled CDN today, so
indicator findings carry provenance and date, and the override-tolerance logic
exists to let a known-good explanation suppress one without suppressing the
class.

## What a finding means

- The finding is a concrete match, with the matched observable and its
  provenance (which corpus or campaign it came from).
- An indicator match is strong evidence of the *specific* past activity; it
  is not proof the current diff is malicious, because observables are reused.
- An indicator suppression must be terminal-visible: when a reviewer
  overrides one, the report still shows what was suppressed and why, so a
  stale override cannot hide a re-appearance.

## See also

- [Override Tolerance](../explanation/scoring-and-verdicts.md)
- [Indicators category page](indicator.md)
