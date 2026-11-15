<!-- description: Indicator rules: a declared surface matches signed external data - the shipped IOC list or a federated publisher's set. Outside the heuristic score, alerted at maximum priority. -->

# Indicators

## Overview


An indicator rule asks one question: does a declared surface match an entry in
**signed external data**? The mechanism is membership, not a heuristic - the
answer is exact equality against a list TrustSight did not invent. H056 reads
the shipped `iocs.toml` and any locally imported baseline; the IOC federation
stage reads a publisher's signed indicator set. They are the same mechanism, so
H056 is filed here and keeps its id; new federation matches will take `I` ids.

Indicator matches are **outside the heuristic score** and never add points. A
`confirmed` match is FATAL; the rest map to a severity by the indicator's
confidence tier. See [IOC Federation](../reference/ioc.md) for the transport and the
update cadence.

See [Rule Mechanics](mechanics.md) for the field table, the severity
weights and the reserved identifier ranges.

---

## Threat context

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

## Detection mechanisms

The rules that make up this category are listed below, each with the series that implements it and the severity it carries. Scoring, matching and identifier allocation are shared across every category: see [Rule Mechanics](mechanics.md).

## Individual rules

<!-- generated: page-index -->
| Rule | Name | Severity |
|---|---|---|
| [H056](#h056) | Known Indicator of Compromise | FATAL |
<!-- /generated: page-index -->

### H056: Known Indicator of Compromise {#h056}

- **Severity:** tiered by the indicator's confidence: `confirmed` is FATAL, `high` is CRITICAL, `medium` is HIGH, an untiered entry is MEDIUM. A `pkgbuild_pattern` entry is capped at CRITICAL whatever its tier, because a regex names a shape rather than an exact artefact.
- **Category:** `ioc`

- **Condition:** A declared surface exactly matches an entry in `iocs.toml`, or an added line matches a `pkgbuild_pattern` entry.

Five surfaces are read: the package's own name; names added to
`depends`/`makedepends`/`optdepends`/`checkdepends`/`provides`/`replaces`/
`conflicts`; the host of any URL and any bare host token; any hex digest of
digest length; and a file the diff added or modified, or the recipe names via
`install=` or a local `source=()` entry. A `pkgbuild_pattern` entry is matched
as a regular expression against added lines; an invalid or
catastrophic-backtracking pattern is refused at load rather than run.
The IOC federation stage is separate and reports attributed matches through
`PackageFact.ioc_matches`; see [IOC Federation](../reference/ioc.md).

Matching is **exact**. Normalisation is limited to what is not part of the
identity: case, a trailing root dot, IDNA spelling, surrounding quotes. A host
is never stripped of a subdomain and a name is never stemmed, because that would
turn equality into resemblance. A malformed entry is dropped with a warning
rather than coerced.

**The shipped list is empty.** TrustSight does not invent indicators, so a fresh
install cannot fire H056 at all, and a miss is uninformative. `trustsight corpus
pivot <indicator>` inverts the rule: given one indicator, it lists every corpus
package referencing it, reading only stored material and never the network.

A `confirmed` indicator cannot be suppressed through `overrides.json`.

## Interpretation

- The finding is a concrete match, with the matched observable and its
  provenance (which corpus or campaign it came from).
- An indicator match is strong evidence of the *specific* past activity; it
  is not proof the current diff is malicious, because observables are reused.
- An indicator suppression must be terminal-visible: when a reviewer
  overrides one, the report still shows what was suppressed and why, so a
  stale override cannot hide a re-appearance.

## Related documentation

- [Override Tolerance](../explanation/scoring-and-verdicts.md)
