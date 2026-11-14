<!-- description: The layers object in the report: detection and coverage per category, the statuses, and a worked JSON example. -->

# Part 3: Reporting

This page answers: what does the `layers` object in a report actually say?

The report groups findings by evidence category and, for each category, records
two independent facts: whether anything was **detected**, and how far the
category could be **assessed**. Detection, coverage and boundary are defined
once in the [glossary](../reference/glossary.md).

## Detection and coverage

- **Detection** is `fired` when a finding in that category was produced, and
  `none` otherwise.
- **Coverage** is `complete` when the category was fully exercised,
  `incomplete` when a coverage gap (a truncated diff, an unresolvable value, a
  partial file) blinded it, and `not_applicable` when the analysis mode cannot
  exercise it at all (L8 cross-package correlation in a single-package
  review).

They are kept separate because a finding must not hide that the same category
was also unread, and an unread category must not hide a finding.

## Reading the statuses

| Category | Detection | Coverage | Meaning |
|---|---|---|---|
| L3 Payload signature | fired | complete | A rule such as `R001` matched a changed command shaped like `curl ... \| bash`. Positive evidence of a known pattern. |
| L3 Payload signature | none | complete | The input was fully available, no rule in this category matched. **Not** a safety certificate. |
| L1-L4 | any | incomplete | A `source=` value is computed dynamically or the diff was truncated, so the category was not fully assessed. |
| L8 Campaign correlation | none | not_applicable | A single-package review has no cross-package input; the check did not run. |

`L8` is `not_applicable` only in a single-package review. In a corpus
correlation cycle (`full-aur`), where the collective G-series pass runs, the
layer is marked exercised and reports `complete`; an `L8` finding in a report
also proves the pass ran.

For one release the object also carries a derived `status`
(`fired`/`passed`/`unreadable`/`not_exercised`) that collapses the two
dimensions for back-compat consumers; new consumers should read `detection`
and `coverage`.

## A worked JSON example

A single-package review of a diff that was read in full, whose `source=` value
was resolved, and which fired `R001` would carry the complete profile below.
This one is the *truncated* variant: the diff was cut short, so every category
that depends on reading the changed text is `incomplete` (`L8` is not applicable
to one package). Detection and coverage move independently, which is the point
of the shape.

```json
"layers": {
  "L1": {"name": "Structural coherence", "detection": "none",  "coverage": "incomplete",     "status": "unreadable",    "findings": []},
  "L2": {"name": "Readability",          "detection": "none",  "coverage": "incomplete",     "status": "unreadable",    "findings": []},
  "L3": {"name": "Payload signature",    "detection": "fired", "coverage": "incomplete",     "status": "fired",         "findings": ["R001"]},
  "L4": {"name": "Evasion shape",        "detection": "none",  "coverage": "incomplete",     "status": "unreadable",    "findings": []},
  "L5": {"name": "Behavioral suspicion", "detection": "none",  "coverage": "incomplete",     "status": "unreadable",    "findings": []},
  "L6": {"name": "Ecosystem memory",     "detection": "none",  "coverage": "incomplete",     "status": "unreadable",    "findings": []},
  "L7": {"name": "Known indicators",     "detection": "none",  "coverage": "incomplete",     "status": "unreadable",    "findings": []},
  "L8": {"name": "Campaign correlation", "detection": "none",  "coverage": "not_applicable", "status": "not_exercised", "findings": []}
}
```

Read it as: a payload-signature check fired (that evidence is real), and at the
same time every text-reading category is `incomplete`, so its silence is not
evidence. The same run with the whole diff present would show `coverage:
"complete"` on every row but `L8`, and `status: "passed"` wherever detection is
`none`.

The same profile as a follow-along list, in category order:

```
L1  Structural coherence     unreadable    (detection none)
L2  Readability              unreadable    (detection none)
L3  Payload signature        fired         (detection fired: R001)
L4  Evasion shape            unreadable    (detection none)
L5  Behavioral suspicion     unreadable    (detection none)
L6  Ecosystem memory         unreadable    (detection none)
L7  Known indicators         unreadable    (detection none)
L8  Campaign correlation     not_exercised (detection none)
```

## The verdict sentence

When findings score, the verdict names the **fired evidence categories**:

```
Evidence categories fired: L3 (Payload signature). Review the diff before building.
```

This answers "which kinds of evidence produced findings". It does not claim a
sequence - a category's label is where the finding was produced, not a stage
an attacker reached.

## The terminal

`inspect --verbose` prints a single line beside the panel listing the
categories whose status is not `passed` and the count of boundaries that
forbid a clean verdict - the same projection the JSON carries. For the profile
above:

```
  Layers: L1 unreadable, L2 unreadable, L3 fired, L4 unreadable, L5 unreadable, L6 unreadable, L7 unreadable, L8 not_exercised; 1 boundary(ies) forbid a clean verdict
```

Every non-`passed` category is named, so the terminal never shows less than the
JSON. The boundary count moves with the run; only the shape is fixed.

## The optional L9 lane

The eight static categories are always present. The optional **L9 build lane**
is reported beside them, not inside them:

- `l9_unavailable` - the lane is disabled, no build manifest was supplied, or
  the sandbox is unavailable. A weight-0 boundary, never "clean".
- `l9_divergence` - the artifact findings and the static analysis disagree.
  Both profiles are rendered in full; neither overrides the other.

L9 findings (`A001`-`A008`) carry no `L1`-`L8` layer and never change the
static score; they are evidence from outside the static analysis.

## The boundary, beside the layers

The layer profile projects findings; the **boundary** list projects what the
run could *not* conclude - one object per coverage gap and per W rendering,
each with `forbids_clean` (see
[the security model](../security/what-a-result-claims.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)).
`incomplete` coverage and a `forbids_clean` boundary are two views of the same
shortfall, and both travel to every surface.

## See Also

- [Part 2: How to add a useful new detector](diversity.md)
- [Part 4: Tests and adversarial evaluation](enforcement.md)
- [Report schema](../reference/report-schema.md) - the exact fields
