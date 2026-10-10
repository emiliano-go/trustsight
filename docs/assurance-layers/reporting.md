<!-- description: The layers object: fired/passed/unreadable/not_exercised, the gap-to-layer blindness mapping, the deepest-layer verdict, and how the terminal and the JSON stay one surface. -->

# Part 3: Reporting

The layer model reaches the person two ways: the JSON `layers` object and the
`--verbose` terminal line. They carry the same projection, because a
guarantee on one surface and not the other is not a guarantee (B11).

## The `layers` object

Every JSON report carries `layers`: a dict keyed `L1`..`L8`, each entry
`{name, status, findings}`.

- **`fired`** - a finding caught at this layer. `findings` lists the rule
  ids that fired there, in the order the engine produced them.
- **`passed`** - the layer was fully exercised and nothing fired.
- **`unreadable`** - a coverage gap left the layer unexercised. This is
  reserved for the layers the missing evidence actually blinds.
- **`not_exercised`** - the layer could not run at all in this mode: `L8` is
  cross-package correlation and a single-package `review`/`inspect` cannot
  supply the collective input, so it reports `not_exercised` rather than a
  misleading `passed`.

## Blindness is gap-precise

A layer is `unreadable` only when the gap that fired can blind *that* layer.
The mapping is data, and it is deliberately conservative in the fail-safe
direction:

| Gap | Layers blinded |
|---|---|
| `diff_truncated`, `scan_truncated`, `partial_hunk`, `line_truncated`, `stage_degraded`, `ruleset_drifted` | every layer |
| `parent_baseline`, `history_truncated` | L6 only |
| `unresolved_source`, `unresolved_parse_time` | L1-L4 |
| `tree_not_analyzed`, `snapshot_refused`, `companion_truncated`, `binary_metadata`, `partial_file_analysis`, `noextract_suppressed` | L1, L3 |
| `unpinned_build_deps`, `deps_not_scanned` | L3, L6 |
| anything unrecognised | every layer (fail safe) |

A history walk cut short does not make L1 look unread; a content truncation
does not leave L6 claiming `passed`. An unrecognised gap blinds everything,
because claiming a layer passed on an unexplained shortfall is the dangerous
error.

## The verdict names the deepest layer

For a run with scored findings, the verdict sentence names the deepest layer
the evidence caught at - `Fired at L4 (Evasion shape).` - before the
mandatory review direction. A clean package's verdict is unchanged, and the
flat findings remain beneath the sentence. The deepest layer is the furthest
the attacker demonstrably reached; it is the answer to "how far in did this
get", which the flat list does not give.

## One surface

`inspect --verbose` prints a single line beside the panel: the layers whose
status is not `passed`, and the count of boundaries that forbid a clean
verdict. That is the same projection the JSON carries, rendered for a person.
The terminal is a surface, not a lesser view of one.

## The boundary, beside the layers

The layer profile is a projection of findings; the **boundary** list
(Addendum 2 W1) is the projection of what the run could not conclude - one
object per coverage gap and per W rendering, each with `forbids_clean`. It is
covered in [Part B of the security model](../security/what-a-result-claims.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete);
the point here is only that `unreadable` layers and `forbids_clean`
boundaries are two views of the same shortfall, and both travel to every
surface.

## See Also

- [Part 2: Diversity and intake](diversity.md)
- [Part 4: Enforcement](enforcement.md)
- [Report schema](../reference/report-schema.md) - the exact fields
