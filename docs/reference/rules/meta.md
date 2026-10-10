<!-- description: M-series rules reason about other findings: a declared practice contradicted by structure, or a composition of weak signals across layers. -->

# Meta and Confluence

M rules take **other rules' findings** as their input. Every other series
reads the recipe; this one reads the finding set.

An M finding never lowers a score and never duplicates a line: its input is
the finding multiset *after* the ownership resolver, so two rules that
matched the same line have already collapsed to one owner by the time M
runs. Its value is the relationship - a practice the recipe claims and a
finding that contradicts it, or several weak signals whose combination is
the story.

This is a reference page. For how weight and scope work, see
[Rule System](system.md).

## Reading an M finding

- It reads the profile, not the diff: the evidence names the findings that
  composed, and the recipe text they came from.
- M001 scores (HIGH); M002 and M003 are weight-0 annotations in v1, because
  the escalation they describe is gated on a corpus measurement before it
  ships.
- It fires at the layer of its inputs, so it has no static layer.

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [M001](#m001) | Claim Contradicted By Structure | HIGH |
| [M002](#m002) | Weak Signal Across Layers | MEDIUM |
| [M003](#m003) | Composition Not Owned Elsewhere | MEDIUM |
<!-- /generated: page-index -->

### M001: Claim Contradicted By Structure {#m001}

**HIGH** (weight 25) · category `meta`

Fires when the recipe's declared practice contradicts a structural finding
in the same run. It joins the *real* claims ledger - the P-series ids the
run's declared facts imply (`trustsight.scoring.declared_claims`) - against
the structural findings: checksums declared (P001) while H091 reports the
arrays do not cover every source, GPG verification declared (P002) while H024
reports it removed, a source pinned (P005) while H101 reports the pinning
lost, a trusted forge declared (P007) while H099 reports the host swapped.

Only M can see this. The declared-practice ledger is weight 0 and the
structural finding is its own claim; "the recipe says one thing and
structurally does another" is a relationship between two findings that no
single rule reads.

A fourth M family is a **tool-health check, never a package finding**:
`cofire_absence` reports when a construct that historically co-fires with a
rule appears without that rule - a sign the rule broke or was evaded in a
known shape. It is consumed by the harness/calibration, not the report,
because a hit is about the tool, not the package.

### M002: Weak Signal Across Layers {#m002}

**MEDIUM, weight 0** (annotation) · category `meta`

Fires when three or more distinct assurance layers fired, none above the
alert bar. An attacker who spreads weak signals across layers stays under
any single threshold; the span is only visible from the whole profile.

Tunable: `[thresholds] m002.min_layers` (default 3). The one-band
escalation the design describes ships only after the cluster-rate gate is
measured on the corpus, so v1 reports the span at weight 0.

### M003: Composition Not Owned Elsewhere {#m003}

**MEDIUM, weight 0** (annotation) · category `meta`

Fires when two or more distinct capability families co-occur while none of
the cluster owners (H027, H098, X007) recorded the composition - typically
because the owner is disabled. The composition is never lost.

Standing gate: any future scored cluster must have a benign-corpus fire
rate at or below its lowest member rule's rate.
