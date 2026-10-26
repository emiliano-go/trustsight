<!-- description: M-series rules reason about other findings: a declared practice contradicted by structure, or a composition of weak signals across layers. -->

# Meta and Confluence

Where these rules come from and what a finding means: [Rule Nature](../nature/meta.md).

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
- M001 scores (HIGH); M002 and M003 are weight-0 but **escalate the band one
  step** (never add points), gated on the benign-corpus cap
  `M escalation stays below the benign cap`.
- It fires at the layer of its inputs, so it has no static layer.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [M001](#m001) | Claim Contradicted By Structure | HIGH |
| [M002](#m002) | Weak Signal Across Layers | MEDIUM |
| [M003](#m003) | Composition Not Owned Elsewhere | MEDIUM |
| [M004](#m004) | Expected Co-fire Absent | INFO |
| [M005](#m005) | Licensor Absent On Licensed Shape | INFO |
| [M006](#m006) | Campaign Re-armed Too Often | INFO |
<!-- /generated: page-index -->

### M001: Claim Contradicted By Structure {#m001}

- **Target:** programmatic (finding set)
- **Severity:** HIGH (weight 25)
- **Category:** `meta`

- **Condition:** The recipe's declared practice contradicts a structural finding in the same run.

It joins the *real* claims ledger - the P-series ids the run's declared facts imply (`trustsight.scoring.declared_claims`) - against the structural findings: checksums declared (P001) while H091 reports the arrays do not cover every source, GPG verification declared (P002) while H024 reports it removed, a source pinned (P005) while H101 reports the pinning lost, a trusted forge declared (P007) while H099 reports the host swapped, a prebuilt deliverable declared (P009) while H066 reports an ELF committed to the repository outside `source=()`.

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

- **Target:** programmatic (finding set)
- **Severity:** MEDIUM, weight 0 (annotation)
- **Category:** `meta`

- **Condition:** Three or more distinct assurance layers fired, none above the alert bar (`[thresholds] m002.min_layers`, default 3).

An attacker who spreads weak signals across layers stays under
any single threshold; the span is only visible from the whole profile. It
adds no points but raises the reported band one step: a spread across layers
is exactly the case a single-signal threshold cannot see. Measured on the
locked benign corpus: 112 on the v1 corpus (3.0%).

### M003: Composition Not Owned Elsewhere {#m003}

- **Target:** programmatic (finding set)
- **Severity:** MEDIUM, weight 0 (annotation)
- **Category:** `meta`

- **Condition:** Two or more distinct capability families co-occur while none of the cluster owners (H027, H098, X007) recorded the composition - typically because the owner is disabled.

The composition is never lost. It adds no points but raises the reported band
one step. Measured on the locked benign corpus: 316 on the v1 corpus (8.5%).

Standing gate: the escalation passes the benign-corpus cap (`M escalation
stays below the benign cap`, `MAX_BENIGN_FIRE_RATE`) before it ships, the
cluster-rate gate the M constitution requires.

### M004: Expected Co-fire Absent {#m004}

- **Target:** programmatic (tool health)
- **Severity:** INFO, weight 0
- **Category:** `meta`

A construct that historically co-fires with another rule appeared without
it. A hit means the **tool**, not the package, needs attention, so this is
never added to a package's finding list: it rides the report's
`cofire_health` channel for the harness and calibration.

### M005: Licensor Absent On Licensed Shape {#m005}

- **Target:** programmatic (tool health)
- **Severity:** INFO, weight 0
- **Category:** `meta`

A rule declaring `escalates_when` fired while none of its declared licensors
did - the detector travelled without its usual company. Like M004 this is a
sensor-health observation, not evidence about the package, so it goes to the
`cofire_health` channel and never scores. See
[Escalation Licensing](../../explanation/escalation-licensing.md).

### M006: Campaign Re-armed Too Often {#m006}

- **Target:** programmatic (tool health)
- **Severity:** INFO, weight 0
- **Category:** `meta`

A campaign re-armed faster than
`[alerts] campaign_min_reactivation_observations` allows. The window is still
refreshed - re-activation is never blocked - but a campaign that re-primes over
and over is the **instrument** churning, not a package misbehaving, so it is
surfaced as a tool-health note rather than passed over in silence. Unlike M004
and M005 it is a cycle-level observation: it is raised in the correlation
cycle's log, not attached to any package's `cofire_health`, and it never
scores. See [Campaign Alert Mode](../../explanation/campaign-alert-mode.md).
