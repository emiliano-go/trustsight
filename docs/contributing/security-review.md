---
description: How to review a security control in TrustSight, and the failure mode that keeps recurring.
---

# Reviewing a Security Control

Every invariant in [the security model](../security.md) has a gate. This page is
about the mistake that lets a gate pass while the invariant is broken, because
it has now happened four times in this codebase and it will happen again.

## The failure mode

**A control applied at one of several equivalent call sites, with the check
pointed at a covered one.**

The control is real. The gate is real. The gate passes. And the invariant is
false, because the code has more than one way in and the check only knows about
one of them.

It is the same shape as the thing [B2](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)
exists to prevent, one level up: content skipped without a gap recorded, versus
an entry point missed without the gate noticing. In both cases nothing fails,
and the absence of a failure reads as a guarantee.

### The four times it happened here

| Invariant | Control | Entry point that was missed |
|-----------|---------|------------------------------|
| A5, matching is bounded | 8 KiB per-line clamp | applied in `apply_rules` (about 30 patterns from `rules.toml`), not to the roughly 88 patterns emitted from `analysis/`, which match the diff text directly. The gate measured `apply_rules`: 0.17s for a 5 MiB line. The real path took 15.06s. |
| A10, output is inert | `clean()` and `safe_markup()` | applied in `review`'s renderer, and the gate exercised that renderer. `_inspect_rich` interpolated a rule id raw and leaked escape sequences. |
| A12/A13, seed and baseline containment | reserved-name guard | enforced in `upsert_package`; `save_package_profile` and `save_pkgbuild_snapshot` are keyed by `package_name` directly and had no guard, and both are on the baseline import path. |
| B2, coverage accounting | `coverage_gaps` on the result | set by four of the five `PackageFact` producers. The first-analysis path declared `tree_analyzed=True` having read no tree at all. |

None of these were subtle once someone looked. All four passed CI.

## The rule

> **For each invariant, enumerate every entry point, then confirm the gate
> exercises the one an attacker reaches, not the one that is convenient to
> call from a test.**

"Convenient to call" is the tell. `apply_rules` takes a list of strings;
`scan_diff` needs a diff. `_render_results_rich` takes a dict; `_inspect_rich`
needs a whole `PackageFact`. The easy call is usually the narrow one, and the
narrow one is usually not the one under attack.

## How to do the enumeration

Do it from the source, not from memory, and prefer a check that enumerates over
a check that samples.

1. **Name the property as a sentence about the program**, not about a function.
   "Rule matching is bounded" not "`apply_rules` is bounded". The sentence tells
   you what to enumerate.
2. **Find every site.** `grep` for the call, the constructor, the table write.
   Do not trust the module layout: `analysis/` looked like it went through
   `rules.py` and did not.
3. **Ask what an operator would actually run.** If the property is about what
   reaches a terminal, the list is every renderer, including the plain-text
   fallbacks and the ones only reachable with `--json` off.
4. **Prefer a structural gate to a behavioural one** when the property is
   "every X does Y". Walking the AST for every `PackageFact(...)` construction
   catches the sixth producer someone adds next year; calling the four you know
   about does not.
5. **When only a behavioural gate is possible, loop over the sites** rather
   than picking one. `terminal output is inert` renders through four paths and
   names them in its output, so the gate's own result says what it covered.
6. **If a path cannot be called without a CLI invocation, extract it.** A
   renderer that cannot be exercised cannot be gated, and an uncoverable path
   is where the unsanitised value will be. `cli/corpus._render_pivot` was split
   out of its command for exactly this reason.

## Which gates enumerate, and which sample

Worth knowing when you are relying on one:

**Structural, enumerate the whole source:** `no interpreter or shell execution`,
`network confined to the fetch modules`, `one network host, declared`,
`every request has a timeout`, `archives are never extracted to disk`,
`SQL is parameterised`, `declared source URLs are never fetched`,
`every result declares its coverage`, `a baseline supplies state, not rules`,
`doc cross-references resolve`.

**Behavioural, loop over every known site:** `terminal output is inert` (four
renderers), `reserved names are refused by every writer` (three writers),
`FATAL rules cannot be switched off` (every shipped FATAL rule).

**Behavioural, single path, because the property is about one function:**
`expansion is bounded and never indirect`, `incomplete coverage fails closed`,
`a coverage gap is always shown with the band`, `version arguments are
shape-checked`, `the maturity numbers are derived, not copied`.

`rule matching is bounded on hostile input` deliberately measures `scan_diff`
end to end rather than any single matcher, because that is the only place both
rule engines are reached.

## When you add an invariant

1. Write the sentence in [the security model](../security.md).
2. Enumerate the entry points before writing the gate.
3. Write the gate against the widest one, or structurally over all of them.
4. Add the row to the [enforcement map](../security.md#part-c-the-enforcement-map).
   The `docs/security.md matches the gates` gate fails otherwise, which is the
   point: a guarantee with no check and a check with no guarantee are both bugs.

## When you add a rule

Detection rules are calibration, not security invariants, and go through
[writing a rule](writing-a-rule.md) and the
[calibration gates](../explanation/fire-rates.md) instead. The one security
question a rule raises is the A5 one: if it compiles a pattern, it must match
against text that has been through `rules.clamp_text`, which every current
call site does. A rule that reads a file, opens a socket, or spawns a process
is not a rule, and `no interpreter or shell execution` plus
`network confined to the fetch modules` will say so.
