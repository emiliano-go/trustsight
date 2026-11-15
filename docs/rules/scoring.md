<!-- description: How rule severity becomes weight, how the additive score is computed, how FATAL behaves, and how review thresholds relate to the score. -->

# Rule Scoring

Rules contribute to the score through their severity weight. The arithmetic
is deliberately strict and additive: nothing lowers a score, and no rule
multiplies another. This page owns the scoring mechanics for rules; the wider
argument for the design is in
[Scoring and Verdicts](../explanation/scoring-and-verdicts.md).

## Score calculation

The final score is computed from four signal sources. Rules are the primary source (Tier A):

**Score formula:**

```text
base = sum(severity_weight for each fired rule)
base += source_bucket_modifiers (Tier B)
base += novelty_weights scaled by maturity (Tier C)
final = clamp(base, 0, 100)
```

A FATAL finding (R012, R013, or a confirmed H056) contributes weight 0 like any other finding: the numeric score stays the strict sum of weights, and the FATAL signal rides the verdict label and the unsuppressible entry in `score_breakdown`.

## Severity and weight

Each severity level carries a weight that reflects its information value: how often does this signal fire on benign packages versus malicious ones?

| Severity | Weight | Fire rate on benign corpus | Meaning |
|----------|--------|---------------------------|---------|
| FATAL | 0 | Never | Contributes no weight; names itself in the verdict label (`Low (FATAL: R012)`). Package is attempting to deceive the reviewer. |
| CRITICAL | 40 | Rare | Almost certainly malicious if triggered. curl pipe bash, sudo in functions. |
| HIGH | 25 | Low | Strong signal. Checksum manipulation, unexpected downloads. |
| MEDIUM | 15 | Moderate | Notable but not definitive. Install file changes. |
| LOW | 5 | High | Weak signal. Demoted from higher severity if corpus fire rate exceeds 30%. |
| INFO | 0 | Variable | Recorded for audit trail only. No score contribution. |

A CRITICAL rule on its own (weight 40) puts a package into the review queue under the default profile, whose threshold is 20. A single HIGH rule (weight 25) does the same, and so do two MEDIUM rules (15 + 15 = 30). The threshold is a *workload* choice rather than a property of the score: [`[review] profile`](../reference/configuration.md#review) moves it to 40 (`quiet`) or 10 (`strict`) without changing any weight, band or arithmetic, and the report carries the profile and its effective threshold beside the `flagged` decision so a reader can see which queue produced it.

## Severity weights

Configured in `config.toml` `[severity_weights]`:

| Severity | Weight |
|----------|--------|
| FATAL | 0 |
| CRITICAL | 40 |
| HIGH | 25 |
| MEDIUM | 15 |
| LOW | 5 |
| INFO | 0 |

## FATAL behaviour

R012 and R013 are shipped FATAL rules. H056 can also emit a FATAL finding when a current package fact matches an IOC whose confidence is `confirmed`; lower-confidence IOC matches use lower severities. A `pkgbuild_pattern` entry is the exception: it matches a regular-expression shape rather than an exact artefact, so it is capped at CRITICAL whatever its tier and can never reach FATAL. FATAL findings contribute **0 weight** to the running total: the numeric score remains the strict sum of finding weights, and the FATAL signal rides (a) the unsuppressible FATAL entry appended to `score_breakdown` - no override can remove it - and (b) the verdict label, where `_fatal_label()` in `src/trustsight/scoring.py` names the rule, e.g. `Low (FATAL: R012)` or, alongside weighted findings, `Medium (FATAL: R013)`. The shipped FATALs target the reviewer reading the report rather than the build machine, so a lone heuristic FATAL misfire no longer reads as a Critical package; a consumer triaging on score should also look for FATAL entries in `score_breakdown`. R012 and R013 are the shipped rules protected from configuration removal or downgrade; H056's severity is derived from the signed/local indicator confidence tier.

---

## Declared-practice findings (P001-P009)

The P namespace reports practices the recipe *declares*, not risks that were
found. The `P` prefix exists so a reader seeing `P0xx` in the output knows at
once that it is not a risk finding. Every one is INFO, weight 0, and checkable
by the reader against the file itself. Defined in `src/trustsight/scoring.py`;
rendered from `DECLARED_REASONS`.

| Id | Meaning |
|----|---------|
| `P001` | Checksums declared for all non-VCS sources (`sha256sums`) |
| `P002` | `validpgpkeys` declared |
| `P003` | A signature source accompanies a source, with PGP keys declared |
| `P005` | Source pinned to a full commit hash (`commit_pinned`) |
| `P006` | Source pinned to a tag - the weaker pin, which `H033` exists to flag because a tag can be repointed |
| `P007` | Source hosted on a trusted forge over HTTPS (`trusted_forge` bucket) |
| `P008` | Source tracks a branch or unpinned ref, so upstream decides at build time what this compiles and runs |
| `P009` | Recipe declares a prebuilt deliverable: a `-bin`/`-appimage`/`-wine` name or a prebuilt-artifact source. `M001` pairs it with `H066` (an undeclared committed ELF) |

`P004` is skipped, so the family has eight members rather than nine. Four of
them - `P002`, `P003`, `P005` and `P008` - render unprompted; the other four
render under `--verbose`. Stating every declared practice on every package
would bury the risk findings, which is the opposite of what the group is for,
so the default set is the ones a reader would find *surprising by their
absence* - plus `P008`, which is the one whose *presence* is the notable thing.
The set is `DECLARED_DEFAULT` in `src/trustsight/scoring.py`.

`P008` is the counterpart `P005`/`P006` never had. A recipe that pins says so;
one that tracks a branch produced no line at all, and "nothing" reads exactly
like "pinned" to anyone scanning the group. It is deliberately not a coverage
gap: the statement is true of every VCS package by design, and raising a gap
would put about a fifth of the original locked corpus into Inconclusive (653
of its 3,246 diffs, as measured then), which buys alert fatigue rather than
information. The band is
left alone and the reader is told what the recipe declares. The
rest render under `--verbose`. The P namespace contrasts with H033/H049/H059:
those fire when a practice is *changed*, these report when one is *present*.
No P finding can lower a score - B10.

## Review thresholds

The score is compared with a review threshold to decide whether a result is
flagged. The default threshold is 20; the `quiet` profile moves it to 40 and
`strict` to 10 without changing a weight, band or the arithmetic. The profile
and its effective threshold are reported beside the `flagged` decision. See
[the configuration reference](../reference/configuration.md#review).

Measured fire rates and the 30 percent gate are owned by
[Fire Rates](../reports/fire-rates.md).
