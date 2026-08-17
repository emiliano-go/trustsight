---
description: How to integrate TrustSight into CI/CD pipelines.
---

# Using TrustSight in CI

The default terminal output is the findings list, not a score: the score exists
and is deterministic, but the tool leads with evidence. Automation therefore
runs on the JSON contract below, the only machine-readable surface, and the one
this guide uses throughout.

## Exit codes

| Code | Meaning |
|------|---------|
| **0** | The analysis completed. Says nothing about what was found. |
| **2** | The analysis could not run or could not complete. |
| **130** | The process was interrupted with `Ctrl+C`. |

**Do not gate on the exit code.** A flagged package still exits 0; see
[exit codes](../reference/exit-codes.md). Gate on the JSON, which is the
contract this guide uses throughout.

## The JSON contract

`trustsight review --json` writes a **list**, one object per package, to stdout.
Progress events go to stderr, so a pipeline only has to read stdout.

Every object carries the report fields below. The list can contain successful rows and rows with `failed: true`: a failed row is an explicit NOT VETTED result, not an omitted package.

| Field | Meaning |
|-------|---------|
| `package` | Package name. |
| `old_version`, `new_version` | Installed version and the version the AUR declares. |
| `findings` | Each with `rule_id`, `file`, `line`, `description`. |
| `verdict` | The rendered sentence. |
| `first_seen` | `true` when there is no prior history for this package. |
| `is_trivial` | `true` when only `pkgver` and checksums moved. |
| `coverage_gaps` | What the run could **not** examine. Always present. |
| `failed` | `true` when this package could not be vetted. Do not treat an empty `findings` list on such a row as clean. |
| `required_by` | Under [`--deps`](../reference/cli.md#trustsight-review), the packages that declare this one. Empty otherwise, and always present, so a gate never has to test for the key. |

`score`, `risk` and `risk_label` are added when `--score` or `--risk` is passed.
`risk` is the bare band; `risk_label` is the same band qualified when the run was
incomplete, for tools that display it to a person.

A minimal CI step:

```bash
trustsight review --score --json > report.json
python3 - <<'EOF'
import json, sys

reports = json.load(open("report.json"))
flagged = [r for r in reports if (r.get("score") or 0) > 20]
partial = [r for r in reports if r.get("coverage_gaps")]

for r in flagged:
    print(f"FLAGGED {r['package']}: {r['verdict']}")
for r in partial:
    print(f"NOT FULLY VETTED {r['package']}: {', '.join(r['coverage_gaps'])}")

sys.exit(1 if flagged or partial else 0)
EOF
```

**Treat `coverage_gaps` as blocking, not informational.** A non-empty list means
the score describes part of the change, not all of it. Two separate bypasses ride
on ignoring it:

- Pad a diff past the size cap, append the payload, and the visible score drops.
- Do the same but include one cheap deliberate HIGH in the visible prefix. The
  score does *not* drop, `risk` reads `"High"`, and a pipeline gating on `risk`
  alone sees a plausible verdict computed from a fraction of the change.

Gating on `risk` without `coverage_gaps` closes the first and leaves the second.
See [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

## Policy gating

Decouple the score from your pass/fail decision. TrustSight's verdict threshold
(20) is a sensible default but your team's tolerance may differ.

```bash
export THRESHOLD=40
trustsight review --score --json > report.json
python3 - <<'EOF'
import json, os, sys

threshold = int(os.environ.get("THRESHOLD", "20"))
reports = json.load(open("report.json"))
over = [r["package"] for r in reports if (r.get("score") or 0) > threshold]
if over:
    print("Packages above threshold:", ", ".join(over))
    sys.exit(1)
EOF
```

Raising the threshold does not raise the coverage bar: `coverage_gaps` is
independent of the score and should be checked whatever threshold you pick.

## Deeper output

`trustsight inspect <pkg> --json` exposes the full `PackageFact` for one package:
the whole score breakdown, bucket classifications, novelty context and evidence.
Field by field, it is documented in the
[report schema](../reference/report-schema.md).

## Per-class CI regression

For teams that want a statistical gate, TrustSight publishes benchmark distributions for each severity class on the [benchmarks page](../explanation/benchmarks-and-methodology.md):

| Class | Metric | Value |
|-------|--------|-------|
| CRITICAL | p5 (5th percentile) | **60** |
| Benign | p95 (95th percentile) | **35** |
| Zero-rate (benign scored 0) | percentage | **68.3%** |
| Test count | total | **2,599** |

**The gate:** if a CRITICAL-class package consistently scores at or above its p5 (60) and no benign package exceeds its p95 (35), the classifier achieves clean separation with no overlap.

To set up your own gate:

1. **Run a baseline** against your package set after initial configuration. See the [re-baselining guide](../contributing/re-baselining.md).
2. **Choose a threshold**: typically 30-40, depending on your tolerance for benign novelty signals.
3. **Add a CI check** that compares regression scores against the baseline. Any package whose score moves from UNFLAGGED to FLAGGED without a corresponding PKGBUILD change is a regression.

The CRITICAL recall of **100%** means every labelled malice sample in the corpus fires the rules it is labelled for. A gate at 40 catches all known CRITICAL patterns and passes benign bumps that score below the 95th percentile.

## Nightly vs per-commit

- **Per-commit**: run `trustsight review` on every PR that touches a PKGBUILD or a `rules.toml` change. Gate on the JSON, as above.
- **Nightly**: run a full review of all installed AUR packages and diff the output against the previous night. Detects drift over time.

## Config in CI

Check in your `config.toml`, `rules.toml`, and the TrustSight database alongside your code. The `trustsight review` command respects the local config tree automatically.

See also:
- [Configuring rules and weights](configuring-rules-and-weights.md)
- [Exit codes reference](../reference/exit-codes.md)
- [The security model](../security.md), for what a verdict does and does not claim
