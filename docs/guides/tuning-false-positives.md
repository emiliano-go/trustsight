---
description: How to identify and fix rules that fire too often on your package set.
---

# Tuning False Positives

No rule is perfect. Some may fire on patterns that are normal for your package set but would be suspicious elsewhere. This guide explains how to identify over-firing rules and what to do about them.

## Step 1: Check fire rates

Run a full review and check how often each rule fires:

```bash
trustsight review --verbose
```

For each rule, note the **fire rate**: the percentage of packages where it triggered.

> **The >30% heuristic:** A rule firing on more than 30% of your packages is not detecting anomalies; it is describing a property of your package set. That rule is now a **census**, not a signal.

## Step 2: Understand why

Inspect a few packages where the rule fired:

```bash
trustsight inspect <package>
```

Look for patterns:

- **R009/R010/R011** (command-structure rules): these now fire only in `function_body` context. If they are still over-firing, the package may use unconventional but legitimate helper functions.
- **R004** (checksum removal): some AUR packages legitimately skip checksums for binary blobs.
- **R005** (new source URL): a vendor may have changed their CDN, causing every package from that vendor to fire.

### Scope constraints already applied

Rules R009, R010, and R011 were scoped to `function_body` context in a previous release specifically to reduce false positives on top-level variable assignments and sourced library files. If they still over-fire, your further options are:

1. Demote the severity to INFO.
2. Disable the rule entirely (not recommended; you lose signal).
3. Add the false-positive pattern to a local allow-list.

## Step 3: Fix : demote, disable, or constrain

**Demote severity** (preferred):

```toml
# rules.toml
[rules.R004]
enabled = true
severity = "LOW"   # was HIGH; still fires, but contributes less score
```

**Disable the rule:**

```toml
[rules.R009]
enabled = false
```

Only disable a rule if you are certain the pattern it detects is never malicious in your context. Revisit this decision periodically; the threat landscape changes.

**Constrain scope** (where supported):

```toml
[rules.R010]
enabled = true
scope = "function_body"  # already the default
```

## Step 4: Re-baseline

After any change, re-run against your corpus:

```bash
trustsight review
```

Score changes: the demoted/disabled rule contributes less. Verify that the packages that were false positives now score where you expect them. See [configuring rules and weights](configuring-rules-and-weights.md) and the [re-baselining guide](../contributing/re-baselining.md).

## Step 5: Validate with benchmarks

TrustSight includes 267 tests with a zero-rate of **81.5%** (benign packages scoring 0). After tuning, re-run:

```bash
pytest tests/
```

Ensure CRITICAL recall stays at **100%**: every known malicious pattern must still fire. The corpus benchmarks in the [explanation section](../explanation/benchmarks-and-methodology.md) define the expected p5/p95 separations:

| Metric | Value |
|--------|-------|
| CRITICAL recall | 100% |
| CRITICAL p5 | 40 |
| Benign p95 | 20 |

If demoting a rule drops CRITICAL recall below 100%, you have gone too far. Restore the rule and find another approach.

## When not to tune

- **First-seen novelty scores** (5–15) are not false positives. They are honest uncertainty that resolves as the maturity gate accumulates observations.
- **C-series rules** (C001–C003) are structural invariants. They cannot be disabled through config. If they fire, they are detecting a real property of the PKGBUILD: investigate before suppressing.
- **INCONCLUSIVE** verdicts from a cold database are not rule false positives. Let the maturity gate accumulate 50 observations before judging.

## See also

- [Configuring rules and weights](configuring-rules-and-weights.md)
- [Rules reference](../reference/rules.md)
- [Cold start and maturity](../explanation/cold-start-and-maturity.md)
