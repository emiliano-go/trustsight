<!-- description: How to find a rule that fires too often on your package set, confirm it against measured fire rates, and disable or reweight it without blinding the rest. -->

# Tuning False Positives

No rule is perfect. Some may fire on patterns that are normal for your package set but would be suspicious elsewhere. This guide explains how to identify over-firing rules and what to do about them.

## Two kinds of false positive

A **benign false positive** is a rule hit on a genuine bad practice by the packager, where the package itself is not malicious. The finding is real; the practice is undesirable, and the rule is doing its job. The fix belongs with the packager, or the finding is documented as a known false positive.

A **malicious false positive** is a bad rule trigger: the rule fired with no bad practice or malicious behaviour behind it. A misread option, an allowlist gap, or a counting or grouping error is a malicious false positive. The fix belongs in the detection shape, and it ships with the true-positive twin.

The term names a false positive of the *maliciousness* claim, not a malicious false positive. The normative definitions are in [Standards](../standards.md#false-positive-vocabulary).

## Step 1: Check fire rates

Start from the measured corpus fire rates in [Fire Rates](../explanation/fire-rates.md), then check how often the rule fires across your own reviewed packages:

```bash
trustsight review --verbose
```

For each rule, note the **fire rate**: the percentage of your reviewed packages where it triggered. Re-derive the corpus rates with `scripts/rebaseline.py` after changing rules or weights.

> **The >30% heuristic:** A rule firing on more than 30% of your packages is not detecting anomalies; it is describing a property of your package set. That rule is now a **census**, not a signal.

## Step 2: Understand why

Inspect a few packages where the rule fired:

```bash
trustsight inspect <package>
```

Look for patterns:

- **H004/R010/R011** (command-structure rules): H004 requires `sudo` at command position; R010 and R011 are restricted to function bodies. If they are still over-firing, the package may use unconventional but legitimate helper functions.
- **H001** (checksum removal): some AUR packages legitimately skip checksums for binary blobs.
- **H002** (checksum array emptied): inspect why a recipe changed `sha256sums` to an empty array.
- **H003** (insecure download protocol): inspect an added `http://` source and whether the same change added or updated checksum backing.

### Scope constraints already applied

R010 and R011 are scoped to `function_body` context to reduce false positives on top-level variable assignments and sourced library files. H004 is code-emitted and requires `sudo` at command position. If they still over-fire, your further options are:

1. Demote the severity to INFO.
2. Disable the rule entirely (not recommended; you lose signal).
3. Add the false-positive pattern to a local allow-list.

## Step 3: Fix : demote, disable, or constrain

**Demote severity** (preferred):

```toml
## config.toml
[rules.R010]
weight_override = 5  # was LOW/5; still fires, but you can raise or lower it
```

**Disable the rule:**

```toml
## config.toml
[rules.R010]
enabled = false
```

Only disable a TOML-defined, non-FATAL rule if you are certain the pattern it detects is never malicious in your context. Revisit this decision periodically; the threat landscape changes.

**Constrain scope** (where supported):

`scope` is a field of the rule definition in `rules.toml`, not a `config.toml` override. Edit it on the rule itself:

```toml
[[rules]]
id = "R010"
# ...existing fields...
scope = ["function_body"]  # already the default
```

## Step 4: Re-baseline

After any change, re-run against your corpus:

```bash
trustsight review --record
```

`--record` persists the observations and analysis history the re-baseline compares against; without it the run is read-only and nothing is stored.

Score changes: the demoted/disabled rule contributes less. Verify that the packages that were false positives now score where you expect them. See [configuring rules and weights](configuring-rules-and-weights.md) and the [re-baselining guide](../contributing/re-baselining.md).

## Step 5: Validate with benchmarks

TrustSight's current test suite has a zero-rate of **72.1%** (benign packages scoring 0). After tuning, re-run:

```bash
uv run --extra dev pytest tests/
```

Ensure CRITICAL recall stays at **100%**: every known malicious pattern must still fire. The corpus benchmarks in the [explanation section](../explanation/benchmarks-and-methodology.md) define the expected p5/p95 separations:

| Metric | Value |
|--------|-------|
| CRITICAL recall | 100% |
| CRITICAL p5 | 60 |
| Benign p95 | 30 |

If demoting a rule drops CRITICAL recall below 100%, you have gone too far. Restore the rule and find another approach.

## Known false positives

Some patterns are deliberately left triggering and documented instead of
suppressed, because the same shape is a real signal elsewhere.

### Kernel module provides (H064, D004, H098)

A `linux*` split package provides module aliases the whole kernel family
depends on: `provides=(KSMBD-MODULE)`, `provides=(LINUX-HEADERS)`, or a
lower-case `<module>-module` name. `is_related_package` cannot accept
these - they name a kernel ABI, not a sibling project - so H064 (and
D004 when enabled) fires, and H098 composes it with a second naming
signal when one is present. The trigger is kept because the same
"provide a name the ecosystem depends on" shape is the dependency hijack
the rule exists for. If your package set is mostly kernel splits, the
tuning is:

Both rules are code-emitted, so `[rules.H064]` / `[rules.D004]` in
`config.toml` never reach them. D004 is governed by `[code_rules]`; H064 has
no per-rule weight control and is silenced with an override:

```toml
## config.toml
[code_rules]
D004 = false          # code-emitted; not experimental, disabled here
```

```bash
trustsight override add H064 --reason "kernel module provides are ABI aliases, not sibling projects"
```

H098 needs two distinct naming signals, so removing D004/H064 can clear
the cluster only where one of them was the second member - investigate
the other member before assuming the cluster is the same false positive.

### Benign findings from the 2026-10-23 watcher triage

These are **benign false positives**, not bad rule triggers: the finding
describes a real practice in the recipe, and the package itself is not
malicious. The rule is doing its job; the fix belongs with the packager.

| Package | Finding | Why it is not malicious |
|---------|---------|-------------------------|
| minetest-game-cdb | H016, W011, W012 | `prepare()` curls an unchecksummed CDB zip outside `source=()`; the zip is byte-identical to the upstream tag and contains no executable Lua. A pin and checksum follow-up is still the right packaging fix. |
| chest-backup | H042, R054, R007, H100 | A root hook seeds a user config and enables a user unit; it downloads and executes nothing. |
| sysc-greet-hyprland | H017, R007, H100 | Documented greeter setup: creates the greeter and enables greetd. |
| librechat | H017, X011, R007, H100 | Server packaging: `npm ci` at build time and an ownership-only hook. |
| hermes-agent-desktop | X011 | Declared, lockfile-pinned `uv`/`npm` build step. |
| paseo-cli-edge | X011 | `npm install` at build time; the published tarball has no install scripts and its checksum matches AUR. |
| firedragon | D003 | Firefox's build system uses `pnpm` in `prepare()`; no payload. |
| actor-framework | H101, H033 | A commit pin became a movable `tag=${pkgver}`. Reproducibility weakens; no payload. |
| yandex-messenger | C003, SOURCE_BUCKET | An expiring signed vendor URL with no version bump; the downloaded `.deb` matches the declared b2sum. |

The first row is also a real packaging issue. The rule hit is correct even
though the package is benign, so the long-term fix is to pin the CDB zip and
add it to `source=()` with a checksum, not to silence H016.

## When not to tune

- **First-seen novelty scores** (5-15) are not false positives. They are honest uncertainty that resolves as the database-wide maturity gate accumulates observations.
- **C-series rules** (C001-C032) are structural invariants. They cannot be disabled through config. If they fire, they are detecting a real property of the PKGBUILD: investigate before suppressing.
- **INCONCLUSIVE** verdicts from a cold database are not rule false positives. Let the maturity gate accumulate 50 observations before judging.

## See also

- [Standards](../standards.md) - the normative rules, including why a detection is never tuned for a package
- [Configuring rules and weights](configuring-rules-and-weights.md)
- [Rules reference](../reference/rules/index.md)
- [Cold start and maturity](../explanation/cold-start-and-maturity.md)
