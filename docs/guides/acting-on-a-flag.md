---
description: What to do when a package is FLAGGED or INCONCLUSIVE.
---

# Acting on a Flag

A **flag** is a prompt to look, not a verdict to obey. TrustSight is a deterministic audit tool, not an authority. When a package scores above 20 or returns INCONCLUSIVE, the right response is investigation, not automatic rejection.

## Step 1: Inspect the package

```bash
trustsight inspect <package>
```

This shows:

- The **diff summary**: every line added, removed, or changed between the installed and candidate PKGBUILD.
- **Resolved commands**: the expanded `source=()`, `sha256sums=()`, `validpgpkeys=()`, etc., as they would execute during the build.
- **Triggered rules**: which [R-series](../reference/rules.md) and [C-series](../reference/rules.md#c-series-c001c003) rules fired, with the specific lines that matched.
- **Evidence breakdown**: contribution from each [evidence tier](../reference/evidence-tiers.md): structural (A), priors (B), novelty (C), verification (D).

## Step 2: Trace the score to specific PKGBUILD lines

Every rule in the output references the line(s) that triggered it. Cross-reference with the diff:

- **R004 (checksum removal)**: look for `sha256sums=('SKIP')` or a `source=` entry without a matching checksum.
- **R005 (new source URL)**: find the added URL in the diff. Check the domain classification in the [evidence tiers](../reference/evidence-tiers.md#tier-b-priors-context).
- **R006 (domain change)**: compare old and new source domains.
- **R012/R013 (FATAL)**: unicode confusables or prompt injection: do not install.

## Step 3: Act by severity tier

| Severity | What to do |
|----------|------------|
| **INFO / LOW** | Note the finding. Unlikely to be malicious in isolation. |
| **MEDIUM** | Run `trustsight inspect` and read the diff manually. Check upstream release notes for the version bump. |
| **HIGH** | Strong signal. Do **not** update this package until you understand why the rule fired. |
| **CRITICAL** | Do **not** install. Investigate thoroughly; checksum removal combined with an unknown domain is a common attack pattern. |
| **FATAL** (R012/R013) | Prompt injection or unicode manipulation detected. Score is forced to 100. **Do not install.** Report to the AUR maintainer or the TUR. |

## When to trust INCONCLUSIVE

**Always inspect manually.** INCONCLUSIVE means the tool could not form a complete picture:

- The score sits in the **25-50** range (Medium).
- No HIGH, CRITICAL, or FATAL signals fired.
- The database is **cold**: fewer than 50 observations, so novelty weight is not at full strength.

In this state the tool is being honest about its uncertainty. The verdict is telling you: "I see some novelty but I don't have enough history to judge it. You need to look yourself." See [cold start and maturity](../explanation/cold-start-and-maturity.md).

## Step 4: Decide

| Finding | Action |
|---------|--------|
| Clean diff, known domain, no rule fires | CLEAN : update normally |
| Medium score from novelty only, warm DB (>50 obs) | Note it : likely benign |
| High score, multiple rule fires, or cold DB + any novelty | **Skip** this package. Inspect deeper or wait for the next release. |
| FATAL rule | **Do not install.** |
| INCONCLUSIVE | Manual inspection required. |

## Recording decisions

After investigation you may decide a rule is over-firing on your package set. See [tuning false positives](tuning-false-positives.md) for how to demote or scope-constrain rules without losing signal.

## See also

- [Auditing before update](auditing-before-update.md): the review workflow.
- [Rules reference (R001-R013)](../reference/rules.md): what each rule detects.
- [Evidence tiers](../reference/evidence-tiers.md): how evidence is weighted.
