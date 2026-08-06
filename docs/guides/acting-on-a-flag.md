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
- **Triggered rules**: which [R-series](../reference/rules.md) and [C-series](../reference/rules.md#c-series) rules fired, with the specific lines that matched.
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

**Always inspect manually.** INCONCLUSIVE means the tool could not form a complete picture, and it arises two ways.

**A cold database**, when all three hold:

- The score sits in the **25-50** range (Medium).
- No HIGH, CRITICAL, or FATAL signals fired.
- The database is **cold**: fewer than 25 recorded analyses for this package, so maturity is below 0.5 and novelty weight is not at full strength. Novelty reaches full weight at 50.

The verdict is telling you: "I see some novelty but I don't have enough history to judge it. You need to look yourself." See [cold start and maturity](../explanation/cold-start-and-maturity.md).

**A coverage gap**, at any score and any maturity, when the run could not examine the whole change. The report names which gap:

- `diff_truncated`: the diff was larger than the size cap, so only its prefix was read.
- `line_truncated`: a single line was longer than the matching limit, so its tail was never matched against any rule.
- `tree_not_analyzed`: the repository file manifest was unavailable, so only the PKGBUILD was read.
- `unresolved_source`: a `source=` entry is computed at build time, so the URL the build will fetch is not in the text.

Here the verdict is telling you something sharper: the part it did read looked ordinary, and there is a part it did not read. Fetch the package yourself and look at what was left out. See [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

## Step 4: Decide

| Finding | Action |
|---------|--------|
| Clean diff, known domain, no rule fires | UNFLAGGED : update normally |
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
