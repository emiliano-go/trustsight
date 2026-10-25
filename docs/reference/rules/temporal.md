<!-- description: Rules reading how recently the package or this revision appeared, from AUR commit timestamps alone. None of them needs a diff. -->

# Temporal Context

Where these rules come from and what a finding means: [Rule Nature](../nature/temporal.md).

How recently the package or this revision appeared. These read git commit
timestamps on the AUR repository and nothing else, so none of them needs a
diff. H020 and H021 also fire on first-seen packages through
`_make_fresh_analysis()` in `pipeline.py`; H022 needs a prior commit, so it
fires only on the incremental path.

None is calibrated against the benign corpus, because each one is a
function of when the scan runs rather than of what the package contains.
H020 and H021 are INFO for that reason: recency has no meaning on its own,
and only escalates a package once another signal fires alongside it.

Release cadence is a related but separate claim and is not scored at all;
see [H028](corpus-behavioral.md#h028).

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [H020](#h020) | Very Recent Update | INFO |
| [H021](#h021) | Brand New Package | INFO |
| [H022](#h022) | Stale Package Revived | MEDIUM |
| [T001](#t001) | Signing-Key Novelty | HIGH |
| [T002](#t002) | Maintainer Domain Novelty | MEDIUM |
| [T003](#t003) | Signing Key Rotated | HIGH |
| [T006](#t006) | Metadata-Git Divergence | MEDIUM |
| [T007](#t007) | Packager Not In History | INFO |
<!-- /generated: page-index -->

### H020: Very Recent Update {#h020}

- **Target:** programmatic (commit timestamp)
- **Severity:** INFO (weight 0)
- **Category:** `temporal`

<!-- name: Very Recent Update -->

- **Condition:** AUR HEAD commit is less than 72 hours old.

Packages updated moments ago have not been visible to the community long enough
for anyone to vet them. Combined with other signals - maintainer change, new
source domains - recency escalates suspicion.

### H021: Brand New Package {#h021}

- **Target:** programmatic (root commit timestamp)
- **Severity:** INFO (weight 0)
- **Category:** `temporal`

<!-- name: Brand New Package -->

- **Condition:** The package's first commit on AUR is less than 30 days old.

A package that barely exists has no reputation. An established package with a
recent update is routine; a package uploaded last week has zero track record.

### H022: Stale Package Revived {#h022}

- **Target:** programmatic (commit timestamp gap)
- **Severity:** MEDIUM (weight 15)
- **Category:** `temporal`

<!-- name: Stale Package Revived -->

- **Condition:** The previously analyzed commit is more than 365 days older than
  the new HEAD - an abandoned package that suddenly has activity.

Account takeovers happen on stale packages: a maintainer stops responding,
someone else adopts the AUR record, and the new maintainer may be malicious.
A gap of a year or more between the version you already have and the one being
offered is worth a medium-weight flag, independent of any diff signal.

### T001: Signing-Key Novelty {#t001}

- **Target:** programmatic (ecosystem signing-key ledger)
- **Severity:** HIGH (weight 25)
- **Category:** `temporal`

<!-- name: Signing-Key Novelty -->

- **Condition:** A `validpgpkeys` fingerprint added in this diff has never
  been observed in the ecosystem key index.

This is distinct from package novelty: the xz lesson is a *key* story. A
key that has signed nothing else in the ecosystem, appearing on this
package, is worth a high-weight flag even when the package itself is old.

The index is cold on a fresh install; the rule declines (silently) until
`[thresholds] t_key.min_observations` keys are recorded, so it never fires
on every key a new install sees.

### T002: Maintainer Domain Novelty {#t002}

- **Target:** programmatic (ecosystem maintainer-domain ledger)
- **Severity:** MEDIUM (weight 15)
- **Category:** `temporal`

<!-- name: Maintainer Domain Novelty -->

- **Condition:** The maintainer email's domain first appeared in the
  ecosystem within the observation window (`[thresholds] t_dom.window_days`,
  default 30) - a domain never seen before first appears now, and one first
  seen this week is as novel as brand new.

A first-seen domain is a weak but real signal about a maintainer with no
prior footprint. Cold index declines, like T001.

### T003: Signing Key Rotated {#t003}

- **Target:** programmatic (`validpgpkeys` pre/post)
- **Severity:** HIGH (weight 25)
- **Category:** `temporal`

<!-- name: Signing Key Rotated -->

- **Condition:** A `validpgpkeys` key is removed *and* a different one is
  added in the same diff.

The xz backdoor's shape: the trusted signer is swapped, not merely widened
(H078) or narrowed (H024). Unlike T001 it needs no ecosystem history - the
rotation of trust inside one commit is its own fact - so it fires cold.

### T006: Metadata-Git Divergence {#t006}

- **Target:** programmatic (AUR LastModified vs git tip commit date)
- **Severity:** MEDIUM (weight 15)
- **Category:** `temporal`

<!-- name: Metadata-Git Divergence -->

- **Condition:** The AUR `LastModified` timestamp is ahead of the git tip
  commit date by at least `[thresholds] t006.min_divergence_hours` (default
  24) hours.

In aurweb, pushes set both `LastModified` and the git commit timestamp, so
divergence means commits were pushed and later stripped (a history rewrite).
The benign explanations (staff reset, maintainer cleanup force-push) are
themselves security-relevant, so this is MEDIUM, review-queue verdict. The
finding's output is designed to be pasted into a report to AUR security,
where push logs survive even when git history does not.

### T007: Packager Not In History {#t007}

- **Target:** programmatic (AUR maintainer vs git commit identities)
- **Severity:** INFO (weight 0)
- **Category:** `temporal`

<!-- name: Packager Not In History -->

- **Condition:** The AUR maintainer name does not appear in any commit
  message, author identity or committer identity in the retained git
  history of the package.

A weight-0 corroboration signal: the AUR says this account packaged the
project, but no commit in history names them. The message is only one place
an identity appears, so the author and committer names and addresses count
too; a maintainer who imported the package often signs the commit and
writes no message at all. Name matching is fuzzy (display name vs email vs
git config), so this corroborates T006 and G008 but never scores alone. On
its own tier it is nearly a confession; as a solo scorer it would
eventually burn someone with an unusual committer setup.
