<!-- description: Rules reading how recently the package or this revision appeared, from AUR commit timestamps alone. None of them needs a diff. -->

# Temporal Context

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
<!-- /generated: page-index -->

### H020: Very Recent Update {#h020}

- **Target:** programmatic (commit timestamp)
- **Severity:** INFO (weight 0)
- **Category:** `temporal`
- **Condition:** AUR HEAD commit is less than 72 hours old.

Packages updated moments ago have not been visible to the community long enough
for anyone to vet them. Combined with other signals - maintainer change, new
source domains - recency escalates suspicion.

### H021: Brand New Package {#h021}

- **Target:** programmatic (root commit timestamp)
- **Severity:** INFO (weight 0)
- **Category:** `temporal`
- **Condition:** The package's first commit on AUR is less than 30 days old.

A package that barely exists has no reputation. An established package with a
recent update is routine; a package uploaded last week has zero track record.

### H022: Stale Package Revived {#h022}

- **Target:** programmatic (commit timestamp gap)
- **Severity:** MEDIUM (weight 15)
- **Category:** `temporal`
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
- **Condition:** The maintainer email's domain has never been observed in
  the ecosystem index.

A first-seen domain is a weak but real signal about a maintainer with no
prior footprint. Cold index declines, like T001.
