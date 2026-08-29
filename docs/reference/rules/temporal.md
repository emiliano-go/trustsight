<!-- description: Rules reading how recently the package or this revision appeared, from AUR commit timestamps alone. None of them needs a diff. -->

# Temporal Context

How recently the package or this revision appeared. These read git commit
timestamps on the AUR repository and nothing else, so none of them needs a
diff, and all three also fire on first-seen packages through
`_make_fresh_analysis()` in `pipeline.py`.

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
