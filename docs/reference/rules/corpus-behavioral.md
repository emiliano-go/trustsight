<!-- description: Rules reading the package's position in the corpus, or its deviation from a corpus baseline. Silent without prior observations; run once per metadata cycle. -->

# Corpus Behavioral

The package's position in the corpus, or its deviation from a corpus
baseline. These are Class D and Class E: they run once per metadata cycle
in `trustsight full-aur`, after the per-package loop, and each returns one
finding per cluster with the members in `params.members`.

They are silent without a prior snapshot, which is enforced rather than
assumed: the calibration gate is `fire_rate(no_baseline) == 0`. H061 and
H057/H060 are prioritisation rather than accusation; they say what a
compromise would reach, not that anything is wrong.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [H028](#h028) | Accelerated Release Cadence | - |
| [H046](#h046) | Orphan/Adoption Dependency | MEDIUM |
| [H056](#h056) | Known Indicator of Compromise | FATAL |
| [H057](#h057) | Transitive Exposure | INFO |
| [H060](#h060) | Transitive Orphan Exposure | INFO |
| [H061](#h061) | Dependency Centrality | INFO |
| [H073](#h073) | Introduction Rate Deviation | MEDIUM |
<!-- /generated: page-index -->

### H028: Accelerated Release Cadence {#h028}

- **Target:** programmatic (git commit graph)
- **Severity:** metadata field, **never a scored finding**
- **Category:** `temporal-metadata`
- **Condition:** The HEAD commit has 3+ ancestors within the last 24 hours
  (rapid-fire pushes).

**Why it does not score:** Bursts of commits are overwhelmingly benign
activity - a maintainer fixing a bad checksum, then a typo, then a rebuild
bump. This is precisely the "measuring activity, not risk" failure the
accuracy work's CI gate (`|pearson(score, diff_lines)| < 0.3`) exists to
catch. At any non-zero weight it becomes a census on active maintainers.

H028 is therefore **metadata only**: recorded as a boolean on the
`PackageFact` (`recent_commit_burst: bool`). It is not appended to
`triggered_rules` and contributes nothing to the score. If future corpus
analysis shows that burst cadence *pairs with* other signals (burst +
maintainer takeover + verification removal), the burst multiplier can be
applied to those signals alone - never as a standalone finding.

**Origin:** pnpm's `minimumReleaseAge` (24-hour cooldown on new versions) and
uv's `exclude-newer` (reject packages published within a configurable window).
Both tools impose a *registry-side cooldown*: do not install a version until
it has existed long enough for the community to vet it. H028 takes the
opposite perspective - instead of blocking recent versions, it notes that
multiple commits landed in a short window, recording the cadence as context
for other signals to use.

### H046: Orphan/Adoption Dependency {#h046}

- **Severity:** MEDIUM (weight 15)
- **Category:** `dependency`
- **Condition:** A package depends directly on a package orphaned or adopted in this cycle.

### H057: Transitive Exposure {#h057}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`
- **Condition:** A package's transitive closure, at least `[thresholds] h057.min_hops` (default 2) hops away, reaches a package adopted out of the orphan state this cycle. Context only, never additive.

### H060: Transitive Orphan Exposure {#h060}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`
- **Condition:** A package's transitive closure includes a currently orphaned package. Context only, never additive.

### H061: Dependency Centrality {#h061}

- **Severity:** INFO (weight 0)
- **Category:** `dependency`
- **Condition:** A package is depended on by at least `[thresholds] h061.min_dependents` (default 50) AUR packages. Prioritisation only: it says what a compromise would reach, not that anything is wrong.

### H073: Introduction Rate Deviation {#h073}

- **Severity:** MEDIUM (weight 15)
- **Category:** `adoption`
- **Condition:** The corpus-wide introduction rate for a cycle deviates from the baseline mean by at least `[thresholds] h073.z_score` (default 3.0), once at least `h073.min_history_cycles` (default 3) cycles of history exist. An immature history is quiet.

### H056: Known Indicator of Compromise {#h056}

- **Severity:** tiered by the indicator's confidence: `confirmed` is FATAL, `high` is CRITICAL, `medium` is HIGH, an untiered entry is MEDIUM
- **Category:** `ioc`
- **Condition:** A declared surface exactly matches an entry in `iocs.toml`.

Four surfaces are read: the package's own name; names added to
`depends`/`makedepends`/`optdepends`/`checkdepends`/`provides`/`replaces`; the
host of any URL and any bare host token; and any hex digest of digest length.
H056 also reads the current PKGBUILD, not only the diff, so a dependency on a
package later published as malware is reported on every review rather than only
on the one that introduced it.

Matching is **exact**. Normalisation is limited to what is not part of the
identity: case, a trailing root dot, IDNA spelling, surrounding quotes. A host
is never stripped of a subdomain and a name is never stemmed, because that would
turn equality into resemblance. A malformed entry is dropped with a warning
rather than coerced.

**The shipped list is empty.** TrustSight does not invent indicators, so a fresh
install cannot fire H056 at all, and a miss is uninformative. `trustsight corpus
pivot <indicator>` inverts the rule: given one indicator, it lists every corpus
package referencing it, reading only stored material and never the network.

A `confirmed` indicator cannot be suppressed through `overrides.json`.
