<!-- description: The A/B/C/D evidence taxonomy: structural findings, source priors, history and novelty, and declared verification, with the maturity gating that governs them. -->

# Evidence Tiers

TrustSight groups scoring signals into four evidence tiers. Each tier represents a fundamentally different kind of information with different availability and confidence characteristics.

```
Tier A : Structural            (strongest, always available)
Tier B : Priors / Context      (domain reputation, always available)
Tier C : History / Novelty     (first-seen tracking, maturity-gated)
Tier D : Verification          (declared, weight 0, reported never scored)
```

---

## Tier A : Structural

Pattern-matched from the PKGBUILD diff. Direct, observable facts about what the build script does.

### Sources

- R-series regex rules and H-series heuristics, plus C/D/S/X rules where the signal requires structural, dependency, sabotage, or anti-evasion context.
- H001/H002 checksum integrity rules (hard-coded, not TOML).
- C001-C009 structural anomaly rules (checksum/source integrity heuristics).
- D001-D004 dependency-graph rules.

### Availability

**Available cold.** No database, no prior observations, no network; Tier A signals fire on the diff content alone. They are always scored at full weight.

### Examples

| Signal | Rule | Severity |
|--------|------|----------|
| `curl ... \| bash` | R001 | CRITICAL |
| `sha256sums=SKIP` | H001 | HIGH / INFO |
| `sha256sums=()` | H002 | HIGH |
| `sudo` in function body | H004 | CRITICAL |
| Unicode bidi override | R013 | FATAL |

### Benchmark

CRITICAL recall: **100%**; every CRITICAL-class sample in the benchmark corpus (267 tests) is detected.

---

## Tier B : Priors / Context {#tier-b-priors-context}

Domain reputation classification for every new source URL in the diff.

### Sources

- Source bucket assignment via `classify_url()` in `src/trustsight/buckets.py`.
- Static domain lists in `trusted_domains.toml`.

### Buckets

| Bucket | Modifier | Examples |
|--------|----------|----------|
| `trusted_forge` | 0 | github.com, gitlab.com, codeberg.org, bitbucket.org |
| `official` | 0 | kernel.org, python.org, nginx.org, archlinux.org |
| `raw_hosting` | +15 | raw.githubusercontent.com, pastebin.com, gist.github.com |
| `unknown` | +20 | Domain not in any allowlist |
| `homograph_attack` | +30 | Domain with Cyrillic homoglyphs (e.g. githab.com) |

A trusted forge is neutral, not a credit. Routing through github.com costs an
attacker nothing, so it is reported as the weight-0 finding `P007` instead
(`src/trustsight/scoring.py`).

### Availability

**Available cold.** Domain classification is a static membership check over the
configured raw-hosting, trusted-forge, and official-domain lists, plus the
homograph check. It does not learn buckets from the corpus and has no
`self_hosted` classifier. No database or history is needed. Always scored at
full weight.

### Scope

The bucket prior is scored once per diff, at the modifier of the least-trusted
single added URL (the maximum), not summed per URL. A package adding thirty
unknown-host URLs is one diff whose provenance is unknown, not thirty separate
facts; summing stacked the modifier until legitimate multi-source packages
(electron, fonts) outscored CRITICAL findings, which the §10 separation gate
(`benign_p95 < malicious_p5`) exists to catch. Only **added** URLs are
classified; removed URLs are not scored.

---

## Tier C : History / Novelty

First-seen tracking for URLs and maintainers, backed by the local SQLite database.

### Sources

- `build_novelty_context()` in `src/trustsight/novelty.py`.
- `source_urls` and `maintainers` tables in the local database at `~/.local/share/trustsight/`.

### Signals

| Signal | Raw weight | Description |
|--------|-----------|-------------|
| `url_first_seen_globally` | +10 | Normalised URL never seen in any package. |
| `url_first_seen_in_this_package` | +5 | Normalised URL never seen for this package. |
| `maintainer_first_seen_for_this_package` | +15 | Maintainer never recorded for this package. |

URLs are normalised before novelty checking: version numbers are replaced with `0`, hashes with `HASH`, dates with `DATE`. This prevents routine bumps from generating false novelty signals. See `normalize_url()` in `src/trustsight/novelty.py`.

### Maturity gate

All Tier C signals are scaled by the **maturity multiplier**:

```
maturity = min(1.0, observation_count / 50)
```

| Observations | Multiplier | Effective weight (url_first_globally) |
|--------------|------------|---------------------------------------|
| 0 | 0.0 | 0 |
| 10 | 0.2 | 2 |
| 25 | 0.5 | 5 |
| 49 | 0.98 | 9 |
| 50+ | 1.0 | 10 |

### Availability

**Cold DB → zero contribution.** With no real observations and no imported
seed, all novelty weights multiply by 0. Maturity uses the greater of the
local analysis count and the seed's bootstrap observation count, so a verified
seed can make Tier C effective on the first local run. As that effective count
warms, novelty signals ramp linearly to full weight.

### INCONCLUSIVE verdict

When the final score is in the Medium range (21-50) **and** maturity is below 0.5 (fewer than ~25 observations) **and** no entry in the breakdown is HIGH, CRITICAL or FATAL, the verdict is downgraded from "Medium" to "Inconclusive". This signals insufficient data rather than actual risk. Logic at `src/trustsight/scoring.py`.

The same downgrade is applied, at any maturity, when the analysis recorded a coverage gap: see [the security model](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete). Logic at `src/trustsight/coverage.py`.

---

## Tier D : Verification

Structural integrity protections declared in the statically visible post-diff
PKGBUILD text.
They are **reported, never scored**: each is emitted as a weight-0 finding in
the `P` namespace. See
[B10](../security.md#b10-positive-evidence-is-reported-never-credited) for why
a signal an attacker can assert for free must not lower a score.

### Sources

- `detect_verification_evidence()` in `src/trustsight/differ.py`.

### Evidence

| Evidence | Finding | Weight | Condition |
|----------|---------|--------|-----------|
| `checksum_present` | `P001` | 0 | Post-diff PKGBUILD has a non-empty sha256/sha512/b2/md5 checksum array. |
| `validpgpkeys_declared` | `P002` | 0 | Post-diff PKGBUILD declares PGP key fingerprints (16+ hex chars). |
| `gpg_verify_present` | `P003` | 0 | Post-diff PKGBUILD runs `gpg --verify`, `gpgv`, or `openpgp --check-signatures`. |
| source pinning | `P005` / `P006` | 0 | Pinned to a commit hash, or to a tag (the weaker form: tags can be repointed). |
| `trusted_forge` | `P007` | 0 | Source URL hosted on a trusted forge (github.com, gitlab.com, etc.) over HTTPS. |
| `no_commit_pin` | `P008` | 0 | Source tracks a branch or unpinned ref; upstream decides at build time what this compiles and runs. |

### End-state, not delta

Verification evidence is computed over the **resolved end-state of the PKGBUILD (what the file looks like after the diff is applied), not over the diff delta. A checksum that was already present before the diff and unchanged still counts. This reflects the actual protection in place when the package is installed.

Checksum evidence is suppressed when `checksum_behavior` is `"changed_from_sha256_to_skip"` or `"checksum_array_emptied"`; an intentionally disabled checksum does not count as present even if the array declaration remains.

### Availability

**Available cold.** Computed from static post-diff text alone, not from database history or a fetched artifact. Contributes nothing to the score in either direction, so it is available and reported from the first run, with no maturity gate and no cold-start caveat.

---

## Tier summary

| Tier | Name | Cold? | Maturity-gated? | Direction | Max contribution per signal |
|------|------|-------|-----------------|-----------|---------------------------|
| A | Structural | Yes | No | Positive | 40 (CRITICAL) or 100 (FATAL) |
| B | Priors/Context | Yes | No | Positive only | +30 (homograph); trusted forge is 0 |
| C | History/Novelty | No : zero without a seed | Yes (×0→1) | Positive only | +15 (maintainer) |
| D | Verification | Yes | No | Reported, never scored | 0 (`P001`-`P008`) |

---

## Outside the tiers: the W series

The four tiers classify **evidence about the recipe**. The W series
(`W001`-`W006`) makes a different kind of statement: not that the recipe did
something, but that this analysis could not read something the recipe will
run. A tier answers "how strong is this signal"; a W finding answers "what
was not looked at".

It is therefore not tier-gated, not maturity-scaled, and not scored. It is
the per-line form of a [coverage gap](report-schema.md), available cold and
always shown. See the [unverifiable rules reference](rules/unverifiable.md).
