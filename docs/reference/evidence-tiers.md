# Evidence Tiers

TrustSight groups scoring signals into four evidence tiers. Each tier represents a fundamentally different kind of information with different availability and confidence characteristics.

```
Tier A : Structural            (strongest, always available)
Tier B : Priors / Context      (domain reputation, always available)
Tier C : History / Novelty     (first-seen tracking, maturity-gated)
Tier D : Verification          (subtractions, end-state only)
```

---

## Tier A : Structural

Pattern-matched from the PKGBUILD diff. Direct, observable facts about what the build script does.

### Sources

- R001–R013 rules firing against resolved command strings or raw diff lines.
- R004/R005 checksum integrity rules (hard-coded, not TOML).
- C001–C003 structural anomaly rules (checksum/source integrity heuristics).

### Availability

**Available cold.** No database, no prior observations, no network; Tier A signals fire on the diff content alone. They are always scored at full weight.

### Examples

| Signal | Rule | Severity |
|--------|------|----------|
| `curl ... \| bash` | R001 | CRITICAL |
| `sha256sums=SKIP` | R004 | HIGH / INFO |
| `sha256sums=()` | R005 | HIGH |
| `sudo` in function body | R009 | CRITICAL |
| Unicode bidi override | R013 | FATAL |

### Benchmark

CRITICAL recall: **100%**; every CRITICAL-class sample in the benchmark corpus (267 tests) is detected.

---

## Tier B : Priors / Context {#tier-b-priors-context}

Domain reputation classification for every new source URL in the diff.

### Sources

- Source bucket assignment via `classify_url()` in `src/trustsight/buckets.py:22`.
- Domain allowlists in `~/.config/trustsight/trusted_domains.toml`.

### Buckets

| Bucket | Modifier | Examples |
|--------|----------|----------|
| `trusted_forge` | –10 | github.com, gitlab.com, codeberg.org, bitbucket.org |
| `official` | 0 | kernel.org, python.org, nginx.org, archlinux.org |
| `self_hosted` | +10 | Custom domain under maintainer control |
| `raw_hosting` | +15 | raw.githubusercontent.com, pastebin.com, gist.github.com |
| `unknown` | +20 | Domain not in any allowlist |
| `homograph_attack` | +30 | Domain with Cyrillic homoglyphs (e.g. githab.com) |

The trusted forge modifier is capped at **–20** total across all URLs (`src/trustsight/scoring.py:108`).

### Availability

**Available cold.** Domain classification depends only on the built-in allowlists and `tldextract`. No database or history needed. Always scored at full weight.

### Scope

Evaluated per-URL. Each added URL contributes its bucket modifier independently. Only **added** URLs are classified; removed URLs are not scored.

---

## Tier C : History / Novelty

First-seen tracking for URLs and maintainers, backed by the local SQLite database.

### Sources

- `build_novelty_context()` in `src/trustsight/novelty.py:81`.
- `source_urls` and `maintainers` tables in the local database at `~/.local/share/trustsight/`.

### Signals

| Signal | Raw weight | Description |
|--------|-----------|-------------|
| `url_first_seen_globally` | +15 | Normalised URL never seen in any package. |
| `url_first_seen_in_this_package` | +10 | Normalised URL never seen for this package. |
| `maintainer_first_seen_for_this_package` | +20 | Maintainer never recorded for this package. |

URLs are normalised before novelty checking: version numbers are replaced with `0`, hashes with `HASH`, dates with `DATE`. This prevents routine bumps from generating false novelty signals. See `normalize_url()` in `src/trustsight/novelty.py:12`.

### Maturity gate

All Tier C signals are scaled by the **maturity multiplier**:

```
maturity = min(1.0, observation_count / 50)
```

| Observations | Multiplier | Effective weight (url_first_globally) |
|--------------|------------|---------------------------------------|
| 0 | 0.0 | 0 |
| 10 | 0.2 | 3 |
| 25 | 0.5 | 7 |
| 49 | 0.98 | 14 |
| 50+ | 1.0 | 15 |

### Availability

**Cold DB → zero contribution.** With no prior observations, all novelty weights multiply by 0. As the database warms up, novelty signals ramp linearly to full weight.

### INCONCLUSIVE verdict

When the final score is in the Medium range (21–50) **and** all contributing signals are Tier C novelty **and** maturity is below 0.5 (fewer than ~25 observations), the verdict is downgraded from "Medium" to "Inconclusive". This signals insufficient data rather than actual risk. Logic at `src/trustsight/scoring.py:192`.

---

## Tier D : Verification

Structural integrity protections in the resolved (post-diff) PKGBUILD. These subtract from the score; they can never increase it.

### Sources

- `detect_verification_evidence()` in `src/trustsight/differ.py:149`.

### Evidence

| Evidence | Modifier | Condition |
|----------|----------|-----------|
| `checksum_present` | –10 | Post-diff PKGBUILD has a non-empty sha256/sha512/b2/md5 checksum array. |
| `validpgpkeys_declared` | –10 | Post-diff PKGBUILD declares PGP key fingerprints (16+ hex chars). |
| `gpg_verify_present` | –5 | Post-diff PKGBUILD runs `gpg --verify`, `gpgv`, or `openpgp --check-signatures`. |

### End-state, not delta

Verification evidence is computed over the **resolved end-state of the PKGBUILD (what the file looks like after the diff is applied), not over the diff delta. A checksum that was already present before the diff and unchanged still counts. This reflects the actual protection in place when the package is installed.

Checksum evidence is suppressed when `checksum_behavior` is `"changed_from_sha256_to_skip"` or `"checksum_array_emptied"`; an intentionally disabled checksum does not count as present even if the array declaration remains.

### Availability

**Available cold.** Computed from the diff text alone. Always scored at full weight. Negative modifiers can bring the total score below zero (the final score is then floored at 0).

---

## Tier summary

| Tier | Name | Cold? | Maturity-gated? | Direction | Max contribution per signal |
|------|------|-------|-----------------|-----------|---------------------------|
| A | Structural | Yes | No | Positive | 40 (CRITICAL) or 100 (FATAL) |
| B | Priors/Context | Yes | No | Positive/negative | +30 (homograph) / –10 (trusted forge, capped –20) |
| C | History/Novelty | No : zero | Yes (×0→1) | Positive only | +20 (maintainer) |
| D | Verification | Yes | No | Negative only | –10 (checksum or PGP) |
