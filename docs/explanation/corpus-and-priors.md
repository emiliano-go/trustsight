# Corpus and Priors

TrustSight maintains an AUR-wide snapshot that serves as the prior distribution for all URL classification and novelty detection.

## How the snapshot is built

1. **Mirror pull**: a full AUR mirror is pulled via rsync over the AUR archive (approximately 89k packages).
2. **Diff extraction**: PKGBUILDs and related files (`.install`, `.patch`, systemd service files) are extracted for every package.
3. **URL extraction**: every `source=` entry, `url=`, and `validpgpkeys=` value is extracted and normalized across the entire corpus.
4. **Classification training**: domain-level frequency distributions are computed to determine which domains are common, which are rare, and which are suspicious.
5. **Weekly regeneration**: the snapshot is rebuilt weekly to stay current as packages are added, removed, or updated.

The snapshot is pinned via `corpus.lock` for reproducible benchmarking. This means a given version of the corpus produces identical results regardless of when or where it is run. When regeneration produces a new snapshot, the lock file is updated and the old snapshot is archived for reproducibility.

### Why weekly, not daily

AUR package turnover is slow enough that weekly regeneration captures every meaningful change. A daily regeneration would introduce noise from transient uploads and intermediate maintainer edits without improving classification accuracy. Weekly regeneration also makes benchmark comparisons tractable: comparing this week's results against last week's shows meaningful signal changes, not hourly drift.

## Why corpus-derived priors beat hand-written lists

A domain appearing once in the entire AUR corpus is suspicious *regardless of what it looks like*. A hand-written typosquat list can only match domains someone thought to enumerate. A corpus-derived prior catches squats nobody enumerated: any domain that appears once in 89k packages is, by definition, unusual.

This is the difference between a static blocklist and a statistical prior. The corpus *is* the prior.

### Examples

- A hand-written list might include `githab.com` as a known typosquat of `github.com`. A corpus-derived prior would also flag `githuib.com`, `githuub.com`, and any other variation that appears once in the corpus. It catches variants no one thought to add to a blocklist.
- A new CDN domain that appears in exactly one package source is flagged as unusual, even though it is a legitimate CDN. This is a true positive in the sense that a single-package CDN use is genuinely unusual and warrants review. The corpus prior is honest about rarity, not about intent.

### How homograph detection works

Homograph detection compares each new domain against a set of known trusted domains using visual similarity heuristics. If a domain is visually confusable with a trusted domain and appears fewer than a threshold number of times in the corpus, it is classified as `homograph_attack`.

The detection is conservative. A domain that looks like `github.com` but uses a Cyrillic `g` is caught. A domain that looks like `github.com` but is a legitimate mirror on a different TLD is flagged as `unknown`, not `homograph`, unless visual similarity is high enough to trigger the heuristic.

The threshold exists because some domains are visually similar to trusted domains by coincidence. A package that legitimately uses `githab.com` (a real domain) would appear multiple times in the corpus and fall below the suspicion threshold. The corpus prior provides the baseline: rare + similar = suspicious.

## How global priors make cold runs accurate

Even on first run (when novelty signals are inactive, see [Cold Start and Maturity](cold-start-and-maturity.md)), URL classification works because the domain list is corpus-derived:

- `trusted_forge`: domains that commonly host AUR sources (GitHub, GitLab, Codeberg, Bitbucket, SourceForge). These carry a negative score modifier because they provide platform-level integrity guarantees: signed commits, tag verification, and content-addressed releases.
- `official`: known upstream domains (kernel.org, python.org, nginx.org, archlinux.org, gnu.org). Neutral modifier: the domain is established but does not provide platform guarantees.
- `self_hosted`: custom domains under maintainer control. Slight positive modifier: the maintainer controls the infrastructure, which introduces a compromise vector but is normal for many packages.
- `raw_hosting`: content-delivery domains (raw.githubusercontent.com, pastebin.com, gist.github.com). Positive modifier: these domains serve content without integrity guarantees.
- `unknown`: everything else, classified by corpus frequency. Positive modifier: the domain is not established in the AUR ecosystem.
- `homograph`: domains that visually resemble known domains. Highest positive modifier: active deception attempt suspected.

A URL that resolves to an `unknown` or `homograph` bucket triggers a signal regardless of whether the local DB has ever seen this specific URL before. The cold-start accuracy comes from the global prior, not the local observation history.

This is critical for the first-run use case. A user running `trustsight review` for the first time gets accurate domain classification from the bundled corpus data, without needing to build up their own observation history.

## Local novelty weighted by global rarity

The composition the naive design misses: a URL that is first-seen-in-this-package but common globally (for example, a popular GitHub repo) is less interesting than one that is first-seen anywhere in the corpus.

TrustSight tracks both:

| Signal | Condition | Full weight | Why the weight differs |
|--------|-----------|-------------|------------------------|
| `url_first_globally` | URL never seen in any AUR package | 15 | A globally novel URL is genuinely rare. It has not appeared in any of the 89k packages in the corpus. This is the strongest novelty signal. |
| `url_first_in_package` | URL never seen in this specific package, but seen elsewhere | 10 | A per-package novel URL is weaker. It might mean the package is new to your observation set, not that the URL is unusual. |

The globally-first signal carries more weight because it is rarer and more specific. The per-package-first signal is weaker because it may just mean the package has not been observed before in your local database.

### The composition in practice

A popular GitHub repository like `https://github.com/torvalds/linux` would never fire `url_first_globally` because it appears in thousands of AUR packages. It might fire `url_first_in_package` for a specific package that is new to your database. The weight would be 10, reflecting that the URL itself is well-known.

A package that adds a URL from a never-before-seen domain fires both `url_first_globally` (15) and the `unknown` source bucket penalty (20), for a combined contribution of 35. The two signals compound because they come from different evidence tiers (B and C).

## Corpus size and coverage

- Approximately 89k packages in the full AUR snapshot.
- Classification covers all unique source URLs extracted from the corpus.
- Weekly regeneration ensures coverage stays current as the AUR grows.
- The bundled domain list covers approximately 14k unique domains, classified by frequency and forge membership.

The corpus is not exhaustive. New packages added between weekly regenerations might contain domains not in the current snapshot. These domains are classified as `unknown` by default, which is the correct conservative behavior. They will be reclassified in the next weekly regeneration if their frequency crosses a threshold.

This also means that removing a package from the AUR does not immediately change classification. The snapshot is weekly, so a removed package's domains remain in the prior until the next regeneration. This is acceptable: domain rarity is measured over a multi-week window, not a point-in-time snapshot.
