# Corpus and Priors

TrustSight maintains an AUR-wide snapshot that serves as the prior distribution for all URL classification and novelty detection.

## How the snapshot is built

1. **Mirror pull**: a full AUR mirror is pulled (via rsync over the AUR archive).
2. **Diff extraction**: PKGBUILDs and related files are extracted for all ~89k packages.
3. **Weekly regeneration**: the snapshot is rebuilt weekly to stay current.

The snapshot is pinned via `corpus.lock` for reproducible benchmarking. This means a given version of the corpus produces identical results regardless of when or where it's run.

## Why corpus-derived priors beat hand-written lists

A domain appearing once in the entire AUR corpus is suspicious *regardless of what it looks like*. A hand-written typosquat list can only match domains someone thought to enumerate. A corpus-derived prior catches squats nobody enumerated; any domain that appears once in 89k packages is, by definition, unusual.

This is the difference between a static blocklist and a statistical prior. The corpus *is* the prior.

## How global priors make cold runs accurate

Even on first run (when novelty signals are inactive, see [Cold Start and Maturity](cold-start-and-maturity.md)), URL classification works because the domain list is corpus-derived:

- `trusted_forge`: domains that commonly host AUR sources (GitHub, GitLab, Codeberg).
- `official`: known upstream domains (gnu.org, python.org, etc.).
- `unknown`: everything else, classified by corpus frequency.
- `homograph`: domains that visually resemble known domains.

A URL that resolves to an `unknown` or `homograph` bucket triggers a signal regardless of whether the local DB has ever seen this specific URL before. The cold-start accuracy comes from the global prior, not the local observation history.

## Local novelty weighted by global rarity

The composition the naive design misses: a URL that is first-seen-in-this-package but common globally (e.g., a popular GitHub repo) is less interesting than one that is first-seen anywhere in the corpus.

TrustSight tracks both:

| Signal | Condition | Full weight |
|--------|-----------|-------------|
| `url_first_globally` | URL never seen in any AUR package | 15 |
| `url_first_in_package` | URL never seen in this specific package, but seen elsewhere | 10 |

The globally-first signal carries more weight because it is rarer and more specific. The per-package-first signal is weaker because it may just mean the package hasn't been observed before.

## Corpus size and coverage

- **~89k packages** in the full AUR snapshot.
- Classification covers all unique source URLs extracted from the corpus.
- Weekly regeneration ensures coverage stays current as the AUR grows.
