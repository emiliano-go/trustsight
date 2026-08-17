# Corpus and Priors

TrustSight can use an AUR-derived seed for URL, maintainer, and dependency
history. These corpus/state features are **optional context signals**, not a
requirement for structural detection: without a seed or local history, the tool
runs cold, keeps the relevant novelty and dependency signals silent or
downweights them, and reports the resulting limitation where applicable. This
avoids treating every first-seen value as suspicious while preserving useful
context for operators who choose to import or accumulate it. Source buckets are
separate: they are static configured domain lists, not corpus-derived frequency
classifications.

## How the snapshot is built

1. **Mirror pull**: a full AUR mirror is pulled via rsync over the AUR archive (approximately 89k packages).
2. **Diff extraction**: PKGBUILDs and related files (`.install`, `.patch`, systemd service files) are extracted for every package.
3. **Observation extraction**: source URLs, maintainer identities, and dependency names are extracted and normalized for the seed's novelty and dependency history.
4. **Seed packaging**: the resulting observations are hashed where required and
   packaged as a signed seed.

The snapshot is pinned via `corpus.lock` for reproducible benchmarking. This means a given version of the corpus produces identical results regardless of when or where it is run. When regeneration produces a new snapshot, the lock file is updated and the old snapshot is archived for reproducibility.

## Static source buckets

Source buckets are intentionally not trained from corpus frequency. The
classifier checks static configured lists for raw-hosting, trusted-forge, and
official domains, then falls back to `unknown`; a targeted homograph check can
produce `homograph_attack`. This makes bucket assignment reproducible from the
configuration and prevents a domain becoming trusted merely by appearing often.

### Examples

- The homograph check detects a mixed-script label that normalizes to a configured popular domain. It does not depend on how often the candidate appears in the corpus.
- A domain absent from every configured list is `unknown`, whether it is new or long-established. Operators can review and deliberately classify domains through configuration.

### How homograph detection works

Homograph detection compares each new domain against configured popular domains
using script-mixing and confusable-character normalization. A domain is
`homograph_attack` only when it is mixed-script and normalizes to a configured
target; there is no corpus-frequency threshold.

The detection is conservative. A domain that looks like `github.com` but uses a Cyrillic `g` is caught. A domain that looks like `github.com` but is a legitimate mirror on a different TLD is flagged as `unknown`, not `homograph`, unless visual similarity is high enough to trigger the heuristic.

This intentionally avoids treating every internationalized domain as hostile:
single-script labels and configured compatible script combinations do not match.

## How static buckets work on cold runs

Even on a cold first run (when novelty signals are inactive, see [Cold Start and Maturity](cold-start-and-maturity.md)), URL classification works because the domain lists are static:

- `trusted_forge`: configured forge domains. Neutral (weight 0) and reported as the declared-practice finding `P007`, never credited.
- `official`: configured upstream domains. Neutral modifier.
- `raw_hosting`: configured content-delivery domains. Positive modifier.
- `unknown`: everything else. Positive modifier.
- `homograph_attack`: a mixed-script confusable of a configured popular domain. Highest positive modifier.

A URL that resolves to an `unknown` or `homograph_attack` bucket triggers a
signal regardless of whether the local DB has ever seen this specific URL
before. Cold-run behavior comes from the static classifier, not local
observation history.

This is critical for the first-run use case. A user running `trustsight review`
for the first time gets the same deterministic bucket classification without
needing prior observations.

## Local novelty and seeded global history

The composition the naive design misses: a URL that is first-seen in this
package but known to the seeded global history is less interesting than one
that is first-seen anywhere in the local or seeded observation store.

TrustSight tracks both:

| Signal | Condition | Full weight | Why the weight differs |
|--------|-----------|-------------|------------------------|
| `url_first_globally` | URL never seen in the local or seeded observation store | 10 | A globally novel URL is the strongest URL-novelty signal. |
| `url_first_in_package` | URL never seen in this specific package, but seen elsewhere | 5 | A per-package novel URL is weaker. It might mean the package is new to your observation set, not that the URL is unusual. |

The globally-first signal carries more weight because it is more specific. The
per-package-first signal is weaker because it may just mean the package has not
been observed before in the local database.

### The composition in practice

A popular GitHub repository like `https://github.com/torvalds/linux` can be
known to the imported seed and therefore not fire `url_first_globally`. It
might fire `url_first_in_package` for a specific package new to the local
database; that signal weighs 5 at full maturity.

A package that adds a globally novel URL on an unknown domain can fire
`url_first_globally` (10 at full maturity) and the `unknown` source-bucket
modifier (20), for a combined contribution of 30. The two signals are
independent Tier B and Tier C evidence.

## Seed coverage

The seed is a point-in-time observation baseline, not a source-bucket list.
New URLs not present in it remain novel until imported or locally observed;
their bucket remains the result of the static domain classifier.

## The live corpus: cycles, the adoption feed, and watch mode

The bundled snapshot is an optional prior. `trustsight full-aur` is an optional
operator-run feature for installations that want to keep local corpus context
current; it is not required for ordinary package review, and it does more than
refresh priors.

Each run is one **cycle**: fetch the AUR metadata dump, diff it against the
stored snapshot, analyse the PKGBUILDs of everything added or changed, then run
the Class D corpus sweep across the whole delta. The sweep is the part that
cannot be done per package. It asks who adopted ten packages this week, which
unrelated packages started sharing a source repository, and whether the
corpus-wide introduction rate jumped; it reports one finding per cluster with
the members attached rather than repeating itself once per member. These are
**campaign-shape** observations about coordinated timing, ownership, and shared
metadata. They do not reveal, download, or inspect an upstream registry payload:
if a build step resolves a package from npm, PyPI, or another registry at build
time, the bytes the registry serves remain outside TrustSight's visibility.

Every cycle is also written to the **adoption feed**, a row per package per
cycle in `cycle_events` recording whether it was added, modified or removed and
who owned it. That feed is the baseline R125 measures a rate deviation against
and the history R108 compares a maintainer's activity to. It is why the first
cycle of a fresh install can never produce a Class D finding: there is nothing
to deviate from, and that silence is enforced by a calibration gate.

`trustsight full-aur --watch` repeats the cycle on an interval. The one thing
it adds beyond repetition is memory: an announced cluster is recorded in
`alert_state` by package and rule, so a cluster is reported the first time it
is seen and counted thereafter. Without that, a maintainer who adopted forty
packages overnight would be re-announced on every cycle until the metadata
changed again, and an operator learns to ignore a feed that repeats itself.

See [the CLI reference](../reference/cli.md#trustsight-full-aur) for the flags
and [the Class D rules](../reference/rules/system.md#class-d-rules) for what the sweep
can find.
