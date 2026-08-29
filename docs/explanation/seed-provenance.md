<!-- description: Where the novelty seed comes from, why its trust anchor sits outside the AUR, and how to rebuild, audit and verify it against the pinned signing key. -->

# Seed Provenance

Where the novelty seed comes from, why its trust anchor is kept outside the
AUR, how to rebuild and audit it yourself, and how the release channel signs
it.

## What the seed is

The seed is a bundle of prior knowledge drawn from the whole AUR, published
on the [release channel](../reference/baseline-keys.md#the-release-channel) as `baseline-seed.tar.gz` and
imported into the user's database on first run (or manually with
`trustsight seed fetch`). The shipped seed is the **v2 hashed format**: a
`trustsight-seed-v2/` directory of salted SHA-256 hashes rather than a SQLite
file of plaintext values. Its three kinds of prior knowledge are:

- **source URLs** (179,956, normalised), with first-seen timestamps
  and use counts;
- **hashed maintainers**: salted hashes of maintainer names and emails, with
  package counts and first-seen timestamps, so no plaintext identity leaves
  the machine that builds the seed (invariant [P1](../security.md#the-invariants));
- **dependency names**: 209,909 dependency names, package names and `provides`
  aliases, with observation counts.

It exists because a cold database makes novelty meaningless: with an empty
`source_urls` table every URL, including github.com, is globally novel, and
with no analysis history `maturity()` returns 0, which gates the novelty tier
off and downgrades every Medium verdict to Inconclusive. The seed supplies the
bootstrap; real analyses take over as soon as they outnumber it. The mechanism
is described in [cold start and maturity](cold-start-and-maturity.md), and the
import commands in [`trustsight seed`](../reference/cli.md#trustsight-seed).

## Why trust sits outside the package

The seed does not ship inside the package. A seed carried in the AUR package
would take its trust anchor from the very channel TrustSight exists to audit,
which is circular: the priors used to judge the AUR would themselves have been
installed from it.

Instead the seed is built by the published scripts, signed by the centralized
distribution key held out-of-band (never in the repository), and distributed
through the release channel, which is not the AUR. At import time
the tool downloads the bounded artifact bytes, then verifies their detached
ed25519 signature against a public key pinned in the source tree
(`src/trustsight/full_aur/baseline_pubkey.pem`) before parsing or importing
them; a download that does not verify is refused. That is the same trust shape
as the corpus baseline
([A13](../security.md#the-invariants)) and the IOC baselines
([A13b](../security.md#the-invariants)), and the key's fingerprint is in
[baseline keys](../reference/baseline-keys.md).

The same pinned key authenticates all release-channel baseline assets. This
centralizes trust: compromise of that key can authorize a hostile seed until an
operator installs a software release pinning a replacement key; there is no
in-band revocation for installed versions. The response and rotation procedure
is in [Publishing Baselines](../contributing/publishing-baselines.md#key-compromise-and-rotation).

On machines without a network connection the seed is simply absent: the
first run degrades to cold start, which is the honest fallback for an
instrument that refuses unverified data. Importing a seed you built yourself
with `--file` remains supported.

## What a hostile seed can and cannot do

The bound on the damage is invariant
[A12](../security.md#the-invariants), enforced by the
`a seed cannot rewrite the database` gate against `db.import_seed`:

- The import is **additive and idempotent**. Every merge uses `INSERT OR
  IGNORE` (or its equivalent), so a row learned from a real analysis always
  wins. A seed can never overwrite local history.
- A seed may set **only the two metadata keys it owns**
  (`seed_observation_count`, `seed_version`). It cannot touch rules, patterns,
  severities, weights, thresholds, or any other metadata key.
- It **cannot raise a locally learned maintainer count** - the merge is `OR
  IGNORE`, not `OR REPLACE`, precisely because an inflated count would
  suppress the new-maintainer rules.
- It **cannot raise a score**. Making a URL, maintainer or dependency look
  familiar only ever *lowers* novelty flags. The worst case is a quieter
  report, never a louder one, and never a fabricated finding.

So even a hostile or forged seed cannot fabricate evidence, cannot rewrite
what the tool has learned, and cannot reach outside its own tables. What it
*can* do is hide novelty: pre-seed an attacker's URL or maintainer as
long-established, and the corresponding flags go quiet. The signature narrows
who can build such a seed to whoever holds the out-of-band key; the
additivity bound is what keeps even a signed seed from doing damage.

## How the seed is built

The build is a three-step pipeline. Everything it consumes is public AUR
data, and everything it does is in scripts in the repository.

**Step 1: obtain the AUR mirror.** The seed is read out of a bare clone of the
AUR monorepo at `~/.cache/trustsight/aur.git`. `scripts/build_corpus.py`
creates this mirror as a side effect (it clones
`https://github.com/archlinux/aur.git`), or you can create it directly:

```bash
git clone --bare https://github.com/archlinux/aur.git ~/.cache/trustsight/aur.git
```

**Step 2: collect the raw maintainer data.** `scripts/generate_seed.py` walks
every branch of the mirror (one branch per package, about 116,000 of them)
and reads the `.SRCINFO` and `PKGBUILD` blobs straight out of the git object
database at each branch tip, reusing the runtime's own normalisers so the
seed and the query time agree. From each package it takes source URLs,
dependency names, and the maintainer (read with the same
`fetcher.extract_maintainer()` the running tool uses), and writes them into
the fixed schema declared in the script.

**Step 3: hash and package.** `scripts/build_hashed_seed.py` converts the raw
maintainer records into the v2 hashed format, then
`scripts/build_release_baselines.py` repackages the `trustsight-seed-v2/`
directory as `baseline-seed.tar.gz` and signs its exact bytes with the
distribution key, writing the detached `baseline-seed.tar.gz.sig` used at
import.

Every build records its inputs: `generate_seed.py --provenance-out` writes
`seed-provenance.json` (the source mirror path and on-disk size, the package,
maintainer and observation counts, the UTC build timestamp, and the exact
command line), and `build_hashed_seed.py --provenance` ships it inside the
archive as `trustsight-seed-v2/seed-provenance.json`. It is metadata about
the build, never part of the hashed content, and it is what lets a third
party reproduce the seed and compare their record against the published one.

The release workflow [`.github/workflows/baselines.yml`](https://github.com/emiliano-go/trustsight/blob/master/.github/workflows/baselines.yml)
runs this pipeline against a draft channel release (a `baseline-<date>` tag,
published only after its complete asset family is verified; see the
[publishing guide](../contributing/publishing-baselines.md)). The canonical
seed is built by the maintainer from the full AUR mirror; CI rebuilds only
when the release has no `baseline-seed.tar.gz` yet, from a mirror
reconstructed from the corpus lockfile. The fallback is auditable but smaller
than the canonical full-mirror seed, and never overwrites an uploaded one.

The gap is not cosmetic. The lock is a calibration corpus, not a sample of
the AUR: a seed built from the lock (3,246 packages) contains about 137
distinct maintainers, while the canonical seed built from the full AUR
mirror (about 116,000 package branches) contains about 35,903. Shipping the
lock-derived seed would reduce novelty coverage by 99.6%, flagging
experienced maintainers as new on every package outside the lock. That is
why the canonical seed is always the one a fresh install fetches, and why
the CI fallback exists only to keep a release shippable, never as a
substitute for the maintainer-built seed.
`trustsight seed fetch --tag baseline-<date>` pins the exact channel release
instead of following `latest`.

## Auditing the shipped seed

The generator is deterministic against a fixed mirror: re-running it against
the same `aur.git` state produces the same data. The AUR moves, so a rebuild
weeks later will legitimately differ; equality is expected only against the
same mirror state. Two checks cover the two failure modes:

```bash
## 1. The release asset is signed by the pinned key (and is
##    unique to this release: no other seed has this digest).
trustsight seed fetch --json   # "status: ok" means the signature verified

## 2. It is the published script over the published input:
python scripts/generate_seed.py --out /tmp/seed-audit.db \
  --provenance-out /tmp/seed-audit-provenance.json
## then diff your seed-provenance.json against the published one: the same
## mirror state must produce the same package, maintainer and observation
## counts.
```

The schema itself is auditable in one read: it is the `SCHEMA` literal at the
top of `scripts/generate_seed.py`, and `sqlite3 /tmp/seed-audit.db .schema`
shows exactly what a seed is allowed to contain. The hashing normalisation
(the `.strip().lower()` chokepoint) is `seed_build._hash_value`, and
`db._hash_maintainer_value` delegates to it, so the seed and the runtime
cannot drift apart.

## What is recorded at import time

`db.import_seed()` hashes the artifact **as delivered** - the exact bytes
whose signature was verified - and writes it into the user database's
`metadata` table:

- `seed_sha256`: the SHA-256 of the imported artifact;
- `seed_origin`: `bundled` when imported from the packaged location,
  otherwise the path it was imported from.

Both are queryable after the fact:

```bash
sqlite3 ~/.local/share/trustsight/trustsight.db \
  "SELECT key, value FROM metadata WHERE key LIKE 'seed_%';"
```

Be precise about what this buys. The digest is **attribution, not
authentication**: it lets the database answer "where did these priors come
from", and it lets you compare what was imported against an artifact you built
or obtained independently. Authentication is the signature check that runs
before the import; the digest records which exact artifact was trusted.
