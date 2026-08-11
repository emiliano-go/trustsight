# Seed Provenance

Where the novelty seed comes from, why trusting it used to be a circular
assumption, how to rebuild and audit it yourself, and how the release
channel signs it.

## What the seed is

The seed is a bundle of prior knowledge drawn from the whole AUR, published
on the [release channel](../reference/baseline-keys.md#the-release-channel) as `baseline-seed.tar.gz` and
imported into the user's database on first run (or manually with
`trustsight seed fetch`). Since v0.12 the shipped seed is the **v2 hashed
format**: a `trustsight-seed-v2/` directory of salted SHA-256 hashes, not a
SQLite file with plaintext values. Its three kinds of prior knowledge are:

- **source URLs** (about 180,000, normalised), with first-seen timestamps
  and use counts;
- **hashed maintainers**: salted hashes of maintainer names and emails, with
  package counts and first-seen timestamps, so no plaintext identity leaves
  the machine that builds the seed (invariant [P1](../security.md#the-invariants));
- **dependency names**: every dependency, package name and `provides` alias,
  with observation counts.

It exists because a cold database makes novelty meaningless: with an empty
`source_urls` table every URL, including github.com, is globally novel, and
with no analysis history `maturity()` returns 0, which gates the novelty tier
off and downgrades every Medium verdict to Inconclusive. The seed supplies the
bootstrap; real analyses take over as soon as they outnumber it. The mechanism
is described in [cold start and maturity](cold-start-and-maturity.md), and the
import commands in [`trustsight seed`](../reference/cli.md#trustsight-seed).

## How trust moved out of the package

Until v0.11 the seed shipped inside the package as
`src/trustsight/data/seed.db.gz`. The package is installed from the AUR,
which is the very channel TrustSight exists to audit; the trust anchor for
the tool's priors was therefore the thing under review, and that was circular.

The seed no longer lives in the package. It is built by the published
scripts, signed by a key held out-of-band (never in the repository), and
distributed through the release channel, which is not the AUR. At import time
the tool verifies the artifact's detached ed25519 signature against a public
key pinned in the source tree (`src/trustsight/full_aur/baseline_pubkey.pem`)
before it reads a byte; a download that does not verify is refused, never
imported. That is the same trust shape as the corpus baseline
([A13](../security.md#the-invariants)) and the IOC baselines
([A13b](../security.md#the-invariants)), and the key's fingerprint is in
[baseline keys](../reference/baseline-keys.md).

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

The release workflow [`.github/workflows/baselines.yml`](../../.github/workflows/baselines.yml)
runs this pipeline on every published release and uploads the `baseline-*`
assets, so the seed a fresh install fetches is the output of the published
scripts over a mirror reconstructed from the corpus lockfile.

## Auditing the shipped seed

The generator is deterministic against a fixed mirror: re-running it against
the same `aur.git` state produces the same data. The AUR moves, so a rebuild
weeks later will legitimately differ; equality is expected only against the
same mirror state. Two checks cover the two failure modes:

```bash
# 1. The release asset is signed by the pinned key (and is
#    unique to this release: no other seed has this digest).
trustsight seed fetch --json   # "status: ok" means the signature verified

# 2. It is the published script over the published input:
python scripts/generate_seed.py --out /tmp/seed-audit.db
# compare maintainers with --src/trustsight/seed-audit against a fresh build
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