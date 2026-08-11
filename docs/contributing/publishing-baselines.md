# Publishing Baselines

This is the maintainer workflow for building, signing, and publishing the
three baseline kinds TrustSight consumes. It ties together the reference
pages: the keys in [baseline keys](../reference/baseline-keys.md), the
`full-aur` command in the [CLI reference](../reference/cli.md#trustsight-full-aur),
the IOC format in [IOC federation](../reference/ioc.md), and the invariants
A13 / A13b / P1 in the [security model](../security.md).

## The release channel

Every baseline the tool consumes at runtime is distributed as a GitHub
release asset in the TrustSight repository, named with the `baseline-`
prefix, and **a baseline release ships the whole family**:

- `baseline-seed.tar.gz` (the v2 hashed novelty seed) plus `.sig`;
- `baseline-ioc-<source>-<incident>-manifest.json` and
  `baseline-ioc-<source>-<incident>-iocs.jsonl`, one pair per curated IOC
  input, each with its `.sig`;
- `baseline-corpus.tar.zst` (the corpus baseline) plus `.sig`;
- `baseline-manifest.json` (per-asset SHA-256, size and signature).

**Two release kinds, kept apart.** Software releases are tagged `vX.Y.Z`
and carry the program and its release notes, never baseline assets. Channel
releases are tagged `baseline-<date>` (for example `baseline-2026-08-10`)
and carry the `baseline-*` assets. A channel release is published **after**
its software release, so it becomes the repository's `latest` release and
the tool's default `/releases/latest/download/...` channel resolves to it
without any per-tag plumbing. The intended cadence: publish a software
release, then publish a fresh `baseline-<date>` right behind it whenever the
baselines need refreshing.

**Pinning.** The default channel follows `latest`, which moves the next time
a newer release is published. `trustsight seed fetch --tag baseline-2026-08-10`
pins a specific channel release, and `release.asset_url(name, tag)` resolves
it; keep the tag of the channel release you verified if you want a
reproducible seed.

`scripts/build_release_baselines.py` assembles and signs the family:
it takes the seed's `trustsight-seed-v2/` directory, the curated IOC inputs,
and the corpus artifact, signs every asset's exact bytes with the distribution
key, self-verifies every signature with the program's own verifier, and writes
the manifest. Every asset also gets a detached `.sig` sibling under the same
key; the tool refuses any download whose signature does not verify.

The seed and IOC assets are built and uploaded **automatically** by
[`.github/workflows/baselines.yml`](../../.github/workflows/baselines.yml),
which only runs for `baseline-*` releases and manual dispatch (software
releases skip it entirely). The seed is rebuilt from a mirror reconstructed
from the corpus lockfile; the mirror lives in the CI cache, so a cold cache
fails the job loudly rather than shipping an unverified or empty seed, and
the maintainer then uploads the locally built, self-verified assets to the
channel release (see below). The corpus baseline cannot be rebuilt from
nothing in CI: it is grown incrementally by `full-aur` runs on a maintainer
machine and is uploaded separately, as described below.

## Prerequisites: the signing key

Signed baselines verify against the ed25519 key pinned in the repo at
`src/trustsight/full_aur/baseline_pubkey.pem` (see
[baseline keys](../reference/baseline-keys.md) for its fingerprint). The private
key never enters the repository. For automated signing it lives in the GitHub
Actions secret `BASELINE_SIGNING_KEY` (a PEM file); for local signing keep a
raw 32-byte file and delete it afterwards, as the corpus-baseline example
below shows. The secret and a locally held key are the same key: assets must
verify against the key pinned in the release's source tree.

## The corpus baseline

### Grow it incrementally (recommended)

A corpus baseline is built from your local database's package profiles and
PKGBUILD snapshots, which `trustsight full-aur` accumulates. **The intended
cadence is incremental**, not one big bootstrap: with a metadata snapshot
present (any `trustsight review` run creates one), each cycle fetches only the
changed packages, which is gentle on the AUR and captures exactly the churn the
corpus-wide features care about.

```bash
# Run periodically (cron or a systemd timer). Each cycle only fetches the delta,
# is capped at [limits] corpus_max_per_cycle (default 2000), and resumes.
trustsight full-aur
```

The corpus is not committed and grows over time. When you want to publish a
snapshot of it, export and sign that run (next section).

### Bootstrap from scratch (only when you must)

A from-scratch bootstrap fetches every PKGBUILD in the AUR (~120k), which is a
lot of requests to a shared community host. It is gated behind `--bootstrap`
so a missing snapshot cannot trigger it by accident, and it is capped per cycle
and resumes, so you run the command repeatedly to finish it in chunks:

```bash
trustsight full-aur --bootstrap      # run again to continue each capped chunk
```

The fetcher enforces a global rate cap (~5 requests/second) and backs off on
`429`/`5xx`/connection resets, but a full bootstrap is still hours of
rate-limited fetching. Prefer growing incrementally.

### Export, sign, attach to the release

Exporting runs a cycle and, when it completes the current transition, writes the
signed artifact:

```bash
trustsight full-aur --export baseline-corpus.tar.zst --sign ~/trustsight-release.raw
```

Convert your PEM once and keep the raw key out of the repo:

```bash
python -c '
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
p = load_pem_private_key(Path.home().joinpath("trustsight-release.pem").read_bytes(), password=None)
Path.home().joinpath("trustsight-release.raw").write_bytes(p.private_bytes_raw())
'
chmod 600 ~/trustsight-release.raw
```

Attach it to the **channel** release (tag `baseline-<date>`, not the software
tag), keeping the `baseline-` prefix:

```bash
gh release upload baseline-2026-08-10 dist/baseline-corpus.tar.zst dist/baseline-corpus.tar.zst.sig
```

```bash
python scripts/build_release_baselines.py --out dist/ \
    --sign-key ~/trustsight-release.raw --corpus baseline-corpus.tar.zst
gh release upload baseline-2026-08-10 dist/baseline-corpus.tar.zst dist/baseline-corpus.tar.zst.sig
shred -u ~/trustsight-release.raw   # the raw key is deleted when you are done
```

`scripts/build_release_baselines.py` adds the transport-level `.sig` (the
artifact already carries its own internal signature over
`canonical_artifact_bytes`); the manifest it writes records the SHA-256.

### Verify before publishing

Verify the artifact imports and its signature checks against the pinned key,
on a throwaway database so your real one is untouched:

```bash
python -c '
import tempfile; from pathlib import Path
import trustsight.db as db, trustsight.config as cfg
d = Path(tempfile.mkdtemp()); db.DATA_DIR = cfg.DATA_DIR = d; db.init_db()
from trustsight.full_aur.export import import_baseline
import_baseline("baseline-corpus.tar.zst", allow_unsigned=False)
print("OK: signature verified against the pinned key")
'
```

`allow_unsigned=False` succeeding is the proof: the artifact verifies against
the key shipped in the build, so every user on this release trusts it. A
`NoTrustedKeyError` means this build pins no key; an `InvalidSignatureError`
means the key does not match. The same throwaway-database check works for the
`.sig` files:

```bash
python -c '
from pathlib import Path
import trustsight.release as release
data = Path("baseline-corpus.tar.zst").read_bytes()
sig = Path("baseline-corpus.tar.zst.sig").read_bytes()
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from trustsight.full_aur.export import _load_trusted_pubkey
key = _load_trusted_pubkey(release.PINNED_PUBKEY_PATH)
Ed25519PublicKey.from_public_bytes(key).verify(sig, data)
print("OK: detached signature verified")
'
```

## IOC baselines

IOC baselines are curated, primary-sourced indicator lists, built into signed
pairs with `scripts/build_ioc_baseline.py`. **Do not invent indicators**: an
IOC match is stated to the user as attribution, so a wrong or fabricated
entry is worse than none. The entry format and the curation workflow are in
[`data/iocs/README.md`](https://github.com/emiliano-go/trustsight/blob/master/data/iocs/README.md)
and [IOC federation](../reference/ioc.md).

```bash
# Curate data/iocs/<incident>.json from primary sources. Provide it to the
# release build script, which signs each manifest with the curator key
# (--ioc-sign-key, defaulting to the distribution key) and adds the
# distribution signature on top, or build the directory form yourself:
python scripts/build_ioc_baseline.py \
    --from-file data/iocs/<incident>.json \
    --source <curator> \
    --incident <incident> \
    --out ioc-baselines/<incident> \
    --sign ~/trustsight-release.raw
```

The release workflow signs and uploads the IOC assets automatically from
every curated `data/iocs/*.json` (it skips `example.json`). Because the
assets are named `baseline-ioc-<source>-<incident>-manifest.json` and
`baseline-ioc-<source>-<incident>-iocs.jsonl`, an operator who wants
`trustsight ioc update` to fetch them sets a feed with `name` (or `asset`)
equal to `<source>-<incident>` and `url` pointing at the release channel;
see [configuration](../reference/configuration.md#baselinesiocfeeds).

## Rotation and hygiene

- The private key is held by the maintainer only (and, for automated
  signing, the `BASELINE_SIGNING_KEY` Actions secret). Rotation means cutting
  a release that pins a new public key in `baseline_pubkey.pem`; there is no
  in-band revocation.
- Never commit the PEM or raw private key. Delete the raw key after signing.
- A baseline supplies **state, not rules** (A13): it cannot change a rule, a
  pattern, a weight, or a threshold, and importing one you did not build is an
  explicit act of trust the importer records.