<!-- description: The ed25519 public keys TrustSight verifies signed baselines against, the two distinct signing mechanisms, and the fingerprints recorded for each. -->

# Baseline Keys

TrustSight verifies signed baselines against ed25519 public keys. There are two
distinct mechanisms, and this page records the keys for each.

## Corpus baseline (A13): repo-pinned key

The corpus baseline (package profiles, PKGBUILD snapshots, and the metadata
snapshot that feed the novelty and maturity models) is verified against a single
key pinned in the repository at `src/trustsight/full_aur/baseline_pubkey.pem`.
The file holds the **32 raw bytes** of the public key, not a PEM wrapper, because
that is what the loader reads.

| Purpose | Algorithm | Fingerprint (`sha256` of the raw public key) | Since |
|---------|-----------|-----------------------------------------------|-------|
| Corpus baseline distribution | Ed25519 | `sha256:6000c216fc85e4efd523a47b6399ec781f05539f33536ac75799775496f41928` | v0.12.0 |

Raw public key (hex): `3bc5a24d09072c4aed2165f29d5a8fd42aeacb9f96962c12eccde64c79786210`

The **private key never enters the repository**. It is held by the maintainer
and, since the release channel exists, is also placed in the GitHub Actions
secret `BASELINE_SIGNING_KEY`, which the
[release baseline workflow](https://github.com/emiliano-go/trustsight/blob/master/.github/workflows/baselines.yml) reads to
sign the `baseline-*` assets at release time. Rotation means cutting a release
that pins a new public key; there is no in-band revocation.

### Rotation drill

1. Generate a new ed25519 keypair, replace
   `src/trustsight/full_aur/baseline_pubkey.pem` and this page's fingerprint
   and raw-hex rows in the same commit, and land it with a signed commit
   (the key file is a critical path).
2. Replace the `BASELINE_SIGNING_KEY` Actions secret with the new private
   key.
3. Cut a channel release (`baseline-<date>`) signed with the new key. Old
   baselines stop verifying the moment a release pins the new key, so every
   asset the channel serves is republished.
4. The signed manifest carries `distribution_pubkey` (the raw key as hex), and
   import refuses a manifest that names a key other than the pinned one. The
   runtime authority is always the pinned file; the manifest field is the
   publish job's statement that it signed with that key.

The fingerprint test in `tests/test_security_model.py` asserts the shipped
bytes, the documented fingerprint and the documented raw hex all agree, so a
key swap cannot be silent.

### The release channel

Every baseline the tool consumes at runtime is distributed as a release asset
named with the `baseline-` prefix. **A baseline channel release** (tag
`baseline-<date>`) ships the bulk family (the seed, the corpus and the
inventory), and **a dedicated IOC channel release** (tag `ioc-<date>`) ships
only the IOC pairs so a time-sensitive indicator set can be republished without
a full baseline cut. Both are kept apart from software releases: a `vX.Y.Z` tag
carries the program and its notes, never baseline assets.

The tool discovers the newest asset-bearing release per channel through the
GitHub API: the seed and corpus resolve the newest `baseline-*` release, and the
IOC pairs resolve the newest `ioc-*` release. The two namespaces never mix; a
seed or corpus fetch matches only `baseline-*`, so it can never be pointed at an
`ioc-*` release. When the API is unreachable the configured fallback is used,
[`[seed] baseline_tag`](configuration.md#seed) for the baseline family and
[`[baselines.ioc] tag`](configuration.md#baselinesioc) for the IOC pairs; the
IOC pairs live only on `ioc-*` releases, so with no fallback and no reachable
`ioc-*` release the fetch refuses rather than reaching for a baseline copy.
Discovery and fallback both refuse rather than guess. `latest` is never the
fallback: it is a `v*` release and carries no baseline assets. The
[publishing guide](../contributing/publishing-baselines.md) documents the
cadence and `seed fetch --tag` for pinning.

| Asset | What it is | Consumed by |
|-------|-----------|-------------|
| `baseline-seed.tar.gz` | the v2 hashed novelty seed | `trustsight seed fetch`, first-run auto-import |
| `baseline-ioc-<source>-<incident>-manifest.json` | one IOC baseline's signed manifest (carries the curator key) | `trustsight ioc update` |
| `baseline-ioc-<source>-<incident>-iocs.jsonl` | the corresponding indicator list | `trustsight ioc update` |
| `baseline-corpus.tar.zst` | the corpus baseline artifact | downloaded and imported with `trustsight import-baseline` |
| `baseline-manifest.json` | per-asset SHA-256, size and signature, plus the monotonic release `version`, optional `expires_at` and the public key used | release inventory |

The seed, corpus and `baseline-manifest.json` live only on a `baseline-<date>`
release; the IOC pairs live only on an `ioc-<date>` release.

Every asset ships with a detached `.sig` sibling: the raw 64-byte Ed25519
signature over the **exact asset bytes**, under the pinned distribution key.
The signed `baseline-manifest.json` binds each asset's name, SHA-256 and size
to a monotonic `version` and an optional `expires_at`. A seed or corpus pull
verifies the asset against that inventory, refuses an expired manifest, and
refuses a `version` lower than the one already imported. A release that
predates the inventory is accepted as unknown; the next versioned release
becomes the floor.
The bounded asset bytes must be downloaded before that signature can be
verified; verification then happens before the payload is parsed, imported, or
used. A download that does not verify is refused (`ReleaseSignatureError`).
`scripts/build_release_baselines.py` assembles and signs the family, and
self-verifies every signature with the program's own verifier before it
writes, so it cannot emit a release the tool would refuse.

### Following another channel

The official channel (`emiliano-go/trustsight`) is the default and is verified
against the distribution key pinned in the package. To follow a different
publisher, set [`[release] channel`](configuration.md#release) to an
`owner/repo` slug and pin that publisher's ed25519 key in
[`[release] key`](configuration.md#release) (64 hex characters or a path to a
raw key file); `seed fetch --channel owner/repo` and
`corpus fetch --channel owner/repo` do the same for one run. The key is the
whole trust decision: a non-official channel is verified against *its* key, and
a non-official channel with no pinned key is refused rather than verified
against the official key. Every import from a non-official channel prints a
warning naming the channel and its key fingerprint, so trusting a third party
is never silent.

### Building and importing a signed corpus baseline

Signing is built into the exporter, so there is no separate build script:

```
trustsight full-aur --export corpus.tar.zst --sign <raw-ed25519-private-key>
python scripts/build_release_baselines.py --out dist/ --sign-key <raw-key> --corpus corpus.tar.zst
gh release upload <tag> dist/baseline-*
```

Both keys the tooling reads are **raw 32-byte** ed25519 keys, not PEM. An
`openssl`-generated PEM is converted once with the `cryptography` library:

```python
from pathlib import Path
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
)

## public: PEM -> the 32 raw bytes pinned in the repo
pub = load_pem_public_key(Path("baseline_pubkey.pem").read_bytes())
Path("src/trustsight/full_aur/baseline_pubkey.pem").write_bytes(pub.public_bytes_raw())

## private (kept outside the repo): PEM -> the 32 raw bytes `--sign` expects
priv = load_pem_private_key(Path("trustsight-release.pem").read_bytes(), password=None)
Path("trustsight-release.raw").write_bytes(priv.private_bytes_raw())  # never commit this
```

The signature covers `full_aur/export.canonical_artifact_bytes` (a canonical JSON
of the manifest fields, sorted profiles and snapshots, and the metadata snapshot
hash), verified by `verify_artifact` against the pinned key. A baseline you built
yourself but did not sign still imports with `--allow-unsigned`; a build that
ever pins a non-key file refuses with `NoTrustedKeyError` rather than reporting a
valid artifact as forged. Distribution signing of the released `.tar.zst` bytes
(the detached `.sig` sibling) is a second, transport-level check on top of the
artifact's own internal signature.

## IOC federation baselines (A13b): manifest-carried per-source keys

IOC baselines are **not** verified against the repo-pinned corpus key at import.
Each IOC baseline carries its curator's public key in its own `manifest.json`;
the importer verifies that manifest and its `iocs.jsonl` against the carried
key. The key is therefore manifest-carried, not configuration-pinned. This keeps
matches attributable per curator and lets one curator rotate a key without
changing another baseline. A released IOC pair additionally carries a
distribution signature under the pinned repo key, checked before the curator's
own signature is consulted.

## Not the PGP disclosure key

The ed25519 baseline key here is distinct from the PGP key used for private
[vulnerability reporting](../security.md#how-to-report)
(`F759D6D49B0A395AB922414A5CC3B4C50D37E793`). One signs release artifacts; the
other encrypts security reports. They are not interchangeable.
