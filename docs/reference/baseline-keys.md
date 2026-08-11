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
[release baseline workflow](../../.github/workflows/baselines.yml) reads to
sign the `baseline-*` assets at release time. Rotation means cutting a release
that pins a new public key; there is no in-band revocation.

### The release channel

Every baseline the tool consumes at runtime is distributed as a release asset
named with the `baseline-` prefix, and **a channel release** (tag
`baseline-<date>`) ships the whole family. Channel releases are kept apart
from software releases: a `vX.Y.Z` tag carries the program and its notes,
never baseline assets, and a channel release is published after its software
release so `latest` (the tool's default channel) resolves to it; the
[publishing guide](contributing/publishing-baselines.md) documents the
cadence and `seed fetch --tag` for pinning.

| Asset | What it is | Consumed by |
|-------|-----------|-------------|
| `baseline-seed.tar.gz` | the v2 hashed novelty seed | `trustsight seed fetch`, first-run auto-import |
| `baseline-ioc-<source>-<incident>-manifest.json` | one IOC baseline's signed manifest (carries the curator key) | `trustsight ioc update` |
| `baseline-ioc-<source>-<incident>-iocs.jsonl` | the corresponding indicator list | `trustsight ioc update` |
| `baseline-corpus.tar.zst` | the corpus baseline artifact | downloaded and imported with `trustsight import-baseline` |
| `baseline-manifest.json` | per-asset SHA-256, size and signature, plus the public key used | release inventory |

Every asset ships with a detached `.sig` sibling: the raw 64-byte Ed25519
signature over the **exact asset bytes**, under the pinned distribution key.
The tool verifies that signature before it reads the payload, so a download
that does not verify is refused (`ReleaseSignatureError`), never imported.
`scripts/build_release_baselines.py` assembles and signs the family, and
self-verifies every signature with the program's own verifier before it
writes, so it cannot emit a release the tool would refuse.

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

# public: PEM -> the 32 raw bytes pinned in the repo
pub = load_pem_public_key(Path("baseline_pubkey.pem").read_bytes())
Path("src/trustsight/full_aur/baseline_pubkey.pem").write_bytes(pub.public_bytes_raw())

# private (kept outside the repo): PEM -> the 32 raw bytes `--sign` expects
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

## IOC federation baselines (A13b): per-source keys in config

IOC baselines are **not** verified against the repo-pinned key. Each IOC baseline
carries its curator's public key in its own `manifest.json`, and the operator
pins the public key they trust for each feed in configuration (see
[`[baselines.ioc]`](configuration.md#baselinesioc) and the
[IOC federation reference](ioc.md)). This is what keeps IOC matches attributable
per curator and lets one curator's key rotate without touching another's. The
maintainer may use the same ed25519 keypair as the corpus baseline above, but the
two verification paths are independent (and a released IOC pair additionally
carries the distribution signature of the pinned repo key, checked before the
curator's own signature is consulted).

## Not the PGP disclosure key

The ed25519 baseline key here is distinct from the PGP key used for private
[vulnerability reporting](../security.md#how-to-report)
(`F759D6D49B0A395AB922414A5CC3B4C50D37E793`). One signs release artifacts; the
other encrypts security reports. They are not interchangeable.
