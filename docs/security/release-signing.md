<!-- description: How TrustSight release artifacts are signed, which key signs them, how makepkg and users verify them, and how the key is rotated. -->

# Release Signing

A checksum alone binds a release to nothing: it lives in the same
`packaging/aur/PKGBUILD` that release automation owns, so anyone who can change
the artifact can change the checksum beside it. TrustSight therefore signs the
release tarball with a key that is **not available to CI**, and pins that key
in the PKGBUILD so `makepkg` and `yay` verify it on every user's machine.

## The key

The release tarball is signed with the maintainer's pinned commit-signing GPG
key. It is the same key that signs commits touching critical paths, and its
private half exists only on the maintainer's machine.

| Purpose | Algorithm | Fingerprint |
|---------|-----------|-------------|
| Commit and release signing | RSA 4096 (GPG) | `F759D6D49B0A395AB922414A5CC3B4C50D37E793` |

The public half is committed at `scripts/commit_signing_key.asc`, published on
[keys.openpgp.org](https://keys.openpgp.org/search?q=F759D6D49B0A395AB922414A5CC3B4C50D37E793),
and pinned in [`.SRCINFO`](https://github.com/emiliano-go/trustsight/blob/master/packaging/aur/.SRCINFO)
as `validpgpkeys`. This is a **different key** from the ed25519 baseline
distribution key in [baseline keys](../reference/baseline-keys.md): that one
signs the `baseline-*` channel assets and its private half is the
`BASELINE_SIGNING_KEY` Actions secret, while this one signs the software
release tarball and never enters CI.

## What is signed

Each software release carries a detached signature over the deterministic
source tarball:

- `trustsight-<version>.tar.gz.sig`: made with
  `gpg --detach-sign --local-user F759D6D4…!`, over the exact bytes of
  `trustsight-<version>.tar.gz`. The trailing `!` forces the primary key: the
  committed public key carries the primary and its encryption subkey, not the
  separate Ed25519 signing subkey, so a signature by that subkey would not
  verify against it.

The tarball is deterministic (`scripts/build_release_tarball.py`), so the
signature is known before the tag exists and ships in the same commit as the
version. `packaging/aur/PKGBUILD` declares the `.sig` as a source, pins the key
  in `validpgpkeys`, and records the signature's real `sha256`, never `SKIP`.

## Verifying a release

`makepkg` and `yay` verify the signature automatically when the key is in the
local keyring. Fetch it once:

```bash
gpg --recv-keys F759D6D49B0A395AB922414A5CC3B4C50D37E793
```

Then either let `makepkg` verify it as part of a build, or check it by hand:

```bash
gpg --verify trustsight-<version>.tar.gz.sig trustsight-<version>.tar.gz
```

CI proves the same thing without the private key. `publishing.yml` and
`release-pkgbuild.yml` import the committed public key and verify the
signature; `pkgbuild.yml` verifies it on a tagged tree and checks checksums
only on an untagged pre-release tree, where the deterministic tarball has
moved since the signature was made. `scripts/verify_release.py` refuses to pass
a release whose `.sig` does not verify against the pinned fingerprint. CI can
verify a signature it cannot produce, which is the point.

## Rotation

Rotation means cutting a release that pins a new key, with no in-band
revocation:

1. Generate a new keypair. Replace its public half in
   `scripts/commit_signing_key.asc`, the `validpgpkeys` fingerprint in
   `packaging/aur/PKGBUILD`, and this page's fingerprint row, in one commit.
   `scripts/commit_signing_key.asc` is a critical path, so the commit must be
   signed by the old key (or a new key already trusted by the policy).
2. Publish the new public key to keys.openpgp.org.
3. Sign the next release's tarball with the new key.

An unsigned or wrong-key release is not a warning: makepkg refuses to build it,
and the release workflows fail before publishing.
