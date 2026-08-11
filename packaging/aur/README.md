# AUR packaging

Files for the `trustsight` AUR package. TrustSight audits its own updates, so
this PKGBUILD is held to the standard the tool enforces.

## Release checklist

The version here must match `pyproject.toml`. Steps that cannot be done ahead
of the release are marked.

1. Confirm `pkgver` matches `version` in `pyproject.toml`.
2. **After the release tag is pushed**, download the tarball and replace
   the placeholder checksum with the real hash:

   ```bash
   cd packaging/aur
   updpkgsums          # replaces the placeholder sha256sum
   makepkg --printsrcinfo > .SRCINFO
   ```

   The placeholder is a zeroed sha256 rather than `SKIP` on purpose: TrustSight
   reports a disabled checksum as R004 at HIGH severity, and shipping a package
   that trips its own rule would be indefensible. A zeroed checksum fails loudly
   at build time; `SKIP` fails silently at review time.

3. Verify the built package:

   ```bash
   makepkg -si
   trustsight --help
   ```

4. Push to the AUR repository.

## Dogfooding check

Scoring this PKGBUILD through TrustSight's own pipeline should yield 0/100 with
only credit signals:

```
score: 0/100
  -10 INFO  SOURCE_BUCKET  Trusted forge modifier (capped at -20)
   -5 INFO  PINNING        Source pinning: checksum_pinned (-5)
  -10 INFO  VERIFICATION   Verification evidence: checksum_present (-10)
```

If a change here introduces a rule firing, that is a signal about the change,
not about the tool.

## Dependency notes

`python-pygit2`, `python-rich`, `python-tldextract`, and
`python-cryptography` are all in the `extra` repository.
`pyalpm` (optional) is in the `community` repository (formerly AUR).
No AUR dependencies are required.

The novelty seed is no longer bundled inside the wheel; it is distributed as
the signed `baseline-seed.tar.gz` release asset. On the first run the tool
fetches and verifies it (mine with `trustsight seed fetch`), and on a
machine without network access the first run simply starts from a cold
database.
