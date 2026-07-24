# AUR packaging

Files for the `trustsight` AUR package. TrustSight audits its own updates, so
this PKGBUILD is held to the standard the tool enforces.

## Release checklist

The version here must match `pyproject.toml`. Steps that cannot be done ahead
of the release are marked.

1. Confirm `pkgver` matches `version` in `pyproject.toml`.
2. **After the release tag is pushed**, fill in the checksum:

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

`python-pygit2` and `python-rich` are in `extra`. `python-tldextract` and
`python-openai` come from the AUR, so this package pulls AUR dependencies:
acceptable for an AUR package, but worth stating since it affects install with
plain `makepkg`.

The bundled novelty seed (`src/trustsight/data/seed.db.gz`, ~12 MB) ships inside
the wheel, so the installed package includes it and the first run needs no
network access.
