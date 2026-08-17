# AUR packaging

Files for the `trustsight` AUR package. TrustSight audits its own updates, so
this PKGBUILD is held to the standard the tool enforces.

## Where the tarball comes from

`source=` points at a **release asset**, not at GitHub's
`/archive/refs/tags/` tarball. Two reasons, both of which have cost a release:

- GitHub generates the archive tarball on demand and does not guarantee its
  bytes. The gzip settings behind it have changed before and invalidated
  recorded checksums across every distribution at once. A release asset is an
  immutable blob; nobody regenerates it.
- The archive cannot exist until the tag does, so its checksum could only be
  recorded *after* tagging, by a second commit. Between those two commits the
  PKGBUILD named a new `pkgver` beside the previous release's checksum, and
  when that repair commit failed in v0.13.1 the branch stayed broken until a
  user reported it.

The asset is built by `scripts/build_release_tarball.py`, which is
deterministic: mtimes, uid/gid and member order are normalised, gzip is given
no timestamp, and the output depends only on the paths and contents that
`git archive` selects. Because `packaging/` is `export-ignore`d, writing the
checksum into this PKGBUILD cannot change the tarball that checksum
describes. That is what makes a pre-tag checksum possible at all.

`sha256sums` is never `SKIP`. TrustSight reports a disabled checksum as R004
at HIGH severity, and shipping a package that trips its own rule would be
indefensible.

## Release checklist

Every step happens **before** the tag. Nothing is repaired afterwards.

1. Land all content changes, including `version` in `pyproject.toml`. The
   version is inside the tarball, so it must be final before the next step.

2. Build the tarball and read its checksum:

   ```bash
   python scripts/build_release_tarball.py
   # dist/trustsight-<ver>.tar.gz
   # sha256 <hash>
   ```

3. Record that hash here and regenerate the metadata. This commit touches
   only `packaging/`, so it cannot change the hash from step 2:

   ```bash
   cd packaging/aur
   sed -i "s/^sha256sums=.*/sha256sums=('<hash>')/" PKGBUILD
   makepkg --printsrcinfo > .SRCINFO
   ```

4. Verify locally before publishing anything:

   ```bash
   makepkg -si
   trustsight --help
   ```

   `check()` runs the shipped suite but excludes `tests/test_fetcher.py` and
   `tests/test_rebaseline.py`.

5. Tag, push, and publish the release **with the tarball attached**:

   ```bash
   git tag -a v<ver> -m "v<ver>"
   git push origin master && git push origin v<ver>
   gh release create v<ver> --title v<ver> \
     --notes-file <notes> dist/trustsight-<ver>.tar.gz
   ```

   The asset must be the file from step 2. `release-pkgbuild.yml` rebuilds
   the tarball from the tag and fails the release if it does not match both
   the recorded checksum and the published asset.

6. Push to the AUR repository.

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
the signed `baseline-seed.tar.gz` release asset. `trustsight seed fetch` fetches
and verifies it explicitly. The only automatic release-channel fetch is the
first seed import performed by `trustsight inspect` when `seed.auto_import` is
enabled; `trustsight ioc update` is the other eligible release-fetch command.
Analysis itself never fetches release assets. On a machine without network
access, an eligible seed import starts from a cold database.
