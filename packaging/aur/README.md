# AUR packaging

Files for the `trustsight` AUR package, which is maintained by this project.
TrustSight audits its own updates, so this PKGBUILD is held to the standard
the tool enforces.

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

`sha256sums` is never `SKIP`. TrustSight reports a disabled checksum as H001
at HIGH severity, and shipping a package that trips its own rule would be
indefensible. The signature entry carries its real hash too; a `SKIP` there
would only save bookkeeping while handing the rule its one exemption.

The tarball is also **signed**. The detached signature
`trustsight-<ver>.tar.gz.sig` is made locally with the pinned commit-signing
key (`validpgpkeys` in the PKGBUILD), whose private half is never available to
CI and is not in this repository. With the signature, compromising the GitHub
account, a token or the release workflow is not enough to publish a forged
artifact: the attacker also needs the offline key. `validpgpkeys` plus the
`.sig` source make makepkg and yay verify it on every user's machine.

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

3. Sign the tarball with the pinned key and read both hashes. The signature
   is made here, on the maintainer's machine, never in CI:

   ```bash
   # The trailing `!` forces the primary key; without it GPG picks the
   # Ed25519 signing subkey, which the committed public key does not carry.
   gpg --detach-sign --local-user F759D6D49B0A395AB922414A5CC3B4C50D37E793! \
     dist/trustsight-<ver>.tar.gz
   cp dist/trustsight-<ver>.tar.gz.sig packaging/aur/
   sha256sum dist/trustsight-<ver>.tar.gz packaging/aur/trustsight-<ver>.tar.gz.sig
   ```

4. Record both hashes here, keep `validpgpkeys` and the `.sig` source, and
   regenerate the metadata. This commit touches only `packaging/`, so it
   cannot change the hashes from steps 2-3:

   ```bash
   cd packaging/aur
   # set sha256sums=('<tarball-hash>' '<signature-hash>')
   makepkg --printsrcinfo > .SRCINFO
   ```

5. Verify locally before publishing anything:

   ```bash
   makepkg -si
   trustsight --help
   ```

   `check()` runs the shipped suite but excludes `tests/test_fetcher.py` and
   `tests/test_rebaseline.py`.

6. Tag, push, and publish the release **with the tarball and its `.sig`
   attached**. The tag must point at the commit that carries the checksum
   recorded in step 4, and must be signed:

   ```bash
   git tag -s v<ver> -m "v<ver>"
   git push origin master && git push origin v<ver>
   gh release create v<ver> --title v<ver> --notes-file <notes> \
     dist/trustsight-<ver>.tar.gz dist/trustsight-<ver>.tar.gz.sig
   ```

   The assets must be the files from steps 2 and 3. `release-pkgbuild.yml`
   rebuilds the tarball from the tag, verifies the published `.sig` against
   the pinned key, and fails the release if either does not match.

7. Push to the AUR repository.

## Building a checkout instead

This recipe pins a published tarball, so it downloads the sources even when
you already cloned them. To build the tree you cloned, offline, use the local
recipe instead:

```bash
cd packaging/local
makepkg -si
```

It takes no `source`, derives `pkgver` from `git describe`, and builds the
parent checkout in place.

## Dogfooding check

Scoring this PKGBUILD through TrustSight's own pipeline should yield 0/100 with
only declared-practice findings:

```
score: 0/100
    0 INFO  P007  source hosted on a trusted forge over HTTPS
    0 INFO  P001  checksums declared for all non-VCS sources
```

If a change here introduces a rule firing, that is a signal about the change,
not about the tool.

## Dependency notes

`python-pygit2`, `python-rich`, `python-tldextract`, and
`python-cryptography` are all in the `extra` repository.
`pyalpm` is optional; install the distribution package that provides it when
native version comparison is desired.
No AUR dependencies are required.

The novelty seed is no longer bundled inside the wheel; it is distributed as
the signed `baseline-seed.tar.gz` release asset. `trustsight seed fetch` fetches
and verifies it explicitly. The only automatic release-channel fetch is the
first seed import performed by `trustsight review` or `trustsight inspect`
when `seed.auto_import` is enabled; `trustsight ioc update` is the other
eligible release-fetch command. On a machine without network access, an
eligible seed import starts from a cold database.
