<!-- description: How a TrustSight version reaches users: the source tarball this repository builds, the PKGBUILD that consumes it, and the checks that gate a tag. -->

# Releasing

How a TrustSight version reaches users, and why the source tarball is built
here rather than taken from GitHub.

## The source is a release asset, not a generated archive

`packaging/aur/PKGBUILD` fetches a tarball this repository builds and attaches
to the release. It deliberately does **not** use
`https://github.com/.../archive/refs/tags/vX.tar.gz`.

Two failures drove that, and both reached users:

**The bytes are not ours.** GitHub generates the archive tarball on demand and
does not guarantee it is stable. The gzip settings behind it have changed
before, invalidating recorded checksums across every distribution at once. A
package whose integrity check depends on a file somebody else regenerates is
not pinned, it is hoping. A release asset is an immutable blob; nothing
regenerates it.

**The ordering is impossible.** A generated archive cannot exist until the tag
does, so its checksum can only be recorded *after* tagging, by a second commit.
Between those two commits the PKGBUILD names a new `pkgver` beside the previous
release's checksum. That window opens on every release, and it stays open for
as long as the repair step takes, and permanently if the repair step fails.

## The determinism contract

`scripts/build_release_tarball.py` builds the tarball as a pure function of the
paths and contents `git archive` selects. Anything that varies between builds
is removed:

- Every member mtime is rewritten to a fixed epoch. `git archive` otherwise
  stamps members with the *commit* date, which would move the checksum on
  every commit.
- `uid`, `gid`, `uname` and `gname` are zeroed, so the builder's account
  cannot leak into the artifact.
- Members are written in sorted order rather than tree order.
- gzip is given `mtime=0` and no filename field. The default embeds the
  current time.

The property that makes a pre-tag checksum possible: `packaging/` is
`export-ignore`d by `.gitattributes`, so **writing the checksum into the
PKGBUILD cannot change the tarball that checksum describes**. Without that
exclusion the whole thing would be circular. `dist/` is gitignored for the
same reason, so a built artifact never lands inside the next one.

## One ordering rule

The checksum is computed **last**, after every other change is final.

Anything outside `packaging/` is inside the tarball, including
`pyproject.toml`, the tests and this page. Editing any of it after hashing
invalidates the recorded value. The script therefore archives the **working
tree** by default rather than `HEAD`, because the content being released is
what is in the tree now, not what the previous commit held:

```bash
python scripts/build_release_tarball.py            # working tree
python scripts/build_release_tarball.py --rev v0.13.2
python scripts/build_release_tarball.py --check <sha256>
```

Archiving the working tree means staging it, and staging is `git add -A`, which
takes everything the ignore rules do not exclude. A scratch file left in the
checkout is untracked, unignored, and would therefore ship inside the release
archive with a checksum that describes it. The working-tree mode refuses to run
while any untracked file is present and names what it found:

```
refusing to build a release tarball from a tree with untracked files:
  scratch/
`git add` what belongs in the release, delete or ignore what does not, or pass
--rev to archive a committed revision.
```

Being in the index is the statement that a new file belongs in the release, so
add the ones that do before computing the checksum. `--rev` archives a committed
revision and is unaffected.

`tests/test_pkgbuild.py::test_recorded_checksum_matches_the_recorded_version`
rebuilds the tarball and compares it against the recorded value, so a stale
checksum cannot be committed at all. `tests/test_release_workflow.py::test_a_worktree_build_refuses_untracked_files`
covers the refusal.

## Prerequisites

One-time setup, or changes rarely. The guide below assumes all of it holds.

- **The signing key.** The maintainer holds the private half of
  `F759D6D49B0A395AB922414A5CC3B4C50D37E793`; its public half is
  `scripts/commit_signing_key.asc` and is published on keys.openpgp.org. Git
  signs commits and tags (`user.signingkey = 5CC3B4C50D37E793!`,
  `commit.gpgsign = true`), and the tarball is signed by hand. The trailing
  `!` forces the primary key: a signature by the Ed25519 signing subkey does
  not verify against the committed public key. See
  [release signing](../security/release-signing.md).
- **GitHub repository settings.** Secret scanning with push protection,
  Dependabot alerts and security updates, CodeQL, private vulnerability
  reporting, actions pinned to a full-length commit SHA, and a branch ruleset
  on the default branch requiring the `verify`, `gates`, `build`, `lint`,
  `fixture-determinism`, `test (3.11)` to `test (3.14)` and `replay` checks
  plus signed commits. The ruleset carries a repository-admin bypass so the
  maintainer's direct signed pushes keep working; it binds pull requests and
  contributors, and the maintainer can override any rule.
- **PyPI trusted publishing.** The `pypi` environment is configured for
  `publishing.yml`; no token is stored.
- **AUR access.** `~/.ssh/config` maps `aur.archlinux.org` to `~/.ssh/aur`,
  and that key is registered on the AUR account.

## The steps

Every step happens **before** the tag. The same checklist lives beside the
package in
[`packaging/aur/README.md`](https://github.com/emiliano-go/trustsight/blob/master/packaging/aur/README.md).

1. **Land all content changes**, including `version` in `pyproject.toml` and
   any dependency or `uv.lock` update. Any change outside `packaging/` moves
   the tarball, so it must be final before the next step.
2. **Close the release in the changelog:** rename `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD` in `docs/changelog.md`.
3. **Build the tarball:** `python scripts/build_release_tarball.py`. It
   archives the working tree and refuses untracked files, so `git add`
   anything new first.
4. **Sign the tarball** with the pinned key, forced to the primary:
   `gpg --detach-sign --local-user F759D6D49B0A395AB922414A5CC3B4C50D37E793! dist/trustsight-<ver>.tar.gz`,
   then copy the `.sig` into `packaging/aur/`. The private key is the
   maintainer's; CI never holds it and can only verify.
5. **Record both checksums** in `packaging/aur/PKGBUILD` (`sha256sums`, real
   hashes, never `SKIP`; keep `validpgpkeys` and the `.sig` source) and
   regenerate `.SRCINFO` with `makepkg --printsrcinfo`. This commit touches
   only `packaging/`, so it cannot move the hashes from steps 3-4.
6. **Verify locally:** `makepkg -si` (makepkg verifies the signature against
   the pinned key), the full suite, and `ruff`.
7. **Commit and push** (signed; the ruleset rejects unsigned commits). The
   tip's recorded checksum and `.sig` must describe the tip's tree, or
   `pkgbuild.yml` goes red: a content commit that is not the packaging commit
   leaves the checksum stale.
8. **Tag it:** `git tag -s vX.Y.Z -m "vX.Y.Z"` and push the tag. The tag must
   point at the release commit.
9. **Dispatch `Release software`:**
   `gh workflow run publishing.yml -f tag=vX.Y.Z -f target=<sha>`. It rebuilds
   from the tag and verifies the signature, metadata and checksums,
   test-installs the wheel and sdist, builds the Arch package with `check()`,
   creates a private draft, verifies the artifact manifest, then publishes
   GitHub and PyPI, and dispatches `release-pkgbuild.yml` as a
   post-publication audit. The tag must already be pushed and must resolve to
   `<sha>`; the workflow refuses a missing or mismatched tag, and it creates
   the release from that tag rather than passing `--target`, which would need
   a `workflows: write` scope `GITHUB_TOKEN` cannot hold once the default
   branch has moved past the release commit.
10. **Push the AUR package:** copy the released `packaging/aur/PKGBUILD` and
    `.SRCINFO` into the AUR repository so `trustsight` moves to the new
    version.

After the software release, and only if the seed or corpus changed, publish a
`baseline-<date>` channel release ([publishing baselines](publishing-baselines.md)).

The harness pin moves in lockstep with the version. `harness-regression.yml` is
a required check and fails when the harness's declared core version is not the
checkout's, so a version bump means updating the harness repository first
(`defaults/environment.yml` and `.github/trustsight-commit`) and bumping the
pinned commit in `harness-regression.yml` to that harness commit. Until then
the check fails closed rather than reporting a pass for a version it cannot
measure.

Nothing is repaired afterwards. There is no post-tag step that can fail and
leave the branch inconsistent, which was the whole defect.

## What CI proves

`publishing.yml` is manually dispatched before a software release exists. It
requires the proposed tag to match `pyproject.toml`, `PKGBUILD`, `.SRCINFO`,
wheel metadata, and sdist metadata; runs the complete test suite, `twine
check`, isolated wheel/sdist smoke installs, and the Arch package `check()`.
Only then does it create a private draft, upload the source archive and
SHA-256 manifest, verify the uploaded bytes, and publish GitHub followed by
PyPI. `release-pkgbuild.yml` remains a post-publication audit; it is also
dispatched automatically by `publishing.yml` after the release is published.

`pkgbuild.yml` runs on every push and pull request. It builds the deterministic
tarball from the checked-out tree, verifies the PKGBUILD checksum against it,
and installs from that artifact with `check()` enabled. It does not wait for or
download a published release asset; the release workflow performs the
additional artifact checks before publication.

## When check() runs from the tarball

The suite runs from inside the extracted archive during `makepkg`, where
`packaging/` and `.git` are both absent. Tests that require either explicitly
skip there rather than fail. The exclusions are narrow: the whole PKGBUILD test
module skips when `packaging/aur/PKGBUILD` is absent; the checksum-rebuild and
archive-membership tests skip when there is no Git checkout; and the critical
paths gate skips only `ARCHIVE_EXCLUDED_PATHS` from its existence assertion.
The package `check()` command also excludes `tests/test_fetcher.py` and
`tests/test_rebaseline.py`; those modules require repository/network fixtures
that are not part of the shipped archive test environment.
Two exclusions carry the weight here, and both are required:

- `scripts/critical_paths.py` lists `ARCHIVE_EXCLUDED_PATHS`, the critical
  paths `export-ignore` legitimately removes. The `critical paths are
  synchronised` gate skips their existence check when it is running from an
  archive and enforces it everywhere else. Without the skip the gate requires
  `packaging/aur/PKGBUILD` to exist while `.gitattributes` guarantees it will
  not, a contradiction that can never hold inside the tarball.
- A test that shells out to `git` must skip when there is no checkout. Inside
  a `makepkg` build the tree is owned by a different user than the one
  building, so git refuses with `detected dubious ownership`, which says
  nothing about what the test was asking.
