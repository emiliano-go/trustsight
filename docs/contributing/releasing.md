---
description: How a TrustSight version reaches users: the source tarball this repository builds, the PKGBUILD that consumes it, and the checks that gate a tag.
---

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

`tests/test_pkgbuild.py::test_recorded_checksum_matches_a_freshly_built_tarball`
rebuilds the tarball and compares it against the recorded value, so a stale
checksum cannot be committed at all. `tests/test_release_workflow.py::test_a_worktree_build_refuses_untracked_files`
covers the refusal.

## The steps

The full checklist lives beside the package in
[`packaging/aur/README.md`](https://github.com/emiliano-go/trustsight/blob/master/packaging/aur/README.md).
In outline, and note that every step happens **before** the tag:

1. Land all content changes, including `version` in `pyproject.toml`.
2. `python scripts/build_release_tarball.py` and read the checksum.
3. Record it in `packaging/aur/PKGBUILD`, regenerate `.SRCINFO`. This commit
   touches only `packaging/`, so it cannot move the checksum from step 2.
4. Build locally with `makepkg -si`.
5. Push the final commit, then dispatch `Release software` with the intended
   `vX.Y.Z` tag and commit. It builds the artifacts, verifies their metadata,
   test-installs the wheel and sdist, builds the Arch package, creates a draft
   release, verifies its checksum manifest, then publishes GitHub and PyPI.

Nothing is repaired afterwards. There is no post-tag step that can fail and
leave the branch inconsistent, which was the whole defect.

## What CI proves

`publishing.yml` is manually dispatched before a software release exists. It
requires the proposed tag to match `pyproject.toml`, `PKGBUILD`, `.SRCINFO`,
wheel metadata, and sdist metadata; runs the complete test suite, `twine
check`, isolated wheel/sdist smoke installs, and the Arch package `check()`.
Only then does it create a private draft, upload the source archive and
SHA-256 manifest, verify the uploaded bytes, and publish GitHub followed by
PyPI. `release-pkgbuild.yml` remains a manual, post-publication audit.

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
