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

**The ordering was impossible.** The generated archive cannot exist until the
tag does, so its checksum could only be recorded *after* tagging, by a second
commit. Between those two commits the PKGBUILD named a new `pkgver` beside the
previous release's checksum. That window opened on every release, and in
v0.13.1 the workflow that closes it failed, so the window never shut and a
user reported the mismatch.

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

`tests/test_pkgbuild.py::test_recorded_checksum_matches_a_freshly_built_tarball`
rebuilds the tarball and compares it against the recorded value, so a stale
checksum cannot be committed at all. This is the check that makes the v0.13.1
report unrepeatable.

## The steps

The full checklist lives beside the package in
[`packaging/aur/README.md`](https://github.com/emiliano-go/trustsight/blob/master/packaging/aur/README.md).
In outline, and note that every step happens **before** the tag:

1. Land all content changes, including `version` in `pyproject.toml`.
2. `python scripts/build_release_tarball.py` and read the checksum.
3. Record it in `packaging/aur/PKGBUILD`, regenerate `.SRCINFO`. This commit
   touches only `packaging/`, so it cannot move the checksum from step 2.
4. Build locally with `makepkg -si`.
5. Tag, push, and publish the release with the tarball from step 2 attached.

Nothing is repaired afterwards. There is no post-tag step that can fail and
leave the branch inconsistent, which was the whole defect.

## What CI proves

`release-pkgbuild.yml` runs on a published release and only verifies; it never
writes to the repository. It rebuilds the tarball from the tag, asserts the
PKGBUILD already records that checksum, asserts the published asset is those
exact bytes, then builds and installs it with `check()` enabled so the shipped
test suite runs against the artifact users will actually get.

`pkgbuild.yml` runs on every push and repeats the checksum assertion against
the published asset. It skips while a release is in flight, because the tag or
the asset may not exist yet; the conditions are described in
`tests/test_release_workflow.py`, which runs the shipped gate script against
synthetic repositories in each state.

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
Two missing exclusions took down the v0.13.1 release:

- `scripts/critical_paths.py` lists `ARCHIVE_EXCLUDED_PATHS`, the critical
  paths `export-ignore` legitimately removes. The `critical paths are
  synchronised` gate skips their existence check when it is running from an
  archive and enforces it everywhere else. Before that, the gate required
  `packaging/aur/PKGBUILD` to exist while `.gitattributes` guaranteed it would
  not, a contradiction that could never hold inside the tarball.
- A test that shells out to `git` must skip when there is no checkout. Inside
  a `makepkg` build the tree is owned by a different user than the one
  building, so git refuses with `detected dubious ownership`, which says
  nothing about what the test was asking.
