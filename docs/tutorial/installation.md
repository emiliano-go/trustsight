<!-- description: Install TrustSight from the PKGBUILD in this repository or from the AUR, verify the installation, and fix the common failures. Requirements are Arch Linux, Python 3.11 or later, and git. -->

# Installation

By the end of this page TrustSight is installed and `trustsight --help` runs. It
requires **Arch Linux**, **Python 3.11 or later**, and **git** (for cloning AUR
repositories during analysis).

!!! note "The AUR package is maintained by this project"

    The `trustsight` AUR package is built from `packaging/aur/PKGBUILD` in
    this repository. It gets no special trust for being the author's: it is
    an AUR package like any other, so inspect its PKGBUILD before installing.
    Source remains the recommended install, below.

## Import the release signing key

`makepkg` verifies the detached signature on the release tarball. Import the
project's signing key once, or the build stops with `unknown public key` for
`5CC3B4C50D37E793`:

```bash
gpg --keyserver hkps://keys.openpgp.org \
  --recv-keys F759D6D49B0A395AB922414A5CC3B4C50D37E793
```

The same key is pinned in `validpgpkeys` in both repository PKGBUILDs and in
the AUR package, so one import covers every install path below.

## Build the repository PKGBUILD (recommended)

The PKGBUILD pins one released version, so check out the release tag it names
rather than the moving `master` branch:

```bash
git clone --depth 1 --branch "$(git ls-remote --tags --refs --sort=-v:refname \
  https://github.com/emiliano-go/trustsight.git 'v*' | head -1 | cut -d/ -f3)" \
  https://github.com/emiliano-go/trustsight.git
cd trustsight/packaging/aur
makepkg -si
```

To build the checkout you just cloned, with no second download of the same
sources from GitHub, use the development recipe instead. It installs
`trustsight-dev` beside the released package and adds `trustsight-dev` and
`trustsight-gate-dev` wrappers with isolated state under
`~/.local/share/trustsight-dev/home`, warns that it is not a release, derives
`pkgver` from `git describe` and builds the tree in place:

```bash
cd trustsight/packaging/dev
makepkg -si
```

Before installing a release, you can confirm the asset matches the tag it
claims to describe:

```bash
python scripts/build_release_tarball.py --rev v<version> --check <sha256>
```

The recorded `<sha256>` is in `packaging/aur/PKGBUILD`.

The PKGBUILD runs the packaged test suite during build, excluding
`tests/test_fetcher.py` and `tests/test_rebaseline.py` because they require
network and corpus fixtures unavailable in a clean package build. `makepkg -si`
pulls in the dependencies (`pygit2`, `tldextract`, `rich`, `typer`, `cryptography`) as proper
system packages. The result is tracked by `pacman`, so it upgrades and
uninstalls like anything else on the system.

Build the PKGBUILD in this repository, as above. PyPI distributions are for
isolated virtual environments, not for installation into Arch's system Python:
installing with `pip` is blocked by the system Python's
`externally-managed-environment` protection, and forcing it with
`--break-system-packages` risks conflicting with `pacman`-managed files. For an
isolated environment, install the PyPI distribution with
`python -m venv .venv && .venv/bin/pip install trustsight`.

For a development checkout with the test dependencies, use a virtualenv instead
(see [development setup](../contributing/development-setup.md)).

## Install from the AUR

The `trustsight` package on the AUR is maintained by this project, but it is
an AUR package like any other: it gets no special trust, so review its
PKGBUILD before installing, exactly as you would with any other.

```bash
git clone https://aur.archlinux.org/trustsight.git
cd trustsight
makepkg -si
```

Or with an AUR helper: `yay -S trustsight`.

## Verify the installation

```bash
trustsight --help
```

You should see a list of available commands: `review`, `inspect`, `history`, `list`, `status`, `seed-db`, `baseline`, `full-aur`, `import-baseline`, `config`, `db`, `override`, `lint-rules`, `lint`, `corpus`, `ioc`, `seed`, `explain`, `report`, `forget`.

Check your configuration:

```bash
trustsight config show
```

## Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: No module named 'pygit2'` | The `python-pygit2` package is missing or the installation is incomplete | `sudo pacman -S python-pygit2`, then reinstall |
| `PGP Signature ... FAILED (unknown public key 5CC3B4C50D37E793)` | The release signing key is not in your GPG keyring | Import it with the [key command above](#import-the-release-signing-key), then re-run `makepkg -si` |

**Next:** [Quickstart](quickstart.md#quickstart), run your first review.
