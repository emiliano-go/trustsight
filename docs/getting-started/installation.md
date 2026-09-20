<!-- description: Build and install TrustSight from the PKGBUILD in this repository. TrustSight is not officially published on the AUR; requirements are Arch Linux, Python 3.11 or later, and git. -->

# Installation

TrustSight requires **Arch Linux**, **Python 3.11 or later**, and **git** (for cloning AUR repositories during analysis).

!!! warning "TrustSight is not officially published on the AUR"

    Any AUR package named `trustsight` is **unaffiliated** with this project
    and is not maintained, reviewed, or endorsed by its author. TrustSight is
    an AUR-review tool; distributing it through the AUR is circular, and an
    unaffiliated upload is itself an unreviewed package. Install from this
    repository's PKGBUILD or the signed release tarball instead, as below.

    Contact is being attempted with the uploader with the aim of reaching a
    secure, correct, and official AUR packaging arrangement. Until that exists,
    treat any AUR `trustsight` package as third-party code and review it
    yourself.

---

## Install From This Repository

```bash
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight/packaging/aur
makepkg -si
```

!!! note "Repository PKGBUILD only"

    Build the PKGBUILD in this repository, as above. PyPI distributions are available for isolated virtual environments, but not for installation into Arch's system Python.

The PKGBUILD runs the packaged test suite during build, excluding
`tests/test_fetcher.py` and `tests/test_rebaseline.py` because they require
network and corpus fixtures unavailable in a clean package build. `makepkg -si`
pulls in the dependencies (`pygit2`, `tldextract`, `rich`, `typer`, `cryptography`) as proper
system packages. The result is tracked by `pacman`, so it upgrades and
uninstalls like anything else on the system.

Do not install into the system interpreter with `pip`: it is blocked by the
system Python's `externally-managed-environment` protection, and forcing it
with `--break-system-packages` risks conflicting with `pacman`-managed files.
For an isolated environment, install the PyPI distribution with
`python -m venv .venv && .venv/bin/pip install trustsight`.

For a development checkout with the test dependencies, use a virtualenv instead (see [development setup](../contributing/development-setup.md)).

---

## Verdicts

Verdicts are template-based descriptions of each triggered finding. The score is calculated locally and deterministically. No LLM is needed.

---

## Verify the installation

```bash
trustsight --help
```

You should see a list of available commands: `review`, `inspect`, `history`, `list`, `status`, `seed-db`, `baseline`, `full-aur`, `import-baseline`, `config`, `db`, `override`, `lint-rules`, `corpus`, `ioc`, `seed`, `forget`.

Check your configuration:

```bash
trustsight config show
```

---

## Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `trustsight review` prints "No outdated packages found." | No AUR packages installed, or all are up to date | Install an AUR package or wait for updates |
| `ModuleNotFoundError: No module named 'pygit2'` | The `python-pygit2` package is missing or the installation is incomplete | `sudo pacman -S python-pygit2`, then reinstall |
