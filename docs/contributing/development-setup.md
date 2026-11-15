<!-- description: Setting up a TrustSight development environment: editable install, the development package, test suite, linter and docs build. -->

# Development Setup

## Prerequisites

- Python 3.11 or later
- `git`
- [uv](https://docs.astral.sh/uv/)

## Clone the repository

```bash
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight
```

## Install development dependencies

```bash
uv sync --locked --extra dev
```

This installs the package in editable mode along with `pytest`, `ruff`, and other dev tooling.

## Build the development package

`packaging/dev/PKGBUILD` builds the checkout you are already in, without
fetching a second copy of the sources. It installs a separate
`trustsight-dev` package under `/opt/trustsight-dev` and adds the
`trustsight-dev` and `trustsight-gate-dev` commands; the stable `trustsight`
commands are left untouched.

```bash
cd packaging/dev
makepkg -si
```

The recipe derives `pkgver` from `git describe` (falling back to a
commit-derived version when a shallow clone has no tags), builds the parent
checkout in place, and runs the test suite from the wheel it just built. Its
wrappers keep config, database and cache under
`~/.local/share/trustsight-dev/home`, so the development build can sit beside a
released install without sharing state. It prints a warning in `prepare()` and
on install because it is not a release.

The release recipe in `packaging/aur/PKGBUILD` is the other half: it pins one
published tarball so a release build is reproducible. Use it for a release
candidate, not for day-to-day work on the checkout.

Remove the development package with `pacman -R trustsight-dev`; its state under
`~/.local/share/trustsight-dev/home` is kept.

## Run the test suite

```bash
uv run --extra dev pytest
```

`pyproject.toml` sets `addopts = "-n 4 --dist loadfile"`, so this runs the
suite on four `pytest-xdist` workers with each test file kept whole on one
worker. That grouping matters: module-scoped fixtures and the few files that
touch process-wide state stay isolated, while the corpus-heavy files run
alongside each other.

Use `-n 0` to restore serial order when you are debugging an ordering
failure:

```bash
uv run --extra dev pytest -n 0
```

The worker count is capped at four on purpose. The regex-safety audit
(`tests/test_regex_safety.py`) measures patterns against a wall-clock budget;
when the machine is oversubscribed, a pattern that is safe serially can time
out. Four workers pass on the project's CI runner.

Run the command above to get the current test count; it changes as coverage
is added.

### Run a single test

```bash
uv run --extra dev pytest tests/test_rules.py::test_r001_curl_bash -v
```

### The suite does not reach the network

Every test runs with `TRUSTSIGHT_OFFLINE=1` set and with outbound sockets
blocked. A test that tries to open a connection to anything but loopback
fails immediately with `NetworkAccessDenied`, naming the address and the
frame that reached for it.

This is not a policy about tidiness. A test that reaches the real AUR does
not fail; it **waits**. The metadata dump is tens of megabytes behind a
300-second timeout, so a mock that silently stops applying turns a
one-second unit test into a stalled CI job with no failing assertion to
point at. The guard converts that stall into a named failure.

If you hit it, the fix is almost always to patch the function that fetches
rather than to allow the call:

| Reaching for | Patch |
|---|---|
| The release channel (seed, IOC baselines, corpus) | Nothing - `TRUSTSIGHT_OFFLINE` already covers it |
| The AUR metadata snapshot | `trustsight.full_aur.metadata.fetch_metadata` |
| A package's PKGBUILD | `trustsight.full_aur.fetch.fetch_pkgbuild_with_tree` |
| Dependency resolution | Already stubbed suite-wide; override it with your own data |

A test whose subject *is* the online path opts back in with
`monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)` and mocks its own
transport; `tests/test_release_fetch.py` does this at file level. The socket
guard still holds the line underneath, so opting out of offline mode does
not let a real request through.

!!! warning "Do not leave `sys.modules` rewritten"

    A test that deletes `trustsight*` modules to re-import them must put
    them back, in a `finally`. Otherwise a later test's
    `monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)` patches one
    module object while its own `from trustsight.db import init_db` refers
    to another: `init_db()` creates tables in a tmpdir and
    `get_connection()` opens your real database. This cost the suite 27
    failures across three files, none of which named the test that caused
    them.

## Lint the codebase

```bash
uv run ruff check src/ tests/
```

## Run evaluation locally

Evaluation recomputes the baseline against the pinned corpus:

```bash
uv run python scripts/rebaseline.py
```

The corpus is gitignored, so rebuild it from the lock first:

```bash
uv run python scripts/build_corpus.py --from-manifest \
  --manifest tests/fixtures/corpus.lock \
  --out tests/fixtures/benign-corpus
```

See [Re-baselining](re-baselining.md) for details.

## Debug a single package

```bash
uv run python -m trustsight inspect <package-name>
```

This runs the full analysis pipeline on one AUR package and prints the per-rule breakdown, evidence, and final score.

## Build the documentation

```bash
uv run --extra docs zensical serve          # build and serve with live reload
uv run --extra docs zensical build          # renders docs/ into site/
uv run --extra docs python scripts/build_llms_txt.py
```

`zensical build` renders every page listed in `zensical.toml`'s nav. The
second command writes `site/llms.txt` and `site/llms-full.txt`, the plain-text
companions every page advertises through `<link rel="alternate">`: an indexed
map of the site, and the whole corpus concatenated. It reads the same nav, so
a page reachable in the sidebar is a page reachable in both files.

Run it after `zensical build`, which clears `site/`. `--check` verifies the
two files match the current docs without writing anything, which is the form
to use in a deployment that should fail rather than publish a stale index:

```bash
uv run --extra docs python scripts/build_llms_txt.py --check
```

`site/` is gitignored; neither the rendered site nor these two files are
committed.
