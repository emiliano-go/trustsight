<!-- description: Setting up a TrustSight development environment: editable install, test suite, linter and docs build. -->

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

## Run the test suite

```bash
uv run pytest
```

Run `uv run pytest` for the current test count; it changes as coverage is added.

### Run a single test

```bash
uv run pytest tests/test_rules.py::test_r001_curl_bash -v
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
| The AUR metadata snapshot | `trustsight.full_aur.pipeline.fetch_metadata` |
| A package's PKGBUILD | `trustsight.full_aur.pipeline.fetch_pkgbuild_with_tree` |
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
python -m trustsight inspect <package-name>
```

This runs the full analysis pipeline on one AUR package and prints the per-rule breakdown, evidence, and final score.

## Build the documentation

```bash
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
