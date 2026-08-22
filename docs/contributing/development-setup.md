---
description: Setting up a TrustSight development environment: editable install, test suite, linter and docs build.
---

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
