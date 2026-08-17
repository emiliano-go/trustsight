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

The current checkout collects **2,613 tests**; the exact count changes as coverage is added.

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
