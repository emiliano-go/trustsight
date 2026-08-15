# Development Setup

## Prerequisites

- Python 3.12 or later
- `git`
- `pip`

## Clone the repository

```bash
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight
```

## Create a virtual environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

## Install development dependencies

```bash
uv sync --extra dev
```

This installs the package in editable mode along with `pytest`, `ruff`, and other dev tooling.

## Run the test suite

```bash
pytest
```

Expect **734 tests passing** across **19 test files**.

### Run a single test

```bash
pytest tests/test_rules.py::test_r001_curl_bash -v
```

## Lint the codebase

```bash
ruff check src/ tests/
```

## Run evaluation locally

Evaluation recomputes the baseline against the pinned corpus:

```bash
python scripts/rebaseline.py
```

The corpus is gitignored, so rebuild it from the lock first:

```bash
python scripts/build_corpus.py --from-manifest \
  --manifest tests/fixtures/corpus.lock \
  --out tests/fixtures/benign-corpus
```

See [Re-baselining](re-baselining.md) for details.

## Debug a single package

```bash
python -m trustsight inspect <package-name>
```

This runs the full analysis pipeline on one AUR package and prints the per-rule breakdown, evidence, and final score.
