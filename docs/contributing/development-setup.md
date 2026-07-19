# Development Setup

## Prerequisites

- Python 3.12 or later
- `git`
- `pip`

## Clone the repository

```bash
git clone https://github.com/your-org/trustsight.git
cd trustsight
```

## Create a virtual environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

## Install development dependencies

```bash
pip install -e ".[dev]"
```

This installs the package in editable mode along with `pytest`, `ruff`, and other dev tooling.

## Run the test suite

```bash
pytest
```

Expect **267 tests passing** across **14 test files**.

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

This requires the corpus to be checked out. See [Re-baselining](re-baselining.md) for details.

## Debug a single package

```bash
python -m trustsight inspect <package-name>
```

This runs the full analysis pipeline on one AUR package and prints the per-rule breakdown, evidence, and final score.
