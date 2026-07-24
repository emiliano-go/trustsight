# Contributing to TrustSight

TrustSight is a CLI tool that audits AUR PKGBUILD diffs for supply-chain risk. It uses a hybrid rule system, TOML-defined patterns (R-series) and code-level structural checks (C-series), to score package modifications on a 0-100 risk scale.

- [Development Setup](development-setup.md): getting started, running tests, linting, and eval
- [Writing a Rule](writing-a-rule.md): how to add R-series or C-series rules, fixture guidelines, fire-rate gate
- [Re-baselining](re-baselining.md): when and how to re-baseline after config or rule changes

## Quick reference

| Metric                | Value                |
|-----------------------|----------------------|
| Tests                 | 267 (14 files)       |
| Python                | 3.12+                |
| Test runner           | pytest               |
| Linter                | ruff                 |
| Rules                 | R001-R013, C001-C003 |
| Rule config           | `rules.toml`         |
| Benign corpus lock    | `tests/fixtures/corpus.lock` |
