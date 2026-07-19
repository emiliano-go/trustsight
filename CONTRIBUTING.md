# Contributing

## Where to start

Read the [README](README.md) for the one-liner, the 30-second example, and the scope table. Join the discussion in GitHub Issues.

## Reporting bugs

Open a [GitHub issue](https://github.com/emiliano-go/trustsight/issues). Include the package name, the score TrustSight produced, and — if possible — the diff or package version. Paste the output of `trustsight inspect <package>`.

## Security issues

Do **not** file a public issue. See [SECURITY.md](docs/security.md) for the disclosure process.

## Code contributions

Pull requests are welcome. Before submitting:

```bash
pytest
ruff check
```

The test suite (`pytest`) runs 267 tests across 14 test files. `ruff check` enforces the project's lint rules (line length 100, target version py312). Both must pass.

## Documentation

See [docs/contributing/](docs/contributing/) for the full contributing guide: development setup, writing new rules, re-baselining corpus benchmarks, and documentation style.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](docs/license.md).
