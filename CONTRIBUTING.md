# Contributing to TrustSight

TrustSight is a security tool with published limits. Contributions that touch analysis, scoring, fixtures, the tokenizer, or the security gates must preserve those limits and be easy to verify.

If you only want to use the tool, start with the README and the getting started guide. If your change affects analysis behavior or the security model, read `docs/security.md` first.

## Quick Start

```bash
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight
uv sync --locked --extra dev
uv run --with pytest python -m pytest
uv run ruff check
uv run python scripts/security_gates.py
```

If you change rules, scoring, tokenizer behavior, or calibration fixtures, also run:

```bash
uv run python scripts/build_corpus.py --from-manifest \
  --manifest tests/fixtures/corpus.lock \
  --out tests/fixtures/benign-corpus
TRUSTSIGHT_FULL_CALIBRATION=1 uv run --with pytest python -m pytest tests/test_calibration_gates.py
```

The benign corpus is gitignored, so a fresh checkout must reconstruct the
locked corpus before the full calibration run.

The committed calibration set is a locked, point-in-time benign corpus and
self-authored labelled fixtures. It is a regression suite, not an independent
performance study. For externally held labels, use the
[blinded-evaluation intake](docs/contributing/blinded-evaluation.md) rather
than adding the material to fixtures before evaluation.

All required checks should pass before a pull request is reviewed.

## Signed Commits

For pull requests to `master` that change one of the exact paths in
`scripts/critical_paths.py`, every commit in the pull request range must carry
a valid GPG signature from the **pinned commit-signing key**
(`scripts/commit_signing_key.asc`, fingerprint
`F759D6D49B0A395AB922414A5CC3B4C50D37E793`). A signature from any other key,
and an unsigned commit, are rejected: the `verify-commit-sigs` workflow
imports that key into a throwaway keyring and verifies each commit against it,
rather than trusting GitHub's "verified" flag, which accepts any key.

For changes that do not touch critical paths, such as documentation, tests, fixtures, or cosmetic fixes, signing is encouraged but not required. If you do not hold the pinned key, leave critical-path changes to the maintainer.

### Setting Up GPG Signing

The pinned key is the only accepted signer for critical paths. To sign with it:

```bash
gpg --import scripts/commit_signing_key.asc   # public half, for verification
gpg --list-secret-keys --keyid-format=long
git config --global user.signingkey 5CC3B4C50D37E793!
git config --global commit.gpgsign true
```

The trailing `!` makes git sign with the primary key rather than a subkey,
which is the fingerprint the workflow pins.

Verify a commit before pushing:

```bash
git log --show-signature -1
```

## Discuss First

Open a GitHub Discussion before spending significant time if your change affects any of the following:

- New rules or severity changes
- Tokenizer or resolver behavior
- Network behavior or fetch targets
- New dependencies
- Database schema changes
- Public API boundaries

These areas affect the project's published security claims. A change here usually needs a matching gate, test, or documentation update.

## Security Critical Paths

The following exact paths are the critical-path set checked by the pull-request
signature workflow:

| File | Why it matters |
|---|---|
| `scripts/security_gates.py` | Executable enforcement of the security model |
| `src/trustsight/tokenizer.py` | Shell and text resolution behavior |
| `src/trustsight/scoring.py` | Determinism, severity, and score calculation |
| `src/trustsight/config.py` | Default settings and shipped rule tables |
| `src/trustsight/db.py` | Stored state and seed integrity |
| `docs/security.md` | Security claims and invariants |
| `.github/workflows/security.yml` | CI checks for security invariants |
| `.github/workflows/calibration.yml` | CI checks for calibration regressions |
| `.github/workflows/verify-commit-sigs.yml` | The signature policy itself |
| `.github/workflows/publishing.yml` | Builds and publishes the release artifacts |
| `.github/workflows/release-pkgbuild.yml` | Verifies a published release |
| `.github/workflows/pkgbuild.yml` | Builds the AUR package from the tarball |
| `.github/workflows/baselines.yml` | Builds and signs the baseline assets |
| `scripts/critical_paths.py` | The canonical critical-path list |
| `scripts/build_release_tarball.py` | The deterministic release tarball |
| `scripts/verify_release.py` | Release metadata and checksum verification |
| `scripts/commit_signing_key.asc` | The commit-signing trust anchor |
| `packaging/aur/PKGBUILD` | Supported packaging path |
| `docs/reference/baseline-keys.md` | Baseline trust anchor |
| `src/trustsight/full_aur/baseline_pubkey.pem` | Distribution key for signed baselines |

If you are unsure whether a change touches one of these paths, ask first.

## Public API Docstrings

`trustsight.api` is the supported surface, so its docstrings are the user
documentation an IDE shows on hover. Use reST fields:

- `:param name:` on every public method parameter.
- `:returns:` and `:raises SomeError:` where they apply.
- `:ivar field:` on every dataclass field. Attribute descriptions live in the
  class docstring, not in a bare string after the assignment.
- An `Example:` section with an indented `.. code-block:: python` block on the
  entry points.

Every public name and method is annotated so type checkers and completion
work; `src/trustsight/py.typed` tells them to read the package. The
`tests/test_api_docs.py` check fails when a new export, field or method ships
without a docstring, an annotation, or its `:ivar:` entry.

## Getting Help

- Architecture questions: open a GitHub Discussion
- Rule design: read the [writing-a-rule](docs/contributing/writing-a-rule.md) and security-review guides
- Corpus re-baselining: follow the re-baselining guide under `docs/contributing/`
- Security disclosures: use `docs/security.md`

GitHub Issues and Discussions are preferred for technical work.

## License

By contributing, you agree that your work will be licensed under the same MIT license as the project. If you are contributing on behalf of an employer, say so in the pull request description.
