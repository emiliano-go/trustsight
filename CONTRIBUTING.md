# Contributing to TrustSight

TrustSight is a security tool with published limits. Contributions that touch analysis, scoring, fixtures, the tokenizer, or the security gates must preserve those limits and be easy to verify.

If you only want to use the tool, start with the README and the getting started guide. If your change affects analysis behavior or the security model, read `docs/security.md` first.

## Quick Start

```bash
git clone https://github.com/emiliano-go/trustsight.git
cd trustsight
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check
python scripts/security_gates.py
```

If you change rules, scoring, tokenizer behavior, or calibration fixtures, also run:

```bash
TRUSTSIGHT_FULL_CALIBRATION=1 pytest tests/test_calibration_gates.py
```

All required checks should pass before a pull request is reviewed.

## Signed Commits

GPG-signed commits are required for changes to security-critical paths: the tokenizer, scoring, config, database, security gates, CI workflows, packaging, and baseline keys. The `CODEOWNERS` file and the `verify-commit-sigs` workflow enforce this.

For changes that do not touch critical paths, such as documentation, tests, fixtures, or cosmetic fixes, signing is encouraged but not required.

### Setting Up GPG Signing

If you do not already have a GPG key:

```bash
gpg --full-generate-key
gpg --list-secret-keys --keyid-format=long
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
```

Add the public key to your GitHub profile:

https://github.com/settings/gpg/new

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

Changes to the paths below require careful review:

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
| `packaging/aur/PKGBUILD` | Supported packaging path |
| `docs/reference/baseline-keys.md` | Baseline trust anchor |
| `src/trustsight/full_aur/baseline_pubkey.pem` | Distribution key for signed baselines |

If you are unsure whether a change touches one of these paths, ask first.

## Getting Help

- Architecture questions: open a GitHub Discussion
- Rule design: read the rule-writing and security-review guides under `docs/contributing/`
- Corpus re-baselining: follow the re-baselining guide under `docs/contributing/`
- Security disclosures: use `docs/security.md`

GitHub Issues and Discussions are preferred for technical work.

## License

By contributing, you agree that your work will be licensed under the same MIT license as the project. If you are contributing on behalf of an employer, say so in the pull request description.
