# Contributing to TrustSight

TrustSight is a CLI tool that audits AUR PKGBUILD diffs for supply-chain risk. It
is an **instrument, not a judge**: it reads changes, applies published detection
rules, and reports what it found and what it could not see. It never decides
whether a package is safe; a person does. Every contribution is measured against
the same thesis, which the [security model](../security.md) states and each part
below applies to work on the tool itself.

- [Development Setup](development-setup.md): getting started, running tests,
  linting, and evaluation
- [Writing a Rule](writing-a-rule.md): how to add R-series or C-series rules,
  fixture guidelines, fire-rate gate
- [Re-baselining](re-baselining.md): when and how to re-baseline after config or
  rule changes
- [Publishing Baselines](publishing-baselines.md): the maintainer workflow for
  building, signing, verifying, and publishing the corpus and IOC baselines
- [Releasing](releasing.md): how a version reaches users, why the source
  tarball is built here rather than taken from GitHub, and the ordering rule
  that keeps the recorded checksum correct
- [Reviewing a Security Control](security-review.md): how to scope a gate so it
  covers the entry point an attacker reaches, and the failure mode that keeps
  recurring

## The boundary

TrustSight does three things, and only three: it **reads** the repository and
the AUR endpoint (plus the signed release assets an operator explicitly asks
for), it **computes** evidence locally and deterministically
without ever executing a PKGBUILD, and it **reports** findings and gaps. A
change that adds a fourth job to the analysis stage (running code, fetching a
declared URL, writing outside the data directories) violates the boundary and
will not be merged.

## The guarantees a contribution must keep

Every agreed guarantee has a gate in CI; a change that breaks a gate is a change
that is not done. The list is stated in full in
[the enforcement map](../security.md#part-c-the-enforcement-map). The ones most
likely to be touched by a rule or pipeline change:

- **Determinism.** The same input produces the same score and evidence record.
  Nondeterminism in scoring is a mandatory-review bug at any scale.
- **Fail-closed on doubts.** A bound that drops input must record a coverage
  gap; a run that did not see the whole change can never present an UNFLAGGED
  verdict. Adding a new truncation seam without a gap is a vulnerability, not a
  rule.
- **Locked invariants.** FATAL rules cannot be switched off, baseline and seed
  can only supply state, and the network boundary is never widened.
- **A claim without a gate is a claim not made.** New guarantees go into
  `scripts/security_gates.py` **and** the security model page, together.

Tokenizer and regex changes require hostile-input tests. Run the deterministic tokenizer fuzz suite with the regular tokenizer tests and security gates. Do not replace Python's `re` module or add a regex engine dependency without a comparative benchmark, syntax-compatibility review, packaging review and a maintainer discussion.

## Signed Commits

For pull requests to `master` that change one of the exact paths in
`scripts/critical_paths.py`, every commit in the pull request range must have a
verified GPG signature. The `verify-commit-sigs` workflow enforces this policy.

For changes that do not touch critical paths, such as documentation, tests, fixtures, or cosmetic fixes, signing is encouraged but not required.

## Non-guarantees to respect

Absence of alerts is not a certificate, and absence on a test machine is not
proof a rule is safe to ship. It is input to a human decision. A rule whose only
evidence is "nothing fired" is not evidence of anything; fire rates on the
benign corpus and real case reports are the arguments that matter.

## Quick reference

| Metric             | Value                           |
|--------------------|---------------------------------|
| Tests              | 2,613 (current checkout)        |
| Python             | 3.11+                           |
| Test runner        | pytest                          |
| Linter             | ruff                            |
| Rules              | 145 scoring rules across R/C/D/S/X, plus P001-P007 declared practice |
| Rule config        | `rules.toml`                    |
| Benign corpus lock | `tests/fixtures/corpus.lock`    |
