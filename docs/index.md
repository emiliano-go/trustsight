---
description: Full documentation for TrustSight : deterministic AUR PKGBUILD audit tool.
---

# TrustSight documentation

Audits AUR PKGBUILDs before you update: catches careless malice and structural risk, and tells you what it can't verify.

---

## Site map

### [Getting Started](getting-started/installation.md)

One-tutorial path from install to your first `trustsight review`. Covers prerequisites, configuration, and interpreting the output table.

### [Guides](guides/index.md)

How to audit packages before updating, use TrustSight in CI pipelines, act on FLAGGED and INCONCLUSIVE verdicts, and tune configuration for your threat model.

### [Reference](reference/index.md)

- **CLI**: full command reference for `review`, `inspect`, `history`, `config`
- **Rules**: R001–R013 detection rules with severity, scope, and examples
- **Code Rules**: C001–C003 structural anomaly rules
- **Config**: config.toml, rules.toml, domains.toml schema
- **Report schema**: PackageFact JSON structure
- **Evidence tiers**: A (structural), B (priors/context), C (history/novelty), D (verification)
- **Exit codes**: what each exit code means

### [Explanation](explanation/index.md)

- **Trust model**: what TrustSight guarantees and what it does not
- **Scoring philosophy**: why deterministic scoring, what the LLM does, verdict-integrity assertions
- **Cold start**: how INCONCLUSIVE and maturity gating work when the database is empty
- **Corpus and benchmarks**: zero-rate, recall, precision figures on the benign and malicious corpuses
- **Limits**: what TrustSight cannot detect (signed payloads, second-order attacks, deliberately-unremarkable PKGBUILDs)

### [Contributing](contributing/index.md)

Development setup, writing new rules, running the test suite, re-baselining corpus benchmarks, and documentation style guide.

### [Changelog](changelog.md)

### [Security](security.md)

### [License](license.md)
