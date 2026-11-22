<!-- description: TrustSight is immune-inspired security intelligence for the AUR: it audits PKGBUILDs, remembers ecosystem history, and reports what it could not verify. An immune system for the AUR. -->

# TrustSight

**An immune system for the AUR.**

TrustSight is immune-inspired security intelligence for the Arch User
Repository. It audits a package update before you build it, reads the recipe
and the change around it, remembers what the ecosystem has seen, and reports
deterministic, evidence-linked findings: what changed, what matched, and what
the analysis could not see.

It is an **instrument, not a judge**. A quiet result is not a certificate of
safety, and no report authorizes skipping review. TrustSight gives you the
evidence; the decision stays with you.

[Why an immune system?](explanation/why-an-immune-system.md) explains the
model, including the human loop that completes it.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white&style=for-the-badge)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-10AC84?style=for-the-badge)](https://github.com/emiliano-go/trustsight/blob/master/LICENSE)
[![Release tests](https://img.shields.io/github/actions/workflow/status/emiliano-go/trustsight/release-tests.yml?style=for-the-badge&logo=github&label=Release%20tests)](https://github.com/emiliano-go/trustsight/actions/workflows/release-tests.yml)
[![PyPI](https://img.shields.io/badge/PyPI-trustsight-3776AB?logo=pypi&logoColor=white&style=for-the-badge)](https://pypi.org/project/trustsight/)

## Three ways in

### Get started

Install TrustSight and run a first review. You do not need to understand the
detection engine to get a useful answer.

- [What is TrustSight?](start-here/what-is-trustsight.md)
- [Installation](start-here/installation.md)
- [Quickstart](start-here/quickstart.md)

### Understand a finding

Learn what a report claims, how to read a finding, and what to do when a rule
fires.

- [Understanding Your First Report](start-here/understanding-your-first-report.md)
- [Rule Interpretation](rules/interpretation.md)
- [Acting on a Flag](workflows/acting-on-a-flag.md)

### Integrate TrustSight

Put the review in front of an update, a package manager, or a CI pipeline.

- [Auditing Before Update](workflows/auditing-before-update.md)
- [Integrating with yay and paru](workflows/integrating-yay-and-paru.md)
- [Using TrustSight in CI/CD](workflows/using-in-ci.md)

Ready to get started? Head over to the [Quickstart](start-here/quickstart.md) for installation and your first review.

## What TrustSight produces

Every review is a deterministic, structured **evidence report**, computed
locally from the bytes on disk:

- **Findings**: each is a named rule with the file, side and line it matched,
  and a plain-English description of what it saw.
- **The change summary**: modified files, source and checksum moves,
  dependency additions, and maintainer or version changes.
- **Coverage gaps**: what the run could not fully assess, stated so an
  incomplete analysis is never mistaken for a clean one.
- **A template verdict**: the findings rendered into a review direction. It
  describes what fired; it never grants permission to skip review.

The report keeps detection and coverage as separate facts. A finding records
what matched; a coverage state records what was read. See
[Assurance Layers](security-design/assurance-layers.md) for how findings are
grouped and [Report Schema](reference/report-schema.md) for the exact payload.

## Security philosophy

TrustSight reads hostile input without trusting it. It never executes a
`PKGBUILD`, never fetches a declared URL during analysis, and never writes
outside its data directories. Every finding is tied to a line and every gap is
reported rather than guessed. Positive evidence is reported and never
credited, because anything an attacker can declare costs them nothing.

Those are guarantees with gates, not slogans. The
[Security Model](security-design/security-model.md) states each one and links
to the enforcement that proves it; the
[Threat Model and Limitations](security-design/threat-model.md) states what
the tool cannot see.

## Go deeper

- [How TrustSight Works](security-design/how-it-works.md): the analysis
  pipeline end to end.
- [Rules Overview](rules/index.md): the rule system, categories and series.
- [Rule Mechanics](rules/mechanics.md): matching, scoring, configuration and
  identifiers.
- [Workflows](workflows/index.md): task-oriented guides for everyday use.
- [Reference](reference/index.md): CLI, Python API, configuration, report
  schema, evidence tiers, IOC federation and exit codes.
- [Reports](reports/index.md): detection records from the wild and measured
  evaluations of the rule set.
- [Glossary](reference/glossary.md): the vocabulary used across the docs.

## Contributing and project resources

TrustSight is measured against the same thesis it reports on. Contributions are
welcome, including rules, tests, documentation and adversarial evaluation.

- [Contributing](contributing/index.md)
- [Writing a Rule](contributing/writing-a-rule.md)
- [Documentation Policy](contributing/documentation-policy.md)
- [Changelog](changelog.md) &middot; [License](license.md) &middot;
  [Vulnerability Reporting](security-design/vulnerability-reporting.md)
