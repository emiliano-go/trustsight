# Reference

Complete reference documentation for the TrustSight CLI, the Python API, rules, configuration, report schema, evidence tiers, and exit codes.

- **[CLI](cli.md)**: `review`, `inspect`, `history`, `config` commands with flags, arguments, and exit codes.
- **[Python API](python-api.md)**: `trustsight.api`, the supported programmatic interface. The same flows the CLI runs, returning dataclasses instead of printing.
- **[Rules](rules/index.md)**: R001-R143 (R-series, TOML-configurable and code-emitted), S001-S008 (sabotage), X001-X007 (crossfire), C001-C007 (code, structural) and D001-D004 (dependency) with severity, weight, target, and description for each. Organised by [category](rules/index.md#categories), one page per category, with the engine's own mechanics in [the system reference](rules/system.md).
- **[Configuration](configuration.md)**: Every `config.toml`, `rules.toml`, and `trusted_domains.toml` key with type, default, and effect. Environment variable reference.
- **[IOC Federation](ioc.md)**: signed known-bad indicator baselines (domains, hashes, package names), the baseline format, matching, expiry, and attribution.
- **[Report Schema](report-schema.md)**: `PackageFact` JSON structure used by `inspect` and stored in the database.
- **[Baseline Keys](baseline-keys.md)**: the pinned ed25519 key for corpus and release assets, and manifest-carried per-source IOC keys.
- **[Evidence Tiers](evidence-tiers.md)**: A (structural), B (priors/context), C (history/novelty), D (verification) taxonomy with maturity gating and cold-start behaviour.
- **[Exit Codes](exit-codes.md)**: 0 (analysis completed), 2 (error), and why a flag is not an exit code.
