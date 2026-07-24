# Reference

Complete reference documentation for TrustSight CLI, rules, configuration, report schema, evidence tiers, and exit codes.

- **[CLI](cli.md)**: `review`, `inspect`, `history`, `config` commands with flags, arguments, and exit codes.
- **[Rules](rules.md)**: R001-R013 (detection, TOML-configurable) and C001-C003 (code, structural) with severity, weight, target, and description for each.
- **[Configuration](configuration.md)**: Every `config.toml`, `rules.toml`, and `trusted_domains.toml` key with type, default, and effect. Environment variable reference.
- **[Report Schema](report-schema.md)**: `PackageFact` JSON structure used by `inspect` and stored in the database.
- **[Evidence Tiers](evidence-tiers.md)**: A (structural), B (priors/context), C (history/novelty), D (verification) taxonomy with maturity gating and cold-start behaviour.
- **[Exit Codes](exit-codes.md)**: 0 (success/clean), 1 (flagged), 2 (error).
