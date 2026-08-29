<!-- description: Reference documentation for the TrustSight CLI, Python API, configuration files, report schema, evidence tiers and exit codes. -->

# Reference

Complete reference documentation for the TrustSight CLI, the Python API, configuration, report schema, evidence tiers, and exit codes. The [rules](../reference/rules/index.md) have a dedicated top-level navigation section.

- **[CLI](cli.md)**: `review`, `inspect`, `history`, `config` commands with flags, arguments, and exit codes.
- **[Python API](python-api.md)**: `trustsight.api`, the supported programmatic interface. The same flows the CLI runs, returning dataclasses instead of printing.
- **[Configuration](configuration.md)**: Every `config.toml`, `rules.toml`, and `trusted_domains.toml` key with type, default, and effect. Environment variable reference.
- **[IOC Federation](ioc.md)**: signed known-bad indicator baselines (domains, hashes, package names), the baseline format, matching, expiry, and attribution.
- **[Report Schema](report-schema.md)**: `PackageFact` JSON structure used by `inspect` and stored in the database.
- **[Baseline Keys](baseline-keys.md)**: the pinned ed25519 key for corpus and release assets, and manifest-carried per-source IOC keys.
- **[Evidence Tiers](evidence-tiers.md)**: A (structural), B (priors/context), C (history/novelty), D (verification) taxonomy with maturity gating and cold-start behaviour.
- **[Exit Codes](exit-codes.md)**: 0 (analysis completed), 2 (error), and why a flag is not an exit code.
