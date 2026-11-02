"""Canonical security-critical paths shared by policy and CI checks."""

# Critical paths that `.gitattributes export-ignore` keeps out of the release
# tarball.  The exclusion is deliberate: a tarball cannot carry the PKGBUILD
# that records that tarball's own checksum.  The consequence is that a check
# asserting every critical path exists cannot also hold inside the archive,
# and the two requirements silently contradicted each other until `check()`
# was actually run from a release tarball and failed on it.
ARCHIVE_EXCLUDED_PATHS = frozenset({
    "packaging/aur/PKGBUILD",
})

CRITICAL_PATHS = frozenset({
    "scripts/security_gates.py",
    # The gate bodies are the enforcement; changing one must be signed just
    # like changing the dispatcher that imports it.
    "scripts/gates/__init__.py",
    "scripts/gates/_core.py",
    "scripts/gates/_immune.py",
    "scripts/gates/_input_bounds.py",
    "scripts/gates/_integrity.py",
    "scripts/gates/_layers.py",
    "scripts/gates/_parity.py",
    "scripts/gates/_process.py",
    "scripts/gates/_reporting.py",
    # Trust, release, signature and rendering modules decide what a result
    # claims and what a release contains.
    "src/trustsight/release.py",
    "src/trustsight/channels.py",
    "src/trustsight/channel_state.py",
    "src/trustsight/ioc_baseline.py",
    "src/trustsight/watchlist.py",
    "src/trustsight/override.py",
    "src/trustsight/full_aur/export.py",
    "src/trustsight/full_aur/baseline_pubkey.pem",
    "src/trustsight/reporting.py",
    "src/trustsight/verdict.py",
    "src/trustsight/coverage.py",
    "src/trustsight/schema.py",
    "src/trustsight/notify.py",
    "src/trustsight/api/__init__.py",
    "src/trustsight/api/_models.py",
    "src/trustsight/api/_reports.py",
    "src/trustsight/api/_validation.py",
    "src/trustsight/cli/review.py",
    "src/trustsight/cli/inspect/commands.py",
    "src/trustsight/cli/inspect/_render.py",
    "src/trustsight/cli/_review_render.py",
    "src/trustsight/tokenizer.py",
    "src/trustsight/_heredoc.py",
    "src/trustsight/_tokenizer_engine/__init__.py",
    "src/trustsight/_tokenizer_engine/_common.py",
    "src/trustsight/_tokenizer_engine/_quotes.py",
    "src/trustsight/_tokenizer_engine/_expansion.py",
    "src/trustsight/_tokenizer_engine/_variables.py",
    "src/trustsight/_tokenizer_engine/_aliases.py",
    "src/trustsight/_tokenizer_engine/_apply.py",
    "src/trustsight/sandbox/client.py",
    "src/trustsight/sandbox/expand_worker.py",
    "src/trustsight/sandbox/protocol.py",
    "src/trustsight/scoring.py",
    "src/trustsight/differ/__init__.py",
    "src/trustsight/differ/_common.py",
    "src/trustsight/differ/_bounds.py",
    "src/trustsight/differ/_diff.py",
    "src/trustsight/differ/_sources.py",
    "src/trustsight/differ/_companions.py",
    "src/trustsight/differ/_checksums.py",
    "src/trustsight/differ/_verification.py",
    "src/trustsight/config/__init__.py",
    "src/trustsight/config/_defaults_executor.py",
    "src/trustsight/config/_default_config.py",
    "src/trustsight/config/_default_rules.py",
    "src/trustsight/db/__init__.py",
    "src/trustsight/db/_common.py",
    "src/trustsight/db/_connection.py",
    "src/trustsight/db/_packages.py",
    "src/trustsight/db/_metadata.py",
    "src/trustsight/db/_dependencies.py",
    "src/trustsight/db/_maintainers.py",
    "src/trustsight/db/_seed.py",
    "src/trustsight/db/_history.py",
    "src/trustsight/db/_profiles.py",
    "docs/security.md",
    "docs/security/program-under-attack.md",
    "docs/security/what-a-result-claims.md",
    "docs/security/enforcement-map.md",
    "docs/security/vulnerability-reporting.md",
    ".github/workflows/security.yml",
    ".github/workflows/calibration.yml",
    # The adversarial replay is a required check now; removing its judging
    # step or restoring the path filters would neutralise it, so it is signed
    # like the other gates.
    ".github/workflows/harness-regression.yml",
    # The signature policy and the release pipeline are critical too.  The
    # signature workflow was outside its own list, so it could be weakened
    # without a signature; the release workflows decide what users receive.
    ".github/workflows/verify-commit-sigs.yml",
    ".github/workflows/publishing.yml",
    ".github/workflows/release-pkgbuild.yml",
    ".github/workflows/pkgbuild.yml",
    ".github/workflows/baselines.yml",
    "scripts/critical_paths.py",
    "scripts/build_release_tarball.py",
    "scripts/verify_release.py",
    # The commit-signing trust anchor.  The signature workflow verifies
    # against this key and this fingerprint; swapping either is a policy
    # change and must be signed like one.
    "scripts/commit_signing_key.asc",
    "packaging/aur/PKGBUILD",
    "docs/reference/baseline-keys.md",
})
