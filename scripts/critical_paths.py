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
    "src/trustsight/tokenizer.py",
    "src/trustsight/_tokenizer_engine.py",
    "src/trustsight/sandbox/client.py",
    "src/trustsight/sandbox/expand_worker.py",
    "src/trustsight/sandbox/protocol.py",
    "src/trustsight/scoring.py",
    "src/trustsight/config.py",
    "src/trustsight/db.py",
    "docs/security.md",
    "docs/security/program-under-attack.md",
    "docs/security/what-a-result-claims.md",
    "docs/security/enforcement-map.md",
    "docs/security/vulnerability-reporting.md",
    ".github/workflows/security.yml",
    ".github/workflows/calibration.yml",
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
    "packaging/aur/PKGBUILD",
    "docs/reference/baseline-keys.md",
    "src/trustsight/full_aur/baseline_pubkey.pem",
})
