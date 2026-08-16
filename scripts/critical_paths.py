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
    "src/trustsight/scoring.py",
    "src/trustsight/config.py",
    "src/trustsight/db.py",
    "docs/security.md",
    ".github/workflows/security.yml",
    ".github/workflows/calibration.yml",
    "packaging/aur/PKGBUILD",
    "docs/reference/baseline-keys.md",
    "src/trustsight/full_aur/baseline_pubkey.pem",
})
