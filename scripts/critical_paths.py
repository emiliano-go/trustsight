"""Canonical security-critical paths shared by policy and CI checks."""

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
