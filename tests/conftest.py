import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

SHARED_RULES = [
    {"id": "R001", "name": "Remote Script Execution", "pattern": r"curl.*\|\s*(bash|sh|python|zsh)", "severity": "CRITICAL", "category": "network_execution", "match_target": "resolved"},
    {"id": "R002", "name": "Wget Pipe to Shell", "pattern": r"wget.*\|\s*(bash|sh|python|zsh)", "severity": "CRITICAL", "category": "network_execution", "match_target": "resolved"},
    {"id": "R003", "name": "Base64 Decode and Execute", "pattern": r"base64.*\-d.*\|", "severity": "CRITICAL", "category": "obfuscation", "match_target": "resolved"},
    {"id": "R004", "name": "Checksum Disabled", "pattern": r"sha256sums\s*=\s*\(?\s*['\"]?(?:SKIP|NONE)['\"]?", "severity": "HIGH", "category": "integrity", "match_target": "raw_line"},
    {"id": "R005", "name": "Checksum Emptied", "pattern": r"sha256sums\s*=\s*\(\s*\)", "severity": "HIGH", "category": "integrity", "match_target": "raw_line"},
    # R006 is now a structural rule (src/trustsight/analysis/structural.py):
    # fires on http:// added sources when no checksum was also added.
    {"id": "R007", "name": "Install File Modification", "pattern": r"\+.*\.install.*", "severity": "MEDIUM", "category": "installer", "match_target": "raw_line"},
    {"id": "R008", "name": "Unexpected File Download", "pattern": r"\b(python|ruby|perl)\s+-c\s+https?://", "severity": "HIGH", "category": "network_execution", "match_target": "resolved"},
    # R009 is now a code rule (src/trustsight/analysis/build.py).
    {"id": "R010", "name": "Uses curl in PKGBUILD", "pattern": r"\bcurl\s", "severity": "LOW", "category": "network_usage", "match_target": "raw_line", "scope": ["function_body"]},
    {"id": "R011", "name": "Uses wget in PKGBUILD", "pattern": r"\bwget\s", "severity": "LOW", "category": "network_usage", "match_target": "raw_line", "scope": ["function_body"]},
    {"id": "R012", "name": "LLM Prompt Injection", "pattern": r"ignore\s+(?:all\s+)?previous\s+(?:instructions|commands|input)", "severity": "FATAL", "category": "injection", "match_target": "resolved"},
    {"id": "R013", "name": "Unicode Bidi Override", "pattern": r"[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]", "severity": "FATAL", "category": "unicode", "match_target": "raw_line"},
]

SHARED_CONFIG = {
    "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
    "source_bucket_weights": {"trusted_forge": -10, "official": 0, "raw_hosting": 15, "unknown": 20, "self_hosted": 10},
    "novelty_weights": {"url_first_globally": 15, "url_first_in_package": 10, "maintainer_first_in_package": 20},
    "verification_evidence": {"checksum_present": -10, "validpgpkeys_declared": -10, "gpg_verify_present": -5},
    "pinning_weights": {"checksum_pinned": -5, "tag_pinned": -3, "branch_pinned": 0, "unpinned": 0},
}
