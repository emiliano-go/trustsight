"""False positives from the 2026-10-26 watcher review.

Each case pins the benign shape that fired and the true-positive twin the
fix must keep.  The batch came from the Electron wrapper refresh (X007,
X011, X013, X024), the Python build in superghidra (H100, X014, X033), and
the cherry-studio helper (H042, R058).
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.analysis.structural._hygiene import capability_in_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


def _diff(lines, *, fn="build", old=("pkgname=p", "pkgver=1", "pkgrel=1")):
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


# X013 - pointing at a public registry is not redirecting the fetch.

def test_x013_a_public_registry_assignment_is_quiet():
    assert "X013" not in _ids([
        'export npm_config_registry="${NPM_CONFIG_REGISTRY:-https://registry.npmjs.org}"',
    ])


def test_x013_a_private_registry_still_fires():
    assert "X013" in _ids([
        'export npm_config_registry="https://packages.evil.example"',
    ])


# X024 - a build-tool path suffix and a local toolchain prepend.

def test_x024_electron_dist_path_suffix_is_quiet():
    assert "X024" not in _ids(['export ELECTRON_OVERRIDE_DIST_PATH="${ELECTRON_DIST}"'])


def test_x024_a_loader_path_still_fires():
    assert "X024" in _ids(['export LD_LIBRARY_PATH="$PWD/lib"'])


def test_x024_a_local_yarn_bin_prepend_is_quiet():
    assert "X024" not in _ids([
        'local _yarnhome="${HOME}/.yarn/install"',
        'export PATH="${_yarnhome}/bin:${PATH}"',
    ])


def test_x024_an_undefined_path_variable_still_fires():
    assert "X024" in _ids(['export PATH="${EVIL}/bin:${PATH}"'])


# X014 - `env=` in Python is not the shell's ENV variable.

def test_x014_lowercase_env_in_a_python_heredoc_is_quiet():
    assert "X014" not in _ids([
        "  cd \"$srcdir/pkg\"",
        "  python - <<'PY'",
        "import subprocess",
        'subprocess.run([], env={**os.environ, "PYTHONPATH": "x"})',
        "PY",
    ])


def test_x014_uppercase_env_assignment_still_fires():
    assert "X014" in _ids(["  ENV=/tmp/evil.sh sh -c true"])


# H100 - `install =` inside a Python heredoc is not an install hook.

def test_h100_python_assignment_named_install_is_quiet():
    assert "H100" not in _ids([
        "  python - <<'PY'",
        "install = subprocess.run(['installer'])",
        "PY",
    ])


def test_h100_a_real_hook_declaration_still_fires():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        " pkgname=p\n+install=p.install\n"
        "--- /dev/null\n+++ b/p.install\n@@ -0,0 +1,3 @@\n"
        "+post_install() {\n+  echo hi\n+}\n"
    )
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(), package_name="p",
            current_text="pkgname=p\ninstall=p.install\n",
        )
    assert "H100" in {e.rule_id for e in fact.score_breakdown}


# X033 - an interpreter heredoc is data for the shell execution rules.

def test_x033_python_heredoc_is_not_a_shell_execution():
    assert "X033" not in _ids([
        "  python - <<'PY'",
        "print('hello')",
        "PY",
    ])


def test_x033_a_srcdir_script_still_fires():
    assert "X033" in _ids(['  bash "$srcdir/stage.sh"'])


# H042 - a relative helper file is inside the build tree.

def test_h042_a_relative_helper_file_is_quiet():
    assert "H042" not in _ids([
        '  local _bindir="resources/binaries/x"',
        '  echo "1" > "${_bindir}/.mise-version"',
    ])


def test_h042_an_absolute_hidden_drop_still_fires():
    assert "H042" in _ids(['  echo "1" > "/opt/.hidden"'])


# H032 - creating $HOME itself is not dropping a file into the profile.

def test_h032_creating_the_home_directory_is_quiet():
    assert "H032" not in _ids(['  mkdir -p "${HOME}" "${HOME}/.cache/tool"'])


def test_h032_a_file_in_home_still_fires():
    assert "H032" in _ids(['  echo x > "${HOME}/.hidden"'])


# R058 - an absolute system binary is a source when -t names a local dest.

def test_r058_system_binary_copied_into_tree_is_quiet():
    assert "R058" not in _ids([
        '  install -m755 "/usr/bin/tool" -t "resources/binaries"',
    ])


def test_r058_an_absolute_destination_still_fires():
    assert "R058" in _ids(['  install -m755 source /usr/bin/tool'])


# C001 - a JavaScript version probe is not a newly executed file.

def test_c001_a_node_version_probe_is_not_a_capability():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        " pkgname=p\n"
        '+_ver="$(node -p "try { require(\'./package.json\').packageManager?.split(\'@\')[1] } catch { }")"\n'
    )
    assert capability_in_diff(diff) is None
