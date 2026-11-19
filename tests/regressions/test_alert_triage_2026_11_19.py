"""Malicious false positives from the 2026-11-19 watcher triage.

Four shapes, each firing on a recipe that a reviewer can account for:

* H032/H042 read a variable that resolves into ``$srcdir`` as the reviewer's
  own home (tsuki-git stages its test home inside the build tree);
* H101 reports a ``-git`` package tracking its git source as lost pinning
  (polo-git folded a build patch into the VCS source);
* C033 reports a wholesale rewrite as a comment-gutting campaign
  (synthos-git removed 21 comments *and* 70 code lines);
* SOURCE_BUCKET did not know Mozilla's ESR download CDN (epixnet).
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.buckets import classify_url  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402


def _scan(diff: str, new_text: str = "", package_name: str = "x") -> set[str]:
    with shipped_config():
        fact = scan_diff(
            diff,
            rules=load_rules(),
            config=load_config(),
            package_name=package_name,
            current_text=new_text,
        )
    return {entry.rule_id for entry in fact.score_breakdown}


def _add_diff(body: str) -> str:
    lines = "".join(f"+{ln}\n" for ln in body.splitlines())
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,%d @@\n"
        "pkgname=x\npkgver=1.0\n%s" % (body.count("\n") + 3, lines)
    )


# --- H032/H042: a variable that resolves inside $srcdir ---------------------
#
# The fixtures are the real 2026-11-19 tsuki-git commit: check() gained
# `local test_home="${srcdir}/test-home"` and then passes `${test_home}/.config`
# to ctest, which the two rules read as the reviewer's own home.  The shape
# needs the whole recipe text, so the fixtures carry it.

_FIXTURES = _ROOT / ".pr-worktrees"  # replaced below by a repo-relative path
_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "alert-triage-2026-11-19"


def _tsuki() -> tuple[str, str]:
    diff = (_FIXTURES / "tsuki-git.diff.txt").read_text()
    new = (_FIXTURES / "tsuki-git-new.PKGBUILD").read_text()
    return diff, new


def test_h032_ignores_variable_that_resolves_into_srcdir():
    diff, new = _tsuki()
    assert "H032" not in _scan(diff, new_text=new, package_name="tsuki-git")


def test_h042_ignores_hidden_write_under_a_staged_variable():
    diff, new = _tsuki()
    assert "H042" not in _scan(diff, new_text=new, package_name="tsuki-git")


def test_h042_still_fires_when_the_variable_has_no_visible_assignment():
    # The exemption is resolution, not a blanket pass for anything that
    # starts with a `$`: an unknown expansion keeps the rule firing.
    ids = _scan(_add_diff('build() {\n  echo x > "${unknown_dir}/.evil"\n}\n'))
    assert "H042" in ids


def test_h032_still_fires_on_a_real_home_write():
    ids = _scan(_add_diff('build() {\n  install -Dm755 evil "$HOME/.local/bin/evil"\n}\n'))
    assert "H032" in ids


# --- H101: a -git package tracks git by design -----------------------------

_PINNED_TO_VCS = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -10,2 +10,2 @@\n"
    '-source=("polo::https://raw.githubusercontent.com/FabioLolix/AUR-artifacts/master/polo-fix-build.patch"\n'
    '-        "v1.0.1.tar.gz::https://example.org/polo-1.0.1.tar.gz")\n'
    '+source=("polo::git+https://github.com/KeremSoke/polo.git")\n'
)


def test_h101_silent_for_a_vcs_package_tracking_git():
    assert "H101" not in _scan(_PINNED_TO_VCS, package_name="polo-git")


def test_h101_still_fires_when_a_plain_package_drops_its_pin():
    assert "H101" in _scan(_PINNED_TO_VCS, package_name="polo")


# --- C033: a wholesale rewrite is not a comment-gutting campaign -----------

def _rewrite_diff(comments: int, code: int) -> str:
    removed = [f"-{'- ' * 0}# comment {i}" for i in range(comments)]
    removed += [f"-install -Dm644 file{i} \"$pkgdir/usr/share/x{i}\"" for i in range(code)]
    added = ['+pkgdesc="rewritten recipe"']
    body = "\n".join(removed + added)
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,200 +1,20 @@\n" + body + "\n"
    )


def test_c033_silent_when_the_diff_removes_code_with_the_prose():
    assert "C033" not in _scan(_rewrite_diff(comments=21, code=70))


def test_c033_fires_when_the_prose_is_gutted_and_the_payload_stays():
    assert "C033" in _scan(_rewrite_diff(comments=21, code=0))


# --- SOURCE_BUCKET: Mozilla's own ESR CDN ---------------------------------

def test_mozilla_esr_download_cdn_is_official():
    url = (
        "https://download-installer.cdn.mozilla.net/pub/firefox/releases/"
        "153.4.0esr/linux-x86_64/en-US/firefox-153.4.0esr.tar.xz"
    )
    with shipped_config():
        bucket, _matched = classify_url(url)
    assert bucket == "official"
