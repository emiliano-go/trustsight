"""Malicious false positives from the 2026-11-20 watcher triage.

Five shapes, each firing on a recipe a reviewer can account for:

* H091 counted one ``md5sums`` entry where the array declared two, because
  the first entry carried an inline comment (flutter-bin);
* H089 read an ``install`` destination as packaged *content* when a heredoc
  opened earlier in the hunk never closed on its context-line terminator;
* C015 read the word "links" inside a printed message as the ``links``
  browser and claimed ``package()`` fetched (hush-shell);
* H069 reported the package's own generated test script (python-webdataset);
* the bucket table did not know Unity's Hub CDN, the Gosuslugi plugin host,
  the Dolphin Anty CDN, Arch's GitLab, or the vendor prefixes Flutter and
  Outline publish from on shared object stores.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))
sys.path.insert(0, str(_ROOT))

from calibration_gates import shipped_config  # noqa: E402

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.analysis.structural._checksums import _package_fetch_client  # noqa: E402
from trustsight.buckets import classify_url  # noqa: E402
from trustsight.config import load_config, load_domains, load_rules  # noqa: E402
from trustsight.differ._checksums import _quoted_items  # noqa: E402


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


# --- H091: an inline comment does not end the array -----------------------

def test_checksum_array_item_after_an_inline_comment_is_counted():
    assert _quoted_items("('a' # upstream uses md5\n 'b')") == ["'a'", "'b'"]


def test_h091_silent_when_the_second_entry_follows_a_comment():
    body = (
        "source=('a.tar.xz' 'b.sh')\n"
        "md5sums=('aaaa' # upstream uses md5\n"
        "         'bbbb')\n"
    )
    assert "H091" not in _scan(_add_diff(body))


# --- H089: a heredoc closes on a context-line terminator ------------------

def test_h089_silent_when_a_heredoc_close_is_a_context_line():
    # The `cat` heredoc closes on an unchanged context line; the install
    # destination after it names $pkgdir, which is where a file goes, not
    # build-only content staged into the package.
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,8 @@\n"
        " package() {\n"
        "+  cat >> \"$pkgdir/opt/x/exclude\" << END\n"
        "+dart_aur\n"
        " END\n"
        "+  install -Dm644 helper.sh \"$pkgdir/opt/x/bin/helper\"\n"
        " }\n"
    )
    assert "H089" not in _scan(diff)


# --- C015: a client inside a printed message is text ----------------------

def test_package_fetch_client_ignores_quoted_prose():
    line = "  echo 'Next, as your user:  hush install  (links the config)'"
    assert _package_fetch_client(line) is None


def test_package_fetch_client_still_sees_a_command_substitution():
    assert _package_fetch_client('  x="$(curl -fsSL https://example.org/x)"')


def test_c015_silent_on_the_hush_shell_echo():
    body = "  echo 'Next, as your user:  hush install  (links the config into ~/.config)'\n"
    assert "C015" not in _scan(_add_diff(f"package() {{\n{body}}}\n"))


# --- H069: check() generating and running its own test is the harness -----

def test_h069_silent_for_a_generated_test_in_check():
    body = (
        "check() {\n"
        "  cat > _check_roundtrip.py <<'PY'\n"
        "print('ok')\n"
        "PY\n"
        "  python _check_roundtrip.py\n"
        "}\n"
    )
    assert "H069" not in _scan(_add_diff(body))


# --- buckets: vendors and path-scoped shared stores -----------------------

def test_vendor_hosts_are_official():
    with shipped_config():
        config = load_domains()
        for url in (
            "https://hub-dist.unity3d.com/artifactory/hub-debian-prod-local/x.deb",
            "https://gu-st.ru/content/Gosplugin/Gosplugin_Linux-Debian_Installer.deb.zip",
            "https://dolphin-anty-cdn.com/anty-app/dolphin-anty-linux-amd64-latest.deb",
            "https://gitlab.archlinux.org/api/v4/projects/1/repository/files/x/raw",
        ):
            assert classify_url(url, config)[0] == "official", url


def test_shared_store_is_official_only_for_the_vendor_prefix():
    with shipped_config():
        config = load_domains()
        assert classify_url(
            "https://storage.googleapis.com/flutter_infra_release/releases/x.tar.xz",
            config)[0] == "official"
        assert classify_url(
            "https://s3.amazonaws.com/outline-releases/client/x.deb",
            config)[0] == "official"
        # Another tenant's bucket on the same host stays unknown.
        assert classify_url(
            "https://storage.googleapis.com/other-tenant/x.tar.xz",
            config)[0] == "unknown"
        assert classify_url(
            "https://s3.amazonaws.com/other-bucket/x.deb", config)[0] == "unknown"


def test_stegsolve_and_cursor_release_hosts_are_official():
    with shipped_config():
        config = load_domains()
        assert classify_url(
            "http://www.narthorn.com/challenges/stegsolve.jar", config)[0] == "official"
        assert classify_url(
            "https://downloads.cursor.com/grokbot/stable/x/linux/x64/grok.deb",
            config)[0] == "official"


def test_project_code_host_and_font_author_are_official():
    with shipped_config():
        config = load_domains()
        assert classify_url(
            "https://cnb.cool/rinnein/szu/your-szu-life/x.tar.gz", config)[0] == "official"
        assert classify_url("http://viznut.fi/fonts/x.ttf", config)[0] == "official"
