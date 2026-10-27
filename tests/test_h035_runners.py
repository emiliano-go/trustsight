"""H035 also sees the one-shot runners that resolve and execute in place."""

from trustsight.analysis import _structural_findings
from trustsight.differ import extract_urls_from_diff


def structural(diff_text: str) -> list[dict]:
    return _structural_findings(
        diff_text, extract_urls_from_diff(diff_text), {}, config={})


def ids(diff_text: str) -> set[str]:
    return {f["rule_id"] for f in structural(diff_text)}


def _hook(line: str) -> str:
    return f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,5 @@
 pkgname=x
+post_install() {{
+  {line}
+}}
"""


def test_h035_fires_on_npx_in_an_install_hook():
    assert "H035" in ids(_hook("npx evil-pkg"))


def test_h035_fires_on_uvx_in_an_install_hook():
    assert "H035" in ids(_hook("uvx evil-pkg"))


def test_h035_fires_on_docker_run_in_an_install_hook():
    assert "H035" in ids(_hook("docker run --rm evil/image"))


def test_h035_stays_quiet_when_the_runner_is_only_printed():
    assert "H035" not in ids(_hook('echo "run npx evil-pkg"'))
