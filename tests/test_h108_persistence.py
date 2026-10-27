"""H108: service or cron enabling commands in build/install code."""

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


def test_h108_fires_on_systemctl_enable():
    assert "H108" in ids(_hook("systemctl enable demo.service"))


def test_h108_fires_on_user_service_and_crontab():
    assert "H108" in ids(_hook("systemctl --user enable demo.service"))
    assert "H108" in ids(_hook("crontab -u root /tmp/cron"))


def test_h108_stays_quiet_when_the_command_is_printed():
    assert "H108" not in ids(_hook('echo "systemctl enable demo.service"'))


def test_h108_quiet_on_read_only_cron_and_at_queries():
    assert "H108" not in ids(_hook("crontab -l"))
    assert "H108" not in ids(_hook("at -l"))
