"""S011 self-referential teardown shapes."""

from trustsight.analysis import scan_diff
from trustsight.config import load_config, load_rules


def _shapes(body: str) -> set[str]:
    lines = body.splitlines() or [""]
    added = "\n".join("+" + line for line in lines)
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n"
        " pkgname=x\n pkgver=1\n+package() {\n"
        f"{added}\n+}}\n"
    )
    fact = scan_diff(
        diff, rules=load_rules(), config=load_config(), package_name="x")
    return {
        entry.params["shape"]
        for entry in fact.score_breakdown
        if entry.rule_id == "S011"
    }


def test_self_deletion_is_reported():
    assert "self-delete" in _shapes('rm -f "$0"')


def test_destructive_exit_trap_is_reported():
    assert "destructive-exit-trap" in _shapes("trap 'rm -rf /tmp/x' EXIT")


def test_orphaning_and_signal_suppression_are_reported():
    assert "orphan" in _shapes("nohup ./evil &")
    assert "orphan" in _shapes("( ./evil & )")
    assert "ignore-termination" in _shapes("trap '' TERM HUP")


def test_exec_replacement_and_corpse_forgery_are_reported():
    assert "exec-replacement" in _shapes("exec bash -c true")
    assert "corpse-forgery" in _shapes(
        "install -m755 /dev/null /usr/bin/foo")


def test_payload_erasure_is_reported():
    assert "payload-erasure" in _shapes(
        'bash "$srcdir/p.sh"\nrm -f "$srcdir/p.sh"')


def test_benign_cleanup_and_traps_are_not_reported():
    assert _shapes('rm -rf "$srcdir/build"') == set()
    assert _shapes("trap 'echo done' EXIT") == set()
