"""Behavioural tests for the Phase 3 install-path persistence cluster
(R077/R084/R085/R088/R114).

Each rule is asserted in both directions: the attack case fires, and the
plan's declared must-not-fire surface stays silent.  R088 is the quietest
rule: a hidden write that is executed belongs to R121/R124, one in a
world-writable dir to R084, one in the user's home to R077 — so no single
piece of evidence ever triple-fires.
"""

from trustsight.analysis import _structural_findings
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


# --- R077: writes into the user's home / rc files ---


def test_r077_fires_on_home_rc_write():
    ids = rule_ids(structural(_diff("build() {\n  echo x > \"$HOME/.bashrc\"\n}\n")))
    assert "R077" in ids


def test_r077_fires_on_install_to_home():
    ids = rule_ids(structural(_diff("build() {\n  install -Dm755 evil \"$HOME/.local/bin/evil\"\n}\n")))
    assert "R077" in ids


def test_r077_ignores_pkgdir_staging():
    ids = rule_ids(structural(
        _diff("package() {\n  install -Dm644 foo \"$pkgdir/etc/skel/.config\"\n}\n")
    ))
    assert "R077" not in ids


def test_r077_ignores_echo_string_mentioning_cp():
    ids = rule_ids(structural(_diff(
        "post_install() {\n  echo \"You have to execute 'cp /usr/share/x/zshrc ~/.zshrc' to use it.\"\n}\n"
    )))
    assert "R077" not in ids


def test_r077_ignores_home_env_export():
    ids = rule_ids(structural(_diff(
        "build() {\n  export XDG_CONFIG_HOME=\"${XDG_CONFIG_HOME:-$HOME/.config}\"\n}\n"
    )))
    assert "R077" not in ids


# --- R084: world-writable staging ---


def test_r084_fires_on_tmp_write():
    ids = rule_ids(structural(_diff("build() {\n  echo x > /tmp/evil.sh\n}\n")))
    assert "R084" in ids


def test_r084_fires_on_tmp_working_dir():
    ids = rule_ids(structural(_diff("build() {\n  cd /tmp\n}\n")))
    assert "R084" in ids


def test_r084_fires_on_exec_from_world_writable():
    ids = rule_ids(structural(_diff("build() {\n  bash /dev/shm/evil.sh\n}\n")))
    assert "R084" in ids


def test_r084_ignores_mktemp():
    ids = rule_ids(structural(_diff("prepare() {\n  d=\"$(mktemp -d)\"\n}\n")))
    assert "R084" not in ids


def test_r084_ignores_tmpdir_mention_without_action():
    ids = rule_ids(structural(_diff(
        "post_install() {\n  for OS_TMPDIR in \"$TMPDIR\" \"$TMP\" \"$TEMP\" /tmp\n  do :\n  done\n}\n"
    )))
    assert "R084" not in ids


def test_r084_ignores_staged_tmp_dir():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x \"$pkgdir/usr/lib/foo/tmp/config\"\n}\n"
    )))
    assert "R084" not in ids


# --- R085: systemd ExecStart from a runtime-writable path ---


def test_r085_fires_on_unit_execstart_in_tmp():
    ids = rule_ids(structural(_diff(
        "build() {\n  cat > evil.service <<EOF\n[Service]\nExecStart=/tmp/evil\nEOF\n}\n"
    )))
    assert "R085" in ids


def test_r085_fires_on_home_execstart():
    ids = rule_ids(structural(_diff(
        "build() {\n  cat > evil.service <<EOF\n[Service]\nExecStart=\"$HOME/evil\"\nEOF\n}\n"
    )))
    assert "R085" in ids


def test_r085_ignores_benign_execstart():
    ids = rule_ids(structural(_diff(
        "build() {\n  cat > ok.service <<EOF\n[Service]\nExecStart=/usr/bin/ok\nEOF\n}\n"
    )))
    assert "R085" not in ids


def test_r085_ignores_desktop_exec():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 foo.desktop \"$pkgdir/usr/share/applications/foo.desktop\"\n}\n"
    )))
    assert "R085" not in ids


# --- R088: hidden drop outside the build trees ---


def test_r088_fires_on_hidden_drop():
    ids = rule_ids(structural(_diff("build() {\n  echo x > .evil.sh\n}\n")))
    assert "R088" in ids


def test_r088_silent_when_hidden_file_executed():
    ids = rule_ids(structural(_diff(
        "build() {\n  echo x > .evil.sh\n  bash .evil.sh\n}\n"
    )))
    assert "R088" not in ids
    assert "R121" in ids


def test_r088_ignores_staged_hidden():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x \"$pkgdir/.hidden\"\n}\n"
    )))
    assert "R088" not in ids


def test_r088_ignores_vcs_hidden():
    ids = rule_ids(structural(_diff(
        "prepare() {\n  echo x > .gitignore\n  mkdir -p .github\n}\n"
    )))
    assert "R088" not in ids


def test_r088_silent_when_hidden_in_tmp():
    ids = rule_ids(structural(_diff("build() {\n  echo x > /tmp/.evil\n}\n")))
    assert "R088" not in ids
    assert "R084" in ids


def test_r088_silent_when_hidden_in_home():
    ids = rule_ids(structural(_diff("build() {\n  echo x > \"$HOME/.evil\"\n}\n")))
    assert "R088" not in ids
    assert "R077" in ids


def test_r088_no_double_fire_with_r121():
    findings = structural(_diff("build() {\n  echo x > .evil.sh\n  bash .evil.sh\n}\n"))
    assert [f["rule_id"] for f in findings].count("R121") == 1
    assert "R088" not in {f["rule_id"] for f in findings}


# --- R114: pacman hook installation ---


def test_r114_fires_on_hook_install():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x.hook \"$pkgdir/usr/share/libalpm/hooks/x.hook\"\n}\n"
    )))
    assert "R114" in ids


def test_r114_fires_on_hook_install_t_dir():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x.hook -t \"$pkgdir/usr/share/libalpm/hooks\"\n}\n"
    )))
    assert "R114" in ids


def test_r114_ignores_non_hook_install():
    ids = rule_ids(structural(_diff(
        "package() {\n  install -Dm644 x.desktop \"$pkgdir/usr/share/applications/x.desktop\"\n}\n"
    )))
    assert "R114" not in ids
