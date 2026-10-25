"""The U-series extension: upstream CI and release integrity (U007-U010).

U007/U008 are federation-fed (a signed ``upstream_repo`` baseline match);
U009 reads an added CI workflow; U010 reads the access mode of a gained
``source=()`` entry.  Nothing here fetches upstream content (A2/A8).
"""

from __future__ import annotations

import pytest

from trustsight.analysis.pipeline import scan_diff
from trustsight.analysis.upstream_release import (
    access_of_source,
    declared_upstream_repo,
    has_validpgpkeys,
    upstream_release_findings,
)
from trustsight.changes import change_delta
from trustsight.ioc_baseline import IocMatch

REPO = "github.com/owner/repo"

BASE = 'pkgname=demo\npkgver=1\npkgrel=1\nurl="https://github.com/owner/repo"\n'


def _collect(diff_text, *, matches=None, current_text=None, config=None):
    delta = change_delta(diff_text, "demo")
    out: list[dict] = []

    def add(rule_id, name, severity, category, match, **extra):
        out.append({"rule_id": rule_id, "severity": severity, "match": match,
                    **extra})

    upstream_release_findings(
        diff_text, delta, add, config or {}, "demo",
        current_text=current_text, matches=matches,
    )
    return out


_NOOP_DIFF = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
    " pkgname=demo\n pkgver=1\n"
)


def _u_ids(fired: list[dict]) -> list[str]:
    """The U-series rule ids, ignoring the always-on W011/W012 boundaries."""
    return [f["rule_id"] for f in fired if not f["rule_id"].startswith("W")]


def _add_workflow(path=".github/workflows/ci.yml") -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n--- /dev/null\n"
        f"+++ b/{path}\n@@ -0,0 +1,1 @@\n+name: CI\n"
    )


def _source_diff(token: str) -> str:
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1,3 +1,4 @@\n"
        " pkgname=demo\n pkgver=1\n pkgrel=1\n"
        f'+source=("{token}")\n'
    )


# -- upstream repository identity -----------------------------------------


def test_a_forge_url_names_the_upstream_repo():
    assert declared_upstream_repo(BASE) == REPO


@pytest.mark.parametrize("url", [
    'url="https://example.com/owner/repo"',
    'url="https://github.com/owner"',
    'url=""',
])
def test_a_non_forge_url_names_no_repo(url):
    assert declared_upstream_repo(f"pkgname=demo\n{url}\n") == ""


# -- U007 / U008 federation -----------------------------------------------


@pytest.mark.parametrize("shape, rule_id", [
    ("exfil", "U007"),
    ("", "U007"),
    ("history_sweep", "U008"),
])
def test_a_federated_shape_files_its_rule(shape, rule_id):
    matches = [IocMatch(type="upstream_repo", value=REPO, source="feed", shape=shape)]
    fired = _collect(_NOOP_DIFF, current_text=BASE, matches=matches)
    assert _u_ids(fired) == [rule_id]
    assert fired[0]["severity"] == "MEDIUM"
    assert fired[0]["upstream_repo"] == REPO
    assert fired[0]["weight_override"] == 0


def test_federation_is_silent_without_a_match():
    fired = _collect(_NOOP_DIFF, current_text=BASE)
    assert [f for f in fired if f["rule_id"] in ("U007", "U008")] == []


def test_a_pkgver_bump_corroborates_the_federation_finding():
    bumped = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
        " pkgname=demo\n-pkgver=1\n+pkgver=2\n pkgrel=1\n"
        ' url="https://github.com/owner/repo"\n'
    )
    matches = [IocMatch(type="upstream_repo", value=REPO, source="feed")]
    fired = _collect(bumped, current_text=BASE.replace("pkgver=1", "pkgver=2"),
                     matches=matches)
    assert fired[0]["pkgver_bumped"] is True
    assert "pkgver bumped" in fired[0]["match"]


# -- U009 new CI surface ---------------------------------------------------


def test_an_added_workflow_is_low_and_weighs_zero():
    fact = scan_diff(_add_workflow(), package_name="demo")
    entries = [e for e in fact.score_breakdown if e.rule_id == "U009"]
    assert entries, "U009 did not fire on an added workflow"
    assert entries[0].severity == "LOW"
    assert entries[0].weight == 0


def test_an_added_non_workflow_file_is_not_ci_surface():
    diff = (
        "diff --git a/README.md b/README.md\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/README.md\n@@ -0,0 +1,1 @@\n+hi\n"
    )
    fact = scan_diff(diff, package_name="demo")
    assert not [e for e in fact.score_breakdown if e.rule_id == "U009"]


# -- U010 unauditable upstream --------------------------------------------


@pytest.mark.parametrize("token, access", [
    ("git+ssh://git@internal.example/x.git", "ssh"),
    ("git@internal.example:x.git", "ssh"),
    ("file:///srv/src/x.tar.gz", "file"),
    ("http://user:token@example.com/x.tar.gz", "embedded_credentials"),
    ("https://10.1.2.3/x.tar.gz", "private_network"),
])
def test_access_of_source_classifies_the_transport(token, access):
    assert access_of_source(token)[0] == access


@pytest.mark.parametrize("token", [
    "git+ssh://git@internal.example/x.git",
    "file:///srv/src/x.tar.gz",
    "https://10.1.2.3/x.tar.gz",
    "ftp://user:token@example.com/x.tar.gz",
])
def test_each_unauditable_transport_files_u010(token):
    fired = _collect(_source_diff(token), current_text=BASE)
    assert _u_ids(fired) == ["U010"]
    assert fired[0]["severity"] == "MEDIUM"


def test_a_public_source_is_not_u010():
    fired = _collect(_source_diff("https://example.com/x.tar.gz"), current_text=BASE)
    assert _u_ids(fired) == []


@pytest.mark.parametrize("token, access", [
    ("demo::git+ssh://git@internal.example/x.git", "ssh"),
    ("demo::file:///srv/src/x.tar.gz", "file"),
    ("demo::https://10.1.2.3/x.tar.gz", "private_network"),
])
def test_renamed_sources_are_classified_after_stripping_the_name(token, access):
    assert access_of_source(token)[0] == access
    assert _u_ids(_collect(_source_diff(token), current_text=BASE)) == ["U010"]


def test_u010_amplifies_when_validpgpkeys_is_absent():
    fired = _collect(_source_diff("git+ssh://git@internal.example/x.git"),
                     current_text=BASE)
    assert fired[0]["amplified"] is True


def test_u010_does_not_amplify_when_validpgpkeys_vouches():
    fired = _collect(
        _source_diff("git+ssh://git@internal.example/x.git"),
        current_text=BASE + "validpgpkeys=('DEADBEEF')\n",
    )
    assert fired[0]["amplified"] is False


def test_c020_keeps_a_public_credential_url():
    fired = _collect(_source_diff("http://user:token@example.com/x.tar.gz"),
                     current_text=BASE)
    assert _u_ids(fired) == []


def test_validpgpkeys_is_read_from_the_recipe():
    assert has_validpgpkeys(BASE + 'validpgpkeys=("A" "B")\n')
    assert not has_validpgpkeys(BASE)


# -- W011 / W012 upstream boundaries --------------------------------------


def test_w011_names_the_unread_upstream_once():
    fired = _collect(_NOOP_DIFF, current_text=BASE)
    w011 = [f for f in fired if f["rule_id"] == "W011"]
    assert len(w011) == 1
    assert w011[0]["severity"] == "INFO"
    assert w011[0]["upstream_repo"] == REPO


def test_w011_is_silent_without_a_forge_upstream():
    plain = 'pkgname=demo\npkgver=1\npkgrel=1\nurl="https://example.com/demo"\n'
    fired = _collect(_NOOP_DIFF, current_text=plain)
    assert [f for f in fired if f["rule_id"] == "W011"] == []


def test_w012_fires_when_the_federation_channel_is_cold():
    cfg = {"baselines": {"ioc": {"enabled": False}}}
    fired = _collect(_NOOP_DIFF, current_text=BASE, config=cfg)
    assert [f["rule_id"] for f in fired if f["rule_id"] == "W012"] == ["W012"]


def test_w012_is_silent_when_the_channel_was_consulted():
    matches = [IocMatch(type="upstream_repo", value=REPO, source="feed")]
    fired = _collect(_NOOP_DIFF, current_text=BASE, matches=matches)
    assert [f for f in fired if f["rule_id"] == "W012"] == []


def test_the_upstream_boundaries_are_weight_zero():
    cfg = {"baselines": {"ioc": {"enabled": False}}}
    fact = scan_diff(_NOOP_DIFF, package_name="demo", current_text=BASE, config=cfg)
    for rule_id in ("W011", "W012"):
        entries = [e for e in fact.score_breakdown if e.rule_id == rule_id]
        assert entries, f"{rule_id} did not fire"
        assert entries[0].severity == "INFO"
        assert entries[0].weight == 0


# -- hardening: the boundaries never fail the run ---------------------------


import sqlite3  # noqa: E402

from trustsight import ioc_baseline  # noqa: E402


@pytest.mark.parametrize("config", [
    None,
    {"baselines": None},
    {"baselines": {"ioc": None}},
    {"baselines": "not-a-dict"},
    ["not", "a", "dict"],
    42,
])
def test_odd_configs_do_not_fail_the_boundaries(config):
    fired = _collect(_NOOP_DIFF, current_text=BASE, config=config)
    assert [f["rule_id"] for f in fired if f["rule_id"].startswith("W")]


@pytest.mark.parametrize("error", [
    sqlite3.OperationalError("no such table"),
    sqlite3.ProgrammingError("wrong thread"),
    RuntimeError("store exploded"),
])
def test_w012_survives_an_unreachable_store(monkeypatch, error):
    def boom():
        raise error

    monkeypatch.setattr(ioc_baseline, "has_upstream_repo_entries", boom)
    fired = _collect(_NOOP_DIFF, current_text=BASE, config={})
    assert "W012" in [f["rule_id"] for f in fired]


def test_has_upstream_repo_entries_is_false_on_a_broken_store(monkeypatch):
    class Boom:
        def __enter__(self):
            raise sqlite3.OperationalError("locked")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(ioc_baseline, "get_connection", lambda: Boom())
    assert ioc_baseline.has_upstream_repo_entries() is False


def test_a_non_iterable_matches_injection_is_a_miss_not_a_crash():
    fired = _collect(_NOOP_DIFF, current_text=BASE, matches=object())
    ids = [f["rule_id"] for f in fired]
    assert "W011" in ids and "W012" not in ids
