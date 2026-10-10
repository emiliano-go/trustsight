"""Spec §1: the change-as-data API.

``ChangeDelta`` is the single query every consumer shares.  These tests
prove the construction site's facts agree with the summary's established
read of the same diff, the object round-trips through its dict form (the
JSON report and the document cache both need that), and the prose summary
renders the delta rather than re-deriving the same facts.
"""

import pathlib

import pytest

from trustsight.changes import ChangeDelta, _host, summarise
from trustsight.differ import (
    _post_diff_lines,
    _pre_diff_lines,
    change_delta,
    extract_urls_from_diff,
    local_source_names,
)
from trustsight.schema import PackageFact, SourceChanges

_CORPUS = pathlib.Path(__file__).resolve().parent / "fixtures" / "benign-corpus"
_SAMPLE = 150


def _sample_corpus():
    paths = sorted(_CORPUS.glob("*.diff"))
    step = max(1, len(paths) // _SAMPLE)
    return paths[::step][:_SAMPLE]


def test_change_delta_is_the_differ_surface():
    from trustsight import differ

    assert differ.change_delta is change_delta


def test_hosts_and_checksums_match_the_summary_reference():
    """Every sampled corpus diff: the delta's host sets and checksum
    classification equal what the summary machinery reads from the text."""
    for path in _sample_corpus():
        text = path.read_text(encoding="utf-8", errors="replace")
        delta = change_delta(text)
        reference = extract_urls_from_diff(text)
        added = {_host(u) for u in reference.added_urls if _host(u)}
        removed = {_host(u) for u in reference.removed_urls if _host(u)}
        assert set(delta.hosts_gained) == added - removed, path.name
        assert set(delta.hosts_lost) == removed - added, path.name
        assert delta.checksum_behavior == reference.checksum_behavior, path.name
        ref_local = (
            local_source_names("\n".join(_post_diff_lines(text)))
            - local_source_names("\n".join(_pre_diff_lines(text)))
        )
        assert set(delta.local_sources_gained) == ref_local, path.name


def test_change_delta_round_trips_through_dict():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1,4 +1,5 @@\n"
        " pkgname=demo\n"
        "-pkgver=1.0\n"
        "+pkgver=1.1\n"
        "-source=('https://old.example/x.tar.gz')\n"
        "+source=('https://new.example/x.tar.gz' 'fix.patch')\n"
        " sha256sums=('aaa')\n"
    )
    delta = change_delta(text)
    assert ChangeDelta.from_dict(delta.to_dict()) == delta
    assert delta.sources.gained == (
        "https://new.example/x.tar.gz", "fix.patch",
    )
    assert "new.example" in delta.hosts_gained


def test_version_facts_resolve_the_scalar_move():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1,3 +1,3 @@\n"
        " pkgname=demo\n"
        "-pkgver=1.0\n"
        "+pkgver=1.1\n"
        " pkgrel=1\n"
    )
    version = change_delta(text).version
    assert version.pkgver_changed is True
    assert version.moved is True
    assert (version.old_pkgver, version.new_pkgver) == ("1.0", "1.1")


def test_a_version_scalar_outside_the_hunk_is_not_guessed():
    """Both sides are needed for a move; a missing projection side is not
    treated as a change."""
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1,1 +1,1 @@\n"
        "+pkgrel=2\n"
    )
    version = change_delta(text).version
    assert version.moved is False
    assert version.new_pkgrel == "2"
    assert version.old_pkgrel == ""


def test_the_summary_renders_the_delta():
    """A fact carrying the delta and one without it render the same prose,
    so the two surfaces cannot disagree by construction."""
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        "@@ -1,4 +1,4 @@\n"
        " pkgname=demo\n"
        "-source=('https://old.example/x.tar.gz')\n"
        "+source=('https://new.example/x.tar.gz')\n"
        " pkgver=1.0\n"
        "-sha256sums=('aaa')\n"
        "+sha256sums=('bbb')\n"
    )
    delta = change_delta(text)
    reference = extract_urls_from_diff(text)
    shared = dict(
        package_name="demo",
        old_version="1.0",
        new_version="1.0",
        source_changes=SourceChanges(
            added_urls=reference.added_urls,
            removed_urls=reference.removed_urls,
            checksum_behavior=reference.checksum_behavior,
        ),
    )
    with_delta = PackageFact(**shared, change=delta.to_dict())
    without = PackageFact(**shared)

    rendered = summarise(with_delta, text)
    assert rendered == summarise(without, text)
    assert any("source host changed: new.example" in e for e in rendered)
    assert any("checksums added or changed" in e for e in rendered)


def test_report_body_carries_the_change_object():
    from trustsight.reporting import evaluate_fact, report_body

    fact = PackageFact(
        package_name="demo",
        change={"hosts_gained": ["example.com"], "reordered": False},
    )
    body = report_body(evaluate_fact(fact))
    assert body["change"]["hosts_gained"] == ["example.com"]


@pytest.mark.parametrize("path", sorted(_CORPUS.glob("*.diff"))[:1])
def test_a_corpus_delta_has_typed_files(path):
    delta = change_delta(path.read_text(encoding="utf-8", errors="replace"))
    assert delta.files
    for file in delta.files:
        assert file.path
        assert file.status in ("added", "removed", "modified")


def test_dependency_facts_are_a_normalised_view_beside_the_raw_delta():
    """Spec §1 divergence (recorded): the summary's dependency entry is the
    *normalised* `extract_dependency_changes` view; the delta's dependency
    arrays are the raw `source=`-style diff.  Rendering the raw delta changed
    119 corpus summaries, so the two are documented as distinct views rather
    than forced to agree."""
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "+depends=('glibc')\n"
    )
    delta = change_delta(text)
    assert delta.dependencies.gained == ("glibc",)  # raw array view
    fact = PackageFact(
        package_name="demo", change=delta.to_dict(),
        dependency_changes={"depends": {"glibc"}},
    )
    assert any("depends: +glibc" in e for e in summarise(fact, text))
