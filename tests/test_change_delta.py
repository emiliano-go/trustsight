"""The change-as-data API.

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
        declared = set(reference.declared_urls)
        added = {_host(u) for u in reference.added_urls
                 if u not in declared and _host(u)}
        removed = {_host(u) for u in reference.removed_urls
                   if u not in declared and _host(u)}
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


def test_added_dependencies_carry_the_normalised_view():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "+depends=('libfoo>=1.2' 'libbar')\n"
        "+optdepends=('libbaz: for extras')\n"
    )
    delta = change_delta(text, "demo")
    assert delta.added_dependencies["depends"] == ("libbar", "libfoo")
    assert delta.added_dependencies["optdepends"] == ("libbaz",)


def test_added_dependencies_match_the_extractor_over_the_corpus():
    """The delta's normalised view must be the extractor's exact answer, so
    the dependency rules read the same facts after the migration."""
    from trustsight.deps import extract_dependency_changes

    for path in _sample_corpus():
        text = path.read_text(encoding="utf-8", errors="replace")
        for pkgbase in ("", "demo"):
            delta = change_delta(text, pkgbase)
            ref = extract_dependency_changes(text, pkgbase)
            assert dict(delta.added_dependencies) == {
                f: tuple(sorted(ref.get(f, ())))
                for f in delta.added_dependencies
            }, (path.name, pkgbase)


def test_relational_arrays_are_deltas():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "+provides=('foo')\n"
        "+conflicts=('bar')\n"
    )
    delta = change_delta(text)
    assert delta.provides.gained == ("foo",)
    assert delta.conflicts.gained == ("bar",)


def test_checksum_parity_and_source_growth():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "+source=('a' 'b')\n"
        "+sha256sums=('x')\n"
    )
    delta = change_delta(text)
    assert delta.checksum_parity == (2, 1, "sha256sums")
    assert delta.source_array_grew is True


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


def test_an_unterminated_source_array_does_not_leak_following_arrays():
    """A hunk showing ``source=(`` without its ``)`` used to read every
    following line - ``_makeopts=(CC=gcc-15 CXX=g++-15)`` - as source
    entries.  The delta must fail closed: the array never closes inside
    the post-state projection, so nothing is gained."""
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,5 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "+source=(\n"
        "+_makeopts=(CC=gcc-15 CXX=g++-15)\n"
    )
    delta = change_delta(text)
    assert delta.sources.gained == ()
    assert delta.sources.lost == ()


def test_a_multiline_source_array_that_closes_still_diffs():
    """The fail-closed drop must not eat a multiline array whose closing
    paren IS visible in the projection."""
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,6 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "+source=(\n"
        "+  'https://x.example/a.tar.gz'\n"
        "+)\n"
    )
    assert change_delta(text).sources.gained == (
        "https://x.example/a.tar.gz",
    )


def test_reemitted_relational_arrays_resolve_through_pkgbase():
    """ddnsto: ``provides``/``conflicts`` re-emitted with the makepkg
    default ``pkgbase=$pkgname`` (``ddnsto-bin``) and the ``${pkgbase%-bin}``
    form resolve to the same names on both sides, so a semantic no-op
    reports no gain or loss - in both the raw delta and the extractor."""
    from trustsight.deps import extract_dependency_changes

    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,5 @@\n"
        " pkgname=ddnsto-bin\n pkgver=1.2\n"
        "-provides=('ddnsto')\n"
        "+provides=('${pkgbase%-bin}')\n"
        "-conflicts=('ddnsto')\n"
        "+conflicts=('${pkgbase%-bin}')\n"
    )
    delta = change_delta(text, "ddnsto-bin")
    assert delta.provides.gained == ()
    assert delta.provides.lost == ()
    assert delta.conflicts.gained == ()
    assert delta.conflicts.lost == ()
    extracted = extract_dependency_changes(text, "ddnsto-bin")
    assert extracted["provides"] == set()
    assert extracted["conflicts"] == set()


def test_a_real_relational_gain_still_reports():
    """The resolution must not stand the rule down: a genuinely new
    provided name still reads as a gain on both surfaces."""
    from trustsight.deps import extract_dependency_changes

    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
        " pkgname=ddnsto-bin\n pkgver=1.2\n"
        "-provides=('ddnsto')\n"
        "+provides=('ddnsto' 'ddnsto-cli')\n"
    )
    delta = change_delta(text, "ddnsto-bin")
    assert delta.provides.gained == ("ddnsto-cli",)
    assert delta.provides.lost == ()
    assert extract_dependency_changes(text, "ddnsto-bin")["provides"] == {
        "ddnsto-cli",
    }


def test_dependency_facts_are_a_normalised_view_beside_the_raw_delta():
    """Divergence (recorded): the summary's dependency entry is the
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


def test_change_delta_validates_added_dependencies_against_the_post_state():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        " pkgname=demo\n+depends=('ghost')\n"
    )
    delta = change_delta(
        diff, "demo", current_text="pkgname=demo\ndepends=('real')\n"
    )
    assert delta.added_dependencies["depends"] == ()
