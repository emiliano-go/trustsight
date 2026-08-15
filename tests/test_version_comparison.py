"""Plan §13 - the VCS local-rebuild bug, and the version contract behind it.

Reported: ``trustsight inspect oolite-git`` printed

    1:1.93.1.r7964.8646e821-1 -> 1.93.1.r7961.93d62158

an update arrow pointing at an *older* commit.  Two different objects were
being compared - a full ``[epoch:]pkgver-pkgrel`` built locally against the
bare ``pkgver=`` line in the AUR PKGBUILD - and for a VCS package the AUR
side is a placeholder that ``pkgver()`` replaces at build time, so it is
routinely behind whatever the last local rebuild produced.

The contract: unresolvable is INCONCLUSIVE, never a silent arrow.
"""

from trustsight.analysis.version import (
    COMPARISON_AHEAD,
    COMPARISON_BEHIND,
    COMPARISON_INCONCLUSIVE,
    COMPARISON_SAME,
    compare_installed_to_aur,
    has_vcs_source,
    is_vcs_package,
    parse_version,
)
from trustsight.cli.display import no_aur_change_note, version_transition
from trustsight.schema import PackageFact


# --- parsing ----------------------------------------------------------------


def test_a_full_version_splits_into_its_three_parts():
    v = parse_version("1:1.93.1.r7964.8646e821-1")
    assert (v.epoch, v.pkgver, v.pkgrel) == (1, "1.93.1.r7964.8646e821", "1")
    assert v.full is True


def test_a_bare_pkgver_is_marked_as_not_full():
    """The distinction is the whole point: it is what must not be compared."""
    v = parse_version("1.93.1.r7961.93d62158")
    assert (v.epoch, v.pkgver, v.pkgrel) == (0, "1.93.1.r7961.93d62158", None)
    assert v.full is False


def test_an_absent_or_unparseable_version_is_none():
    assert parse_version("") is None
    assert parse_version(None) is None
    assert parse_version("$_commit-$pkgrel") is None
    assert parse_version("1:2:3-1") is None


# --- VCS detection ----------------------------------------------------------


def test_a_pkgver_function_marks_a_package_as_vcs():
    """The declared fact, not the name: pkgver is computed at build time."""
    assert is_vcs_package("anything", "pkgver() {\n  git describe\n}\n")


def test_a_commit_pinned_vcs_source_alone_is_still_comparable():
    """"Uses git" is not the property; "computes its version" is.

    A ``git+https`` source pinned to a commit with a plain ``pkgver=0.7``
    declares its version like any other package (accounts-qml-module is a
    real example).  Calling that incomparable would replace a wrong arrow
    with a wrong shrug.
    """
    pkgbuild = (
        "pkgver=0.7\n"
        "source=(git+https://gitlab.com/accounts-sso/mod#commit=$_commit)\n"
    )
    assert not is_vcs_package("accounts-qml-module", pkgbuild)
    assert has_vcs_source(pkgbuild)


def test_a_vcs_suffix_decides_only_when_the_pkgbuild_is_missing():
    """Without the file, ``-git`` is the best evidence there is."""
    assert is_vcs_package("oolite-git", "")
    assert not is_vcs_package("thing-svn", "pkgver=1.0\nsource=('https://x/t.tar.gz')")


def test_an_ordinary_package_is_not_vcs():
    assert not is_vcs_package("firefox", "pkgver=1.0\nsource=('https://x/f.tar.gz')")
    # a git *URL* that is not a VCS source scheme is a plain tarball host
    assert not has_vcs_source("source=('https://github.com/u/t/archive/v1.tar.gz')")


# --- the comparison ---------------------------------------------------------


def test_the_reported_case_is_inconclusive_not_an_update():
    assert compare_installed_to_aur(
        "1:1.93.1.r7964.8646e821-1", "1.93.1.r7961.93d62158", is_vcs=True,
    ) == COMPARISON_INCONCLUSIVE


def test_an_aur_pkgver_ahead_of_the_installed_one_is_an_update():
    assert compare_installed_to_aur("1.0-1", "1.1") == COMPARISON_AHEAD


def test_the_same_pkgver_with_a_pkgrel_is_not_a_change():
    """pkgrel is a packaging revision the AUR pkgver line does not carry."""
    assert compare_installed_to_aur("1.2.3-4", "1.2.3") == COMPARISON_SAME


def test_a_locally_newer_version_is_not_reported_as_an_update():
    """A backwards move is not a change, whatever the arrow used to say."""
    assert compare_installed_to_aur("2.0-1", "1.9") == COMPARISON_BEHIND


def test_epoch_decides_before_pkgver():
    assert compare_installed_to_aur("1:1.0-1", "9.0") == COMPARISON_BEHIND
    assert compare_installed_to_aur("1.0-1", "1:0.1") == COMPARISON_AHEAD


def test_two_full_versions_compare_as_full_versions():
    assert compare_installed_to_aur("1.2.3-1", "1.2.3-2") == COMPARISON_AHEAD


def test_an_unresolved_side_is_inconclusive_never_clean():
    assert compare_installed_to_aur("", "1.0") == COMPARISON_INCONCLUSIVE
    assert compare_installed_to_aur("1.0-1", "") == COMPARISON_INCONCLUSIVE
    assert compare_installed_to_aur("1.0-1", "$_commit") == COMPARISON_INCONCLUSIVE


# --- rendering --------------------------------------------------------------


def _fact(**kwargs) -> PackageFact:
    return PackageFact(package_name="oolite-git", **kwargs)


def test_an_inconclusive_comparison_never_renders_an_arrow():
    text = version_transition(_fact(
        old_version="1:1.93.1.r7964.8646e821-1",
        new_version="1.93.1.r7961.93d62158",
        version_comparison=COMPARISON_INCONCLUSIVE,
    ))
    assert "->" not in text
    assert "not comparable" in text
    assert "1:1.93.1.r7964.8646e821-1 installed" in text


def test_a_real_update_still_renders_an_arrow():
    text = version_transition(_fact(
        old_version="1.0-1", new_version="1.1",
        version_comparison=COMPARISON_AHEAD,
    ))
    assert text == "1.0-1 -> 1.1"


def test_an_unchanged_package_shows_one_version():
    text = version_transition(_fact(
        old_version="1.2.3-4", new_version="1.2.3",
        version_comparison=COMPARISON_SAME,
    ))
    assert text == "1.2.3-4"


def test_the_no_change_note_names_the_commit_and_the_reason():
    note = no_aur_change_note(_fact(
        old_commit="8646e821abc", new_commit="8646e821abc",
        version_comparison=COMPARISON_INCONCLUSIVE,
    ))
    assert note == (
        "No changes in the AUR since last review (commit 8646e82).  "
        "Your installed version differs because this is a VCS package "
        "rebuilt locally."
    ) or note.startswith("No changes in the AUR since last review (commit 8646e821)")
    assert "VCS package rebuilt locally" in note


def test_the_no_change_note_is_silent_when_the_commit_moved():
    assert no_aur_change_note(_fact(old_commit="aaa", new_commit="bbb")) is None
    assert no_aur_change_note(_fact(old_commit="", new_commit="bbb")) is None


def test_a_non_vcs_package_with_no_new_commit_omits_the_vcs_sentence():
    note = no_aur_change_note(_fact(
        old_commit="cafebabe1", new_commit="cafebabe1",
        version_comparison=COMPARISON_SAME,
    ))
    assert note == "No changes in the AUR since last review (commit cafebabe)."


# --- the CLI surfaces -------------------------------------------------------


def test_inspect_status_leads_with_the_no_change_note():
    from trustsight.cli.inspect import _status_text

    fact = _fact(
        old_commit="8646e821abc", new_commit="8646e821abc",
        version_comparison=COMPARISON_INCONCLUSIVE,
        first_seen=False,
    )
    assert _status_text(fact).startswith("No changes in the AUR since last review")


def test_review_row_renders_the_not_comparable_form():
    from trustsight.cli.review import _version_cell

    cell = _version_cell({
        "old_version": "1:1.93.1.r7964.8646e821-1",
        "new_version": "1.93.1.r7961.93d62158",
        "version_comparison": COMPARISON_INCONCLUSIVE,
    })
    assert "→" not in cell
    assert "not comparable" in cell


def test_review_row_keeps_the_arrow_for_a_real_update():
    from trustsight.cli.review import _version_cell

    cell = _version_cell({
        "old_version": "1.0-1", "new_version": "1.1",
        "version_comparison": COMPARISON_AHEAD,
    })
    assert "→" in cell


def test_json_output_carries_the_comparison():
    """A machine consumer needs the caveat the table shows."""
    from trustsight.reporting import evaluate_fact, report_body

    data = report_body(evaluate_fact(_fact(
        old_version="1:1.0-1", new_version="0.9",
        version_comparison=COMPARISON_INCONCLUSIVE,
    )))
    assert data["version_comparison"] == COMPARISON_INCONCLUSIVE
