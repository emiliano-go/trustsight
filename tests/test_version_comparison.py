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
    full_version_from_pkgbuild,
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


# --- the declared version ---------------------------------------------------
#
# Second report, same package: `inspect oolite-git` rendered
#
#     1:1.93.1.r7967.caea422f-2 installed / AUR pkgver 1.93.1.r7966.7ccbff5e
#
# The AUR PKGBUILD declares epoch=1, pkgver=1.93.1.r7966.7ccbff5e and
# pkgrel=2; only the middle field was ever read.


#: The shape of the real oolite-git PKGBUILD, trimmed to the fields that
#: decide a version.
OOLITE_PKGBUILD = (
    "# Maintainer: Lone_Wolf <Lone_Wolf@klaas-de-kat.nl>\n"
    "pkgname=oolite-git\n"
    "pkgver=1.93.1.r7966.7ccbff5e\n"
    "pkgrel=2\n"
    "epoch=1\n"
    "source=(oolite-git::git+https://github.com/OoliteProject/oolite)\n"
    "pkgver() {\n"
    "  git describe --tags\n"
    "}\n"
)


def test_the_declared_version_carries_epoch_and_pkgrel():
    assert full_version_from_pkgbuild(OOLITE_PKGBUILD) == "1:1.93.1.r7966.7ccbff5e-2"


def test_an_absent_epoch_is_omitted_and_so_is_a_zero_one():
    """pacman renders neither, and a spurious ``0:`` would not compare equal."""
    assert full_version_from_pkgbuild("pkgver=1.2.3\npkgrel=1\n") == "1.2.3-1"
    assert full_version_from_pkgbuild("epoch=0\npkgver=1.2.3\npkgrel=1\n") == "1.2.3-1"


def test_quoted_and_commented_assignments_are_read():
    text = 'pkgver="1.2.3"  # upstream tag\npkgrel=\'4\'\nepoch=2\n'
    assert full_version_from_pkgbuild(text) == "2:1.2.3-4"


def test_an_unresolved_pkgver_yields_nothing_rather_than_a_guess():
    """The caller's fallbacks stay in charge; no version is invented."""
    assert full_version_from_pkgbuild("pkgver=$_commit\npkgrel=1\n") == ""
    assert full_version_from_pkgbuild("pkgver=${_ver}\n") == ""
    assert full_version_from_pkgbuild("") == ""


def test_a_pkgver_function_is_not_an_assignment():
    """``pkgver()`` declares nothing; reading it as a value would be a lie."""
    assert full_version_from_pkgbuild("pkgver() {\n  git describe\n}\n") == ""


def test_an_unresolved_pkgrel_leaves_the_pkgver_usable():
    """One unreadable field does not throw away the two that were readable."""
    assert full_version_from_pkgbuild("epoch=1\npkgver=1.2.3\npkgrel=$_rel\n") == "1:1.2.3"


# --- the comparison ---------------------------------------------------------


def test_the_reported_case_is_inconclusive_not_an_update():
    assert compare_installed_to_aur(
        "1:1.93.1.r7964.8646e821-1", "1.93.1.r7961.93d62158", is_vcs=True,
    ) == COMPARISON_INCONCLUSIVE


def test_an_aur_pkgver_ahead_of_the_installed_one_is_an_update():
    assert compare_installed_to_aur("1.0-1", "1.1") == COMPARISON_AHEAD


def test_a_bare_aur_side_still_compares_by_pkgver_alone():
    """A pkgrel that was never declared cannot be a difference.

    Both this and the full-versus-full case below are the contract: what
    changed is that the AUR side can now *be* full, not what a bare one
    means.
    """
    assert compare_installed_to_aur("1.2.3-4", "1.2.3") == COMPARISON_SAME


def test_an_aur_pkgrel_bump_is_an_update():
    """A rebuild is something users are meant to take, and pacman says so.

    Unreachable until the AUR side carried its declared pkgrel: every
    comparison had a bare right-hand side, so a maintainer's pkgrel bump
    rendered as "no change" even though discovery had just listed the
    package as outdated on exactly that difference.
    """
    assert compare_installed_to_aur("1:1.2.3-1", "1:1.2.3-2") == COMPARISON_AHEAD
    assert compare_installed_to_aur("1:1.2.3-2", "1:1.2.3-1") == COMPARISON_BEHIND


def test_a_locally_newer_version_is_not_reported_as_an_update():
    """A backwards move is not a change, whatever the arrow used to say."""
    assert compare_installed_to_aur("2.0-1", "1.9") == COMPARISON_BEHIND


def test_epoch_decides_before_pkgver():
    assert compare_installed_to_aur("1:1.0-1", "9.0") == COMPARISON_BEHIND
    assert compare_installed_to_aur("1.0-1", "1:0.1") == COMPARISON_AHEAD


def test_a_declared_epoch_on_both_sides_is_not_a_difference():
    """The second oolite-git report, reduced to its non-VCS core.

    With the epoch dropped from the AUR side, a package that declares
    ``epoch=1`` on both sides compared 1 against 0 and came out as
    *installed ahead* - a real update reported as a backwards move. This is
    the case the extraction fix exists for; ``test_epoch_decides_before_pkgver``
    above still pins what a genuinely bare side means.
    """
    assert compare_installed_to_aur("1:2.0-1", "1:2.1-1") == COMPARISON_AHEAD
    assert compare_installed_to_aur("1:2.0-1", "1:2.0-1") == COMPARISON_SAME


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


def test_the_version_line_says_why_it_declined_to_compare():
    """Naming the cause is the difference between this report and the next."""
    text = version_transition(_fact(
        old_version="1:1.93.1.r7967.caea422f-2",
        new_version="1:1.93.1.r7966.7ccbff5e-2",
        version_comparison=COMPARISON_INCONCLUSIVE,
    ))
    assert "pkgver() computes the version at build time" in text
    # Both sides now read as the same kind of object, epoch included.
    assert "1:1.93.1.r7967.caea422f-2 installed" in text
    assert "1:1.93.1.r7966.7ccbff5e-2 declared in the AUR" in text


def test_an_unreadable_version_is_not_blamed_on_pkgver():
    text = version_transition(_fact(
        old_version="1.0-1", new_version="$_commit",
        version_comparison=COMPARISON_INCONCLUSIVE,
    ))
    assert "could not be resolved" in text
    assert "pkgver()" not in text


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
        old_version="1:1.93.1.r7967.caea422f-2",
        new_version="1:1.93.1.r7966.7ccbff5e-2",
        version_comparison=COMPARISON_INCONCLUSIVE,
    ))
    assert note.startswith("No changes in the AUR since last review (commit 8646e821)")
    assert "pkgver() computes the version at build time" in note


def test_the_no_change_note_separates_unreadable_from_computed():
    """Two causes wear one constant, and the reader needs to know which.

    A maintainer read "not comparable" beside a missing epoch and concluded
    the epoch was the cause. It was a real defect, but the comparison was
    declined for the other reason entirely.
    """
    note = no_aur_change_note(_fact(
        old_commit="8646e821abc", new_commit="8646e821abc",
        old_version="", new_version="$_commit",
        version_comparison=COMPARISON_INCONCLUSIVE,
    ))
    assert "could not be compared" in note
    assert "pkgver()" not in note


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


def test_review_row_names_the_reason_and_the_declared_side():
    """The review row must agree with the inspect version line: a comparison
    that is not comparable says why, and no longer says `AUR pkgver`, because
    the AUR side is the declared version when there is one to read."""
    from trustsight.cli.review import _version_cell

    cell = _version_cell({
        "old_version": "1:1.93.1.r7967.caea422f-2",
        "new_version": "1:1.93.1.r7966.7ccbff5e-2",
        "version_comparison": COMPARISON_INCONCLUSIVE,
    })
    assert "declared in the AUR" in cell
    assert "not comparable: pkgver() computes the version at build time" in cell
    assert "AUR pkgver" not in cell


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
