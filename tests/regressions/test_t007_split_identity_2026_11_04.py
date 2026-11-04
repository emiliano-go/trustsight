"""Issue #117: T007 searched the combined Name <mail> string in one field."""

from __future__ import annotations

from trustsight.analysis.temporal import t_packager_not_in_history
from trustsight.maintainer_email import split_maintainer


class _Commit:
    def __init__(self, message: str = "", author_name: str = "",
                 author_email: str = "", committer_name: str = "",
                 committer_email: str = ""):
        self.message = message
        self.author_name = author_name
        self.author_email = author_email
        self.committer_name = committer_name
        self.committer_email = committer_email


class _Project:
    def __init__(self, commits):
        self._commits = commits

    def walk(self, head, limit=None):
        return self._commits


def _fires(maintainer: str, commits) -> bool:
    return bool(t_packager_not_in_history(
        _Project(commits), "abc123", maintainer, None))


def test_full_name_and_address_match_the_author_identity():
    assert not _fires(
        "Caleb Maclennan <caleb@alerque.com>",
        [_Commit(author_name="Caleb Maclennan",
                 author_email="caleb@alerque.com")],
    )


def test_address_matches_when_the_commit_display_name_differs():
    assert not _fires(
        "Caleb Maclennan <caleb@alerque.com>",
        [_Commit(committer_name="C. Maclennan",
                 committer_email="caleb@alerque.com")],
    )


def test_matching_is_case_insensitive():
    assert not _fires(
        "caleb maclennan <caleb@alerque.com>",
        [_Commit(author_name="CALEB MACLENNAN",
                 author_email="CALEB@ALERQUE.COM")],
    )


def test_a_genuinely_absent_identity_still_fires():
    assert _fires(
        "Caleb Maclennan <caleb@alerque.com>",
        [_Commit(author_name="Someone Else", author_email="other@example.org")],
    )


def test_split_maintainer_keeps_name_only_and_address_only_forms():
    assert split_maintainer("Caleb Maclennan <caleb@alerque.com>") == (
        "Caleb Maclennan", "caleb@alerque.com")
    assert split_maintainer("tippfehlr") == ("tippfehlr", "")
    assert split_maintainer("caleb@alerque.com") == ("", "caleb@alerque.com")
