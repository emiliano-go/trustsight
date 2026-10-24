"""The T-series temporal novelty rules."""

import pytest

from trustsight.analysis.temporal import (
    t_domain_findings,
    t_key_findings,
    t_metadata_git_divergence,
    t_packager_not_in_history,
)
from trustsight.db import (
    domain_first_seen,
    init_db,
    key_observed_before,
    observed_domain_count,
    observed_key_count,
    record_observed_domain,
    record_observed_key,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


class _Commit:
    def __init__(self, commit_time: int = 0, message: str = "",
                 author_name: str = "", author_email: str = "",
                 committer_name: str = "", committer_email: str = ""):
        self.commit_time = commit_time
        self.message = message
        self.author_name = author_name
        self.author_email = author_email
        self.committer_name = committer_name
        self.committer_email = committer_email


class _Project:
    """A minimal stand-in for GitProject, for the T006/T007 rules."""

    def __init__(self, commit_time: int = 0, messages=None):
        self._commit_time = commit_time
        self._messages = messages or []

    def commit_meta(self, oids):
        return [_Commit(commit_time=self._commit_time)]

    def walk(self, head, limit=None):
        return [_Commit(message=m) for m in self._messages]


def test_t001_cold_index_declines(db):
    assert observed_key_count() == 0
    assert t_key_findings({"pgp_keys": {"gained": ["ABCDEF"]}}, None) == []


def test_t001_fires_for_a_never_seen_key(db):
    record_observed_key("KNOWNKEY")
    assert key_observed_before("KNOWNKEY")
    got = t_key_findings({"pgp_keys": {"gained": ["NEWKEY"]}}, None)
    assert [f["rule_id"] for f in got] == ["T001"]
    assert got[0]["evidence"]["key"] == "NEWKEY"


def test_t001_silent_for_a_known_key(db):
    record_observed_key("KNOWNKEY")
    assert t_key_findings({"pgp_keys": {"gained": ["KNOWNKEY"]}}, None) == []


def test_t002_cold_index_declines(db):
    assert observed_domain_count() == 0
    assert t_domain_findings("me@new.example", None) == []


def test_t002_fires_for_a_new_domain(db):
    record_observed_domain("known.example")
    assert domain_first_seen("known.example")
    got = t_domain_findings("me@new.example", None)
    assert [f["rule_id"] for f in got] == ["T002"]


def test_t002_fires_for_a_domain_first_seen_inside_the_window(db):
    """The window, not just "never observed"."""
    record_observed_domain("fresh.example")  # first_seen defaults to now
    got = t_domain_findings("me@fresh.example", None)
    assert [f["rule_id"] for f in got] == ["T002"]


def test_t002_silent_for_a_long_observed_domain(db):
    record_observed_domain("known.example", observed_at="2020-01-01 00:00:00")
    assert t_domain_findings("me@known.example", None) == []


def test_key_ledger_is_bounded(db, monkeypatch):
    import trustsight.db as dbmod

    monkeypatch.setattr(dbmod._history, "MAX_OBSERVED_KEYS", 5)
    for i in range(10):
        record_observed_key(f"key-{i}", observed_at=f"2026-01-01 00:00:{i:02d}")
    assert observed_key_count() <= 5
    # The newest survive; the oldest were pruned.
    assert key_observed_before("key-9")


def test_t006_fires_when_metadata_is_ahead_of_git():
    tip = 1_700_000_000
    project = _Project(commit_time=tip)
    got = t_metadata_git_divergence(
        project, "abc123", tip + 25 * 3600, None)
    assert [f["rule_id"] for f in got] == ["T006"]
    assert got[0]["severity"] == "MEDIUM"


def test_t006_silent_within_the_margin():
    tip = 1_700_000_000
    project = _Project(commit_time=tip)
    assert t_metadata_git_divergence(
        project, "abc123", tip + 3600, None) == []


def test_t006_silent_without_data():
    project = _Project(commit_time=1_700_000_000)
    assert t_metadata_git_divergence(project, "", 1_700_000_000, None) == []
    assert t_metadata_git_divergence(project, "abc", None, None) == []


def test_t007_fires_when_maintainer_is_absent_from_history():
    project = _Project(messages=["import package", "bump to 1.2"])
    got = t_packager_not_in_history(project, "abc123", "tippfehlr", None)
    assert [f["rule_id"] for f in got] == ["T007"]
    assert got[0]["severity"] == "INFO"


def test_t007_silent_when_maintainer_appears_in_a_commit():
    project = _Project(messages=["import package by tippfehlr"])
    assert t_packager_not_in_history(
        project, "abc123", "tippfehlr", None) == []


def test_t007_reads_the_commit_author_not_only_the_message():
    """#57 side note: the import commit is often unsigned in its message."""
    project = _Project(messages=["import package"])
    project.walk = lambda head, limit=None: [
        _Commit(message="import package", author_name="Ralf Seichter",
                author_email="rseichter@example.org")
    ]
    assert t_packager_not_in_history(
        project, "abc123", "rseichter", None) == []


def test_t007_reads_the_committer_identity():
    project = _Project(messages=["import package"])
    project.walk = lambda head, limit=None: [
        _Commit(message="import package", committer_name="rseichter",
                committer_email="rseichter@example.org")
    ]
    assert t_packager_not_in_history(
        project, "abc123", "rseichter", None) == []


def test_t007_silent_without_data():
    project = _Project(messages=["import package"])
    assert t_packager_not_in_history(project, "", "someone", None) == []
    assert t_packager_not_in_history(project, "abc", "", None) == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Stephan Springer <buzo+arch@Lini.de>", "lini.de"),
        ("buzo+arch@Lini.de", "lini.de"),
        ("buzo+arch@Lini.de (comment)", "lini.de"),
        ("Name <buzo+arch@Lini.de", "lini.de"),
        ("Name Only", ""),
    ],
)
def test_maintainer_domain_parses_aur_forms(value, expected):
    from trustsight.maintainer_email import maintainer_domain

    assert maintainer_domain(value) == expected


def test_t002_reports_the_bare_domain_from_brackets(db):
    record_observed_domain("known.example")
    got = t_domain_findings("Stephan Springer <buzo+arch@Lini.de>", None)

    assert [f["rule_id"] for f in got] == ["T002"]
    assert got[0]["params"]["domain"] == "lini.de"
    assert "lini.de>" not in got[0]["match"]


def test_t002_matches_a_recorded_bare_domain(db):
    record_observed_domain("lini.de", observed_at="2020-01-01 00:00:00")
    assert t_domain_findings(
        "Stephan Springer <buzo+arch@Lini.de>", None) == []
