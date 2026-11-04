"""Issue #116: the 0.27.0 pipeline merge stopped recording T-series state."""

from __future__ import annotations

import json

from tests.git_fake import FakeGitProject
from trustsight.db import (
    domain_first_seen,
    get_connection,
    init_db,
    insert_analysis,
    key_observed_before,
    update_package_maintainer,
    upsert_package,
)


def _pkgbuild(version: str, key: str = "", maintainer: str = "") -> str:
    lines = []
    if maintainer:
        lines.append(f"# Maintainer: {maintainer}")
    lines += ["pkgname=demo", f"pkgver={version}"]
    if key:
        lines.append(f"validpgpkeys=('{key}')")
    return "\n".join(lines) + "\n"


def _corpus_analysis(isolated, maintainer: str, key: str, *, record: bool):
    from trustsight.config import ensure_default_configs
    from trustsight.full_aur.analyze import TemporalContext, analyze_package_text

    ensure_default_configs()
    return analyze_package_text(
        pkg_name="demo",
        old_pkgbuild=_pkgbuild("1.0"),
        new_pkgbuild=_pkgbuild("1.1", key, maintainer),
        maintainer=maintainer,
        temporal=TemporalContext(),
        record=record,
    )


def test_corpus_recording_writes_domain_and_keys(isolated):
    _corpus_analysis(isolated, "Olav <olav@recorded.example>",
                     "KEY-CORPUS", record=True)
    assert domain_first_seen("recorded.example") is not None
    assert key_observed_before("KEY-CORPUS")


def test_read_only_analysis_writes_neither_ledger(isolated):
    _corpus_analysis(isolated, "Olav <olav@readonly.example>",
                     "KEY-READONLY", record=False)
    assert domain_first_seen("readonly.example") is None
    assert not key_observed_before("KEY-READONLY")


def test_migration_seeds_domains_and_keys_from_existing_state(isolated):
    pid = upsert_package("known-maintainer", "1.0")
    update_package_maintainer("known-maintainer", "Olav <olav@known.example>")
    insert_analysis(
        pid, "", "1.0", "", "", 0, "",
        json.dumps({"change": {"pgp_keys": {
            "gained": ["KNOWNKEY"], "lost": ["RETIREDKEY"]}}}),
        [],
    )
    with get_connection() as conn:
        conn.execute(
            "UPDATE analysis_history SET timestamp = '2020-01-01 00:00:00'")
        conn.execute(
            "DELETE FROM metadata WHERE key IN "
            "('observed_domains_from_packages_v1', "
            "'observed_signing_keys_from_history_v1')")
        conn.commit()

    init_db()

    assert domain_first_seen("known.example") == "2020-01-01 00:00:00"
    assert key_observed_before("KNOWNKEY")
    assert key_observed_before("RETIREDKEY")


def test_git_path_records_domain_and_keys(isolated, monkeypatch):
    import pygit2
    import trustsight.analysis.pipeline as pipeline

    repo = pygit2.init_repository(str(isolated / "repo"), bare=True)

    def commit(text: str) -> str:
        sig = pygit2.Signature("T Maintainer", "t@example.invalid")
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", repo.create_blob(text),
                       pygit2.GIT_FILEMODE_BLOB)
        parents = [repo.head.target] if not repo.is_empty else []
        return str(repo.create_commit(
            "refs/heads/master", sig, sig, "c", builder.write(), parents))

    commit(_pkgbuild("1.0", maintainer="T Maintainer <t@example.invalid>"))
    commit(_pkgbuild("1.1", "KEY-GIT",
                     "T Maintainer <t@example.invalid>"))
    monkeypatch.setattr(
        pipeline._analyze, "clone_or_fetch",
        lambda name, mtime=None: FakeGitProject(repo))

    pipeline.analyze_package("demo-git-record", installed_version="1.0-1",
                             record=True)

    assert domain_first_seen("example.invalid") is not None
    assert key_observed_before("KEY-GIT")
