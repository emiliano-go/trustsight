"""The analysis recording path keeps the T-series ledgers current."""

from __future__ import annotations

import pytest

from trustsight.db import (
    domain_first_seen,
    init_db,
    key_observed_before,
)


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    from trustsight.config import ensure_default_configs

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    ensure_default_configs()
    init_db()
    yield tmp_path


def _pkgbuild(version: str, key: str = "") -> str:
    lines = ["pkgname=demo", f"pkgver={version}"]
    if key:
        lines.append(f"validpgpkeys=('{key}')")
    return "\n".join(lines) + "\n"


def test_corpus_recording_writes_domain_and_keys(isolated_db):
    from trustsight.full_aur.analyze import TemporalContext, analyze_package_text

    analyze_package_text(
        pkg_name="demo",
        old_pkgbuild=_pkgbuild("1.0"),
        new_pkgbuild=_pkgbuild("1.1", "KEY-NEW"),
        maintainer="Olav <olav@recorded.example>",
        temporal=TemporalContext(),
        record=True,
    )

    assert domain_first_seen("recorded.example") is not None
    assert key_observed_before("KEY-NEW")


def test_a_read_only_analysis_writes_neither_ledger(isolated_db):
    from trustsight.full_aur.analyze import TemporalContext, analyze_package_text

    analyze_package_text(
        pkg_name="demo",
        old_pkgbuild=_pkgbuild("1.0"),
        new_pkgbuild=_pkgbuild("1.1", "KEY-READONLY"),
        maintainer="Olav <olav@readonly.example>",
        temporal=TemporalContext(),
        record=False,
    )

    assert domain_first_seen("readonly.example") is None
    assert not key_observed_before("KEY-READONLY")
