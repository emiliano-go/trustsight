"""``trustsight corpus fetch``: the opt-in pull channel for the corpus baseline.

The command downloads ``baseline-corpus.tar.zst`` through the release
channel, verifies the detached ed25519 signature against the pinned
distribution key before the bytes are parsed, and imports the artifact.
These tests mock the release download (like the seed-fetch and ioc-update
suites do), so nothing reaches the network.
"""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from trustsight import release
from trustsight.cli import app
from trustsight.db import get_connection, init_db


@pytest.fixture(autouse=True)
def _the_channel_is_the_subject(monkeypatch):
    """Corpus fetch reaches the release channel, so opt out of offline mode."""
    monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)
    release._BASELINE_TAG_RESOLVED = False
    release._BASELINE_TAG_CACHE = None
    monkeypatch.setattr(release, "_resolve_baseline_tag", lambda: None)
    monkeypatch.setattr(
        release, "_configured_baseline_tag", lambda: "baseline-2026-08-10"
    )


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    import trustsight.config as config
    import trustsight.db as db

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(db, "DATA_DIR", tmp_path / "data")
    (tmp_path / "config").mkdir(parents=True)
    (tmp_path / "data").mkdir(parents=True)
    init_db()
    return tmp_path


@pytest.fixture
def signed_artifact(tmp_path, monkeypatch):
    """A real signed corpus artifact; fetch_verified_asset returns its bytes.

    The artifact is built in its own scratch database so the test's
    isolated database only ever sees the import half of the flow.
    """
    import trustsight.config as config
    import trustsight.db as db
    from trustsight.full_aur import export
    from trustsight.full_aur.export import build_artifact

    private = Ed25519PrivateKey.generate()
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    private_path = key_dir / "release.raw"
    private_path.write_bytes(private.private_bytes_raw())
    pubkey_path = key_dir / "pubkey"
    pubkey_path.write_bytes(private.public_key().public_bytes_raw())
    monkeypatch.setattr(export, "_TRUSTED_PUBKEY_FILE", pubkey_path)

    builder = tmp_path / "builder"
    (builder / "config").mkdir(parents=True)
    (builder / "data").mkdir(parents=True)
    monkeypatch.setattr(config, "CONFIG_DIR", builder / "config")
    monkeypatch.setattr(config, "DATA_DIR", builder / "data")
    monkeypatch.setattr(config, "CACHE_DIR", builder / "cache")
    monkeypatch.setattr(db, "DATA_DIR", builder / "data")
    init_db()

    with get_connection() as conn:
        conn.execute(
            """INSERT INTO package_profiles
               (package_name, observation_count, last_score, last_risk)
               VALUES ('demo-pkg', 1, 7, 'LOW')"""
        )
        conn.executemany(
            """INSERT INTO dependency_names
               (name, first_seen_globally_timestamp, observation_count)
               VALUES (?, '2026-01-01T00:00:00Z', 3)""",
            [("dep-one",), ("dep-two",)],
        )
        conn.commit()

    artifact = builder / "baseline-corpus.tar.zst"
    build_artifact(str(artifact), private_key_path=str(private_path))

    # Point the database back at the isolated scratch directory.
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(db, "DATA_DIR", tmp_path / "data")
    return artifact.read_bytes()


def _profile_count() -> int:
    with get_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM package_profiles"
        ).fetchone()["n"]


def test_fetch_downloads_verifies_and_imports(isolated, signed_artifact, monkeypatch):
    fetched = []

    def fake_fetch(asset_name, **kwargs):
        fetched.append(asset_name)
        return signed_artifact

    monkeypatch.setattr(release, "fetch_verified_asset", fake_fetch)

    result = CliRunner().invoke(app, ["corpus", "fetch", "--yes", "--json"])

    assert result.exit_code == 0, result.output
    assert fetched == ["baseline-corpus.tar.zst"]
    assert _profile_count() == 1
    with get_connection() as conn:
        deps = conn.execute("SELECT COUNT(*) AS n FROM dependency_names").fetchone()["n"]
    assert deps == 2
    # The plan and the import counts are both part of the json output:
    # two JSON documents, one per line.
    docs = [json.loads(line) for line in result.output.splitlines() if line.strip()]
    assert docs[0]["plan"]["asset"] == "baseline-corpus.tar.zst"
    assert docs[0]["plan"]["profiles"] == 0
    assert docs[1]["profiles"] == 1
    assert docs[1]["source_urls"] == 0


def test_fetch_refuses_a_signature_failure(isolated, monkeypatch):
    def boom(asset_name, **kwargs):
        raise release.ReleaseSignatureError("signature mismatch")

    monkeypatch.setattr(release, "fetch_verified_asset", boom)

    result = CliRunner().invoke(app, ["corpus", "fetch", "--yes"])

    assert result.exit_code == 2
    assert "refused" in result.output.lower()
    assert _profile_count() == 0


def test_fetch_is_disabled_offline(isolated, monkeypatch):
    monkeypatch.setenv("TRUSTSIGHT_OFFLINE", "1")

    result = CliRunner().invoke(app, ["corpus", "fetch", "--yes"])

    assert result.exit_code == 2
    assert "TRUSTSIGHT_OFFLINE" in result.output


def test_fetch_prompts_before_merging_into_a_non_empty_corpus(
    isolated, signed_artifact, monkeypatch
):
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO package_profiles
               (package_name, observation_count, last_score, last_risk)
               VALUES ('local-pkg', 1, 3, 'LOW')"""
        )
        conn.commit()

    def fake_fetch(asset_name, **kwargs):
        return signed_artifact

    monkeypatch.setattr(release, "fetch_verified_asset", fake_fetch)

    declined = CliRunner().invoke(app, ["corpus", "fetch"], input="n\n")
    assert declined.exit_code == 2
    assert _profile_count() == 1  # unchanged: 'demo-pkg' was not imported

    accepted = CliRunner().invoke(app, ["corpus", "fetch"], input="y\n")
    assert accepted.exit_code == 0, accepted.output
    assert _profile_count() == 2


def test_fetch_json_prints_the_plan_without_prompting(
    isolated, signed_artifact, monkeypatch
):
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO package_profiles
               (package_name, observation_count, last_score, last_risk)
               VALUES ('local-pkg', 1, 3, 'LOW')"""
        )
        conn.commit()

    def fake_fetch(asset_name, **kwargs):
        return signed_artifact

    monkeypatch.setattr(release, "fetch_verified_asset", fake_fetch)

    # No input: if it prompted, the runner would abort on EOF and exit 1/2.
    result = CliRunner().invoke(app, ["corpus", "fetch", "--json"])

    assert result.exit_code == 0, result.output
    assert '"plan"' in result.output
    assert _profile_count() == 2
