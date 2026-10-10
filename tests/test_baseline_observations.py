"""Artifact version 2: the corpus baseline carries novelty observations.

The signed payload now covers the observation tables the seed importer
writes (source_urls, dependency_names, maintainers_hashed), so importing a
corpus baseline warms the same priors a `seed fetch` warms.  These tests pin
the round trip, the additive merge semantics, and that the signature covers
the new data: a novelty section modified after signing is a refusal.
"""

import gzip
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trustsight.db import get_connection, init_db
from trustsight.full_aur import export
from trustsight.full_aur.export import (
    InvalidSignatureError,
    UnsignedBaselineError,
    build_artifact,
    canonical_artifact_bytes,
    import_baseline,
)

SALT = "test-salt-abc123"


def _point_at(monkeypatch, config, db, root) -> None:
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CONFIG_DIR", root / "config")
    monkeypatch.setattr(config, "DATA_DIR", root / "data")
    monkeypatch.setattr(config, "CACHE_DIR", root / "cache")
    monkeypatch.setattr(db, "DATA_DIR", root / "data")


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    """A signed version 2 artifact built from a seeded scratch database.

    The builder's database is seeded and the artifact built while that
    database is the live one; the fixture then re-points the database at a
    second, empty scratch directory for the import half of each test.
    """
    import trustsight.config as config
    import trustsight.db as db

    builder_root = tmp_path / "builder"
    _point_at(monkeypatch, config, db, builder_root)

    private = Ed25519PrivateKey.generate()
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    private_path = key_dir / "release.raw"
    private_path.write_bytes(private.private_bytes_raw())
    pubkey_path = key_dir / "pubkey"
    pubkey_path.write_bytes(private.public_key().public_bytes_raw())
    # The import verifies against the pinned key; point the pin at ours.
    monkeypatch.setattr(export, "_TRUSTED_PUBKEY_FILE", pubkey_path)

    init_db()
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )
        conn.executemany(
            """INSERT INTO source_urls
               (url, first_seen_package_id, first_seen_globally_timestamp,
                total_uses, last_seen_timestamp) VALUES (?, 0, ?, ?, ?)""",
            [
                ("https://example.com/a.tar.gz", "2026-01-01T00:00:00Z", 3, None),
                ("https://forge.example/b.git", "2026-01-02T00:00:00Z", 1, None),
            ],
        )
        conn.executemany(
            """INSERT INTO dependency_names
               (name, first_seen_globally_timestamp, observation_count)
               VALUES (?, ?, ?)""",
            [
                ("python", "2026-01-01T00:00:00Z", 40),
                ("lib-xyz", "2026-01-01T00:00:00Z", 2),
            ],
        )
        conn.executemany(
            """INSERT INTO maintainers_hashed
               (name_hash, email_hash, first_seen, package_count, packages, source)
               VALUES (?, NULL, ?, ?, ?, 'seed')""",
            [
                ("h" * 64, "2026-01-01T00:00:00Z", 5, json.dumps(["pkg-a"])),
                ("e" * 64, None, 1, None),
            ],
        )
        conn.execute(
            "INSERT OR REPLACE INTO seed_meta (key, value) VALUES ('salt', ?)", (SALT,)
        )
        conn.commit()

    path = builder_root / "baseline-corpus.tar.zst"
    build_artifact(str(path), private_key_path=str(private_path),
                   corpus_cutoff="etag-1")

    importer_root = tmp_path / "importer"
    _point_at(monkeypatch, config, db, importer_root)
    init_db()
    return path


def _counts() -> dict:
    with get_connection() as conn:
        return {
            "source_urls": conn.execute(
                "SELECT COUNT(*) AS n FROM source_urls").fetchone()["n"],
            "dependency_names": conn.execute(
                "SELECT COUNT(*) AS n FROM dependency_names").fetchone()["n"],
            "maintainers": conn.execute(
                "SELECT COUNT(*) AS n FROM maintainers_hashed").fetchone()["n"],
            "salt": conn.execute(
                "SELECT value FROM seed_meta WHERE key = 'salt'").fetchone(),
        }


def test_signed_artifact_round_trips_observations(artifact):
    import_baseline(str(artifact))

    counts = _counts()
    assert counts["source_urls"] == 2
    assert counts["dependency_names"] == 2
    assert counts["maintainers"] == 2
    assert counts["salt"]["value"] == SALT


def test_import_is_additive_and_never_clobbers_local_rows(artifact):

    # Local history predates the baseline: a known URL with its own
    # first-seen, a dependency name with more local observations, and a
    # maintainer row the artifact also carries.
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
        )
        conn.execute(
            """INSERT INTO source_urls
               (url, first_seen_package_id, first_seen_globally_timestamp,
                total_uses, last_seen_timestamp)
               VALUES ('https://example.com/a.tar.gz', 0, '2025-06-01T00:00:00Z',
                       9, '2026-05-01T00:00:00Z')"""
        )
        conn.execute(
            """INSERT INTO dependency_names
               (name, first_seen_globally_timestamp, observation_count)
               VALUES ('python', '2025-06-01T00:00:00Z', 5)"""
        )
        conn.execute(
            """INSERT INTO maintainers_hashed
               (name_hash, email_hash, first_seen, package_count, packages, source)
               VALUES ('h' * 1 || ?, NULL, '2025-06-01T00:00:00Z', 7, NULL, 'local')""",
            ("h" * 63,),
        )
        conn.execute(
            "INSERT OR REPLACE INTO seed_meta (key, value) VALUES ('salt', ?)", (SALT,)
        )
        conn.commit()

    import_baseline(str(artifact))

    with get_connection() as conn:
        url = conn.execute(
            "SELECT * FROM source_urls WHERE url = 'https://example.com/a.tar.gz'"
        ).fetchone()
        dep = conn.execute(
            "SELECT * FROM dependency_names WHERE name = 'python'"
        ).fetchone()
        maint = conn.execute(
            "SELECT COUNT(*) AS n FROM maintainers_hashed WHERE name_hash = ?",
            ("h" * 64,),
        ).fetchone()["n"]
    # The local row wins everywhere: same URL kept with its timestamps,
    # counts accumulate, no duplicate maintainer row.
    assert url["total_uses"] == 9
    assert url["first_seen_globally_timestamp"] == "2025-06-01T00:00:00Z"
    assert dep["observation_count"] == 45  # 5 local + 40 from the artifact
    assert maint == 1
    assert _counts()["dependency_names"] == 2  # 'lib-xyz' merged in


def test_artifact_with_a_foreign_salt_skips_maintainer_rows(artifact):

    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO seed_meta (key, value) VALUES ('salt', 'local-salt')"
        )
        conn.commit()

    import_baseline(str(artifact))

    counts = _counts()
    # URLs and dependency names are salt-independent and still merge...
    assert counts["source_urls"] == 2
    assert counts["dependency_names"] == 2
    # ...but the foreign-salt maintainer rows are skipped, exactly as the
    # seed importer behaves, and the stored salt is untouched.
    assert counts["maintainers"] == 0
    assert counts["salt"]["value"] == "local-salt"


def test_version_1_artifact_without_observations_still_imports(tmp_path, artifact):
    metadata = [{"Name": "demo"}]
    m_hash = hashlib.sha256(
        json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest = {"version": 1, "ruleset_version": "t", "scorer_version": "t",
                "corpus_cutoff": ""}
    payload = json.loads(
        canonical_artifact_bytes([], [], m_hash, manifest).decode()
    )
    artifact = {"signature": None, **payload, "metadata_snapshot": metadata}
    path = tmp_path / "old.gz"
    path.write_bytes(gzip.compress(json.dumps(artifact).encode()))

    import_baseline(str(path), allow_unsigned=True)

    assert _counts()["source_urls"] == 0
    assert _counts()["dependency_names"] == 0


def test_unsigned_version_2_artifact_is_refused(tmp_path, artifact):
    unsigned = tmp_path / "unsigned.tar.zst"
    build_artifact(str(unsigned))  # no private key: unsigned

    with pytest.raises(UnsignedBaselineError):
        import_baseline(str(unsigned), allow_unsigned=False)


def test_tampered_novelty_payload_fails_verification(artifact):

    raw = gzip.decompress(artifact.read_bytes())
    data = json.loads(raw)
    data["observations"]["source_urls"].append(
        {"url": "https://evil.example/x.tar.gz", "total_uses": 1}
    )
    tampered = artifact.parent / "tampered.tar.zst"
    tampered.write_bytes(gzip.compress(json.dumps(data).encode()))

    with pytest.raises(InvalidSignatureError):
        import_baseline(str(tampered), allow_unsigned=False)


def test_canonical_bytes_differ_when_observations_differ():
    base = {"version": 2, "ruleset_version": "t", "scorer_version": "t",
            "corpus_cutoff": ""}
    obs_a = {"salt": None, "source_urls": [{"url": "https://a.example/x",
            "first_seen_package_id": 0, "first_seen_globally_timestamp": None,
            "total_uses": 1, "last_seen_timestamp": None}],
            "dependency_names": [], "maintainers": []}
    obs_b = {**obs_a, "source_urls": [{"url": "https://b.example/x",
            "first_seen_package_id": 0, "first_seen_globally_timestamp": None,
            "total_uses": 1, "last_seen_timestamp": None}]}
    a = canonical_artifact_bytes([], [], "h", base, observations=obs_a)
    b = canonical_artifact_bytes([], [], "h", base, observations=obs_b)
    assert a != b
    # And the key is absent entirely when no observations are given, so a
    # version 1 payload re-canonicalises to its original signed bytes.
    v1 = canonical_artifact_bytes([], [], "h", {"version": 1, **{k: "t" for k in
        ("ruleset_version", "scorer_version")}, "corpus_cutoff": ""})
    assert b'"observations"' not in v1
