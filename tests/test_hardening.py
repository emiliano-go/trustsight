"""Adversarial regressions: what a hostile input may not be able to do.

Each test here corresponds to something that *did* work against an earlier
revision of this code - a signature that covered less than it appeared to, a
regex that could be made quadratic, a response with no ceiling - rather than
to a hypothetical.  They are grouped by the surface that receives the
untrusted bytes.
"""

import gzip
import hashlib
import io
import json
import tarfile
import time

import pytest

from trustsight.analysis.base import iter_scheme_urls
from trustsight.full_aur import fetch as corpus_fetch
from trustsight.full_aur.export import (
    InvalidSignatureError,
    MalformedBaselineError,
    _read_artifact,
    canonical_artifact_bytes,
    import_baseline,
)
from trustsight.full_aur.metadata import (
    DecompressionTooLarge,
    default_metadata_path,
    gunzip_capped,
)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Config and database in a scratch directory."""
    import trustsight.config as config
    import trustsight.db as db

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(db, "DATA_DIR", tmp_path / "data")
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    db.init_db()
    return tmp_path


# ---------------------------------------------------------------------------
# The baseline artifact: the only file a user is invited to take from
# someone else, and the only one carrying a signature.
# ---------------------------------------------------------------------------


MANIFEST = {
    "version": 1, "ruleset_version": "t", "scorer_version": "t",
    "corpus_cutoff": "",
}


def _metadata_hash(metadata_list) -> str:
    raw = json.dumps(metadata_list, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _artifact(tmp_path, metadata_list, signed_metadata=None, name="baseline.gz"):
    """Write an artifact whose signed hash covers *signed_metadata*."""
    signed = metadata_list if signed_metadata is None else signed_metadata
    canonical = canonical_artifact_bytes([], [], _metadata_hash(signed), MANIFEST)
    artifact = {
        "signature": None,
        **json.loads(canonical),
        "metadata_snapshot": metadata_list,
    }
    path = tmp_path / name
    path.write_bytes(gzip.compress(json.dumps(artifact).encode()))
    return path


def test_a_swapped_metadata_snapshot_is_refused(isolated):
    """The snapshot rides outside the signature; only its hash is signed.

    Without this check a validly signed artifact could be re-published with
    an attacker's entire AUR metadata attached - maintainers, versions,
    dependency edges, everything discovery, R092/R100/R116 and `corpus
    pivot` read - and the signature would still verify.
    """
    honest = [{"Name": "demo", "Maintainer": "alice"}]
    forged = [{"Name": "evil-pkg", "Maintainer": "mallory"}]
    path = _artifact(isolated, forged, signed_metadata=honest)

    with pytest.raises(InvalidSignatureError):
        import_baseline(str(path), allow_unsigned=True)

    assert not default_metadata_path().exists()


def test_a_matching_metadata_snapshot_is_imported(isolated):
    honest = [{"Name": "demo", "Maintainer": "alice"}]
    import_baseline(str(_artifact(isolated, honest)), allow_unsigned=True)

    saved = json.loads(default_metadata_path().read_text())
    assert list(saved["packages"]) == ["demo"]


def test_the_snapshot_lands_in_the_config_dir_not_the_cwd(isolated, monkeypatch):
    """`review` reads it from the config dir; the importer wrote it to $PWD."""
    elsewhere = isolated / "somewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    import_baseline(
        str(_artifact(isolated, [{"Name": "demo"}])), allow_unsigned=True
    )

    assert default_metadata_path().exists()
    assert not (elsewhere / "full-aur-meta.json").exists()


def test_rows_without_a_package_name_are_skipped_not_fatal(isolated):
    metadata = [{"Name": "demo"}]
    canonical = canonical_artifact_bytes(
        [], [], _metadata_hash(metadata), MANIFEST
    )
    payload = json.loads(canonical)
    payload["profiles"] = [{"last_score": 5}, {"package_name": "ok", "last_score": 1}]
    payload["snapshots"] = ["not-a-dict", {"package_name": "ok", "pkgbuild_text": "x"}]
    artifact = {"signature": None, **payload, "metadata_snapshot": metadata}
    path = isolated / "ragged.gz"
    path.write_bytes(gzip.compress(json.dumps(artifact).encode()))

    import_baseline(str(path), allow_unsigned=True)  # must not raise

    from trustsight.db import get_pkgbuild_snapshot
    assert get_pkgbuild_snapshot("ok") is not None


def test_a_decompression_bomb_is_capped():
    """A gzip member is free to claim gigabytes; expanding it to find out is
    the attack."""
    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024))
    with pytest.raises(DecompressionTooLarge):
        gunzip_capped(bomb, limit=1024 * 1024)


def test_an_artifact_with_a_junk_signature_field_is_rejected(isolated):
    for bad in ({"signature": ["not", "hex"]}, {"signature": "zz"}):
        payload = {**json.loads(canonical_artifact_bytes([], [], "", MANIFEST)), **bad}
        path = isolated / "junk.gz"
        path.write_bytes(gzip.compress(json.dumps(payload).encode()))
        with pytest.raises(MalformedBaselineError):
            _read_artifact(path)


def test_an_artifact_that_is_not_an_object_is_rejected(isolated):
    path = isolated / "list.gz"
    path.write_bytes(gzip.compress(json.dumps([1, 2, 3]).encode()))
    with pytest.raises(MalformedBaselineError):
        _read_artifact(path)


# ---------------------------------------------------------------------------
# The corpus fetcher: bytes from a mirror, parsed before anything is known
# about them.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes, chunk: int = 65536):
        self._buf = io.BytesIO(body)
        self._chunk = chunk

    def read(self, size=None):
        return self._buf.read(size or self._chunk)


def test_an_oversized_response_is_abandoned(monkeypatch):
    """A response read with no bound lets the remote end choose how much of
    this machine's memory to use."""
    monkeypatch.setattr(corpus_fetch, "MAX_RESPONSE_BYTES", 4096)
    monkeypatch.setattr(
        corpus_fetch.urllib.request, "urlopen",
        lambda *a, **k: _FakeResponse(b"A" * 100_000),
    )
    assert corpus_fetch._http_get("https://example.invalid/x") is None


def test_a_normal_response_is_returned_whole(monkeypatch):
    monkeypatch.setattr(
        corpus_fetch.urllib.request, "urlopen",
        lambda *a, **k: _FakeResponse(b"pkgname=demo\n"),
    )
    assert corpus_fetch._http_get("https://example.invalid/x") == b"pkgname=demo\n"


def _tar_with(members: int) -> tarfile.TarFile:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i in range(members):
            info = tarfile.TarInfo(f"demo/file{i}")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r")


def test_the_snapshot_manifest_stops_at_its_member_cap():
    """`getmembers()` parses the whole archive first; the walk is lazy now."""
    manifest = corpus_fetch._snapshot_manifest(_tar_with(500), max_members=10)
    assert len(manifest) == 10


def test_a_missing_pkgbuild_in_a_large_tar_gives_up(monkeypatch):
    monkeypatch.setattr(corpus_fetch, "MAX_TAR_MEMBERS", 50)
    assert corpus_fetch._pkgbuild_from_tarfile(_tar_with(500), "demo") is None


def test_package_names_are_url_encoded(monkeypatch):
    """A name is data from the metadata dump, not a piece of the URL."""
    seen = []
    monkeypatch.setattr(corpus_fetch, "_http_get", lambda url: seen.append(url) or None)
    corpus_fetch.fetch_pkgbuild("evil&h=other#frag")
    corpus_fetch.fetch_srcinfo("evil&h=other")
    assert all("&h=other" not in url for url in seen)
    assert all("#frag" not in url for url in seen)


def test_resume_state_follows_the_config_dir(isolated, monkeypatch):
    """A bootstrap resumed from another directory used to start over."""
    elsewhere = isolated / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    corpus_fetch.save_resume_state({"processed": ["a"]})
    assert corpus_fetch.load_resume_state() == {"processed": ["a"]}
    assert not (elsewhere / "full-aur-resume.json").exists()

    corpus_fetch.clear_resume_state()
    assert corpus_fetch.load_resume_state() is None


# ---------------------------------------------------------------------------
# Pathological PKGBUILD text: the attacker writes every byte of the diff.
# ---------------------------------------------------------------------------


def test_url_extraction_is_linear_on_a_line_with_no_url():
    """The regex form rescanned from every position: 200 KB took ~30 seconds.

    A PKGBUILD may legally contain a very long token, and an attacker may
    choose to.
    """
    started = time.perf_counter()
    assert list(iter_scheme_urls("a" * 200_000)) == []
    assert time.perf_counter() - started < 1.0


def test_url_extraction_still_finds_what_the_regex_found():
    line = "  curl -o out 'https://user:pw@example.org:8443/a/b?c=d' && echo done"
    assert list(iter_scheme_urls(line)) == [
        ("https", "https://user:pw@example.org:8443/a/b?c=d")
    ]


@pytest.mark.parametrize("text,expected", [
    ("git+https://example.org/t.git", [("git+https", "git+https://example.org/t.git")]),
    ("no scheme here", []),
    ("://leading", []),
    ("(https://example.org/x)", [("https", "https://example.org/x")]),
])
def test_url_extraction_edge_cases(text, expected):
    assert list(iter_scheme_urls(text)) == expected


def test_r106_is_not_slowed_by_a_pathological_line():
    """The rule runs on every added line of every reviewed package."""
    from trustsight.analysis.ioc import _ioc_findings
    from trustsight.iocs import load_indicators

    indicators = load_indicators({
        "meta": {"version": 1},
        "entries": [{"type": "domain", "value": "malware.example",
                     "confidence": "confirmed"}],
    })
    diff = "+" + "a" * 100_000 + "\n+" + "-" * 100_000
    started = time.perf_counter()
    _ioc_findings(diff, "demo", {}, lambda *a, **k: None, indicators=indicators)
    assert time.perf_counter() - started < 2.0


# ---------------------------------------------------------------------------
# Package names and versions reaching a command line.
# ---------------------------------------------------------------------------


def test_a_flag_shaped_package_name_cannot_become_a_pacman_flag(monkeypatch):
    import trustsight.analysis.base as base

    seen = {}

    class _Result:
        returncode = 1
        stdout = ""

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return _Result()

    monkeypatch.setattr(base.subprocess, "run", fake_run)
    base._get_installed_version("-Qo")
    assert seen["argv"] == ["pacman", "-Q", "--", "-Qo"]


def test_a_flag_shaped_version_never_reaches_vercmp(monkeypatch):
    """vercmp has no "--" separator, so the guard is a shape check."""
    import trustsight.discovery as discovery

    monkeypatch.setattr(discovery, "_get_pyalpm_vercmp", lambda: None)
    monkeypatch.setattr(
        discovery.subprocess, "run",
        lambda *a, **k: pytest.fail("vercmp invoked with a flag-shaped version"),
    )
    assert discovery._vercmp("--help", "1.0") == discovery._simple_vercmp("--help", "1.0")


def test_a_seed_database_bomb_is_refused(tmp_path, monkeypatch):
    """`seed-db` takes a path, so the seed is not always the bundled one."""
    import trustsight.db as db

    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    monkeypatch.setattr(db, "MAX_SEED_BYTES", 4096)
    bomb = tmp_path / "seed.db.gz"
    bomb.write_bytes(gzip.compress(b"\0" * 1_000_000))

    with pytest.raises(ValueError, match="exceeds"):
        db.import_seed(bomb)
