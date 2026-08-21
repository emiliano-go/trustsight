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
import os
import tarfile
import time

import pytest
from unittest.mock import patch

from trustsight.analysis.base import iter_scheme_urls
from trustsight.bounded_io import ReadTooLarge, read_capped
from trustsight.coverage import (
    SNAPSHOT_REFUSED,
    TREE_NOT_ANALYZED,
    fail_closed,
    gaps_from,
    qualified_band,
)
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


def test_seed_archive_rejects_symlink_members(tmp_path):
    import tarfile
    import trustsight.db as db

    archive = tmp_path / "seed.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo("trustsight-seed-v2/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)

    with pytest.raises(ValueError, match="unsupported link"):
        db._extract_v2_archive(archive, tmp_path / "out")


def test_seed_archive_rejects_excessive_member_count(tmp_path, monkeypatch):
    import tarfile
    import trustsight.db as db

    monkeypatch.setattr(db, "MAX_SEED_MEMBERS", 1)
    archive = tmp_path / "seed.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for name in ("trustsight-seed-v2/a", "trustsight-seed-v2/b"):
            info = tarfile.TarInfo(name)
            info.size = 0
            tf.addfile(info)

    with pytest.raises(ValueError, match="members"):
        db._extract_v2_archive(archive, tmp_path / "out")


def test_a_snapshot_member_declaring_gigabytes_is_refused(monkeypatch):
    """The compressed response cap is not a bound on a decompressed member.

    `_http_get` abandons a body past MAX_RESPONSE_BYTES, but that is the
    gzipped size.  A member of highly compressible content declares - and
    an unbounded `read()` allocates - whatever size the archive says, so a
    tarball well inside the response cap used to be enough to exhaust the
    machine.  The bound is on the read.
    """
    monkeypatch.setattr(corpus_fetch, "MAX_TAR_MEMBER_BYTES", 4096)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        payload = b"\0" * 1_000_000  # compresses to about a kilobyte
        info = tarfile.TarInfo("demo/PKGBUILD")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    body = buf.getvalue()
    assert len(body) < corpus_fetch.MAX_RESPONSE_BYTES  # the cap never fires

    tf = tarfile.open(fileobj=io.BytesIO(body), mode="r:gz")
    with pytest.raises(ReadTooLarge):
        corpus_fetch._pkgbuild_from_tarfile(tf, "demo")


def test_a_refused_snapshot_is_reported_as_a_coverage_gap(monkeypatch):
    """A bound that drops content may not read as an absent snapshot.

    Both fall back to the cgit text fetch, so without the distinction a
    refused archive and a package with no tarball produce the same result -
    and A14 requires a bound that dropped content to be visible as one.
    """
    monkeypatch.setattr(corpus_fetch, "MAX_TAR_MEMBER_BYTES", 4096)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        payload = b"\0" * 1_000_000
        info = tarfile.TarInfo("demo/PKGBUILD")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    with patch.object(
        corpus_fetch, "_http_get", side_effect=[buf.getvalue(), b"pkgname=demo\n"]
    ):
        text, manifest, trailer, refused = corpus_fetch.fetch_pkgbuild_with_tree("demo")

    # The fallback still produced a PKGBUILD, so the run is not a failure -
    # which is exactly why the refusal has to be reported separately.
    assert text == "pkgname=demo\n"
    assert manifest is None
    assert refused is True

    gaps = gaps_from(tree_analyzed=bool(manifest), snapshot_refused=refused)
    assert SNAPSHOT_REFUSED in gaps
    assert TREE_NOT_ANALYZED in gaps  # the tree really was not examined
    assert fail_closed("Low", gaps, []) == "Inconclusive"
    assert qualified_band("High", gaps).endswith("(incomplete analysis)")


def test_a_snapshot_member_under_the_bound_still_reads(monkeypatch):
    """The refusal is a ceiling, not a ban: a real PKGBUILD is unaffected."""
    monkeypatch.setattr(corpus_fetch, "MAX_TAR_MEMBER_BYTES", 4096)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        payload = b"pkgname=demo\npkgver=1.0\n"
        info = tarfile.TarInfo("demo/PKGBUILD")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    tf = tarfile.open(fileobj=io.BytesIO(buf.getvalue()), mode="r:gz")
    assert corpus_fetch._pkgbuild_from_tarfile(tf, "demo") == "pkgname=demo\npkgver=1.0\n"


def test_an_oversized_ioc_baseline_is_refused_before_verification(tmp_path, monkeypatch):
    """The signature covers these bytes, so the bound precedes the check.

    Verification cannot run until the file has been read, which is exactly
    why the bound cannot live behind it: an unbounded read here is reached
    by any artifact an operator was handed, signed or not.
    """
    import trustsight.ioc_baseline as ioc

    monkeypatch.setattr(ioc, "MAX_BASELINE_BYTES", 1024)
    huge = tmp_path / "iocs.jsonl"
    huge.write_bytes(b"x" * 8192)

    with pytest.raises(ReadTooLarge, match="refusing to read"):
        ioc._load_text(huge)


def test_an_oversized_baseline_artifact_is_refused_before_decompression(tmp_path, monkeypatch):
    """`gunzip_capped` bounds the expansion; nothing bounded the file."""
    import trustsight.full_aur.export as export

    monkeypatch.setattr(export, "MAX_ARTIFACT_BYTES", 1024)
    artifact = tmp_path / "baseline.json.gz"
    # Incompressible, so the artifact *on disk* is what exceeds the bound:
    # this is the read that feeds gunzip_capped, not the expansion it caps.
    artifact.write_bytes(gzip.compress(os.urandom(64 * 1024)))
    assert artifact.stat().st_size > 1024

    with pytest.raises(ReadTooLarge, match="refusing to read"):
        _read_artifact(artifact)


def test_a_bounded_read_refuses_rather_than_truncating():
    """A short buffer would read as a whole one; that is the seam A5 refuses."""
    stream = io.BytesIO(b"A" * 5000)
    with pytest.raises(ReadTooLarge):
        read_capped(stream, 1024, "test stream")


# ---------------------------------------------------------------------------
# Diff generation: bounds precede materialisation, and truncation travels.
# ---------------------------------------------------------------------------


def test_a_patch_is_bounded_before_it_is_assembled():
    """`patch.text` materialises a whole patch; the cap must precede the join.

    The git path used to call the generator with no limit at all, so every
    filtered patch was read in full and concatenated before the pipeline's
    cap applied - a bound on what was kept rather than on what was read.
    """
    from trustsight.differ import MAX_PATCH_BYTES, truncate_diff

    oversized = "+" + ("a" * (MAX_PATCH_BYTES * 2))
    bounded, cut = truncate_diff(oversized, MAX_PATCH_BYTES)
    assert cut is True
    assert len(bounded.encode("utf-8")) <= MAX_PATCH_BYTES


def test_generator_truncation_is_returned_not_inferred():
    """A dropped patch leaves the text under the cap, so measuring lies.

    This is the pairing that matters: bound the generator without returning
    the flag and a skipped patch becomes invisible, because the assembled
    text is then at or under the limit and `truncate_diff` reports complete.
    """
    import inspect

    from trustsight import differ
    from trustsight.analysis import pipeline

    source = inspect.getsource(differ.generate_diff_bounded)
    assert "truncated = True" in source
    assert source.rstrip().endswith("return unified, summary, truncated")

    git_path = inspect.getsource(pipeline.analyze_package)
    assert "generated_truncated" in git_path
    assert "combined_truncated or generated_truncated" in git_path


def test_the_two_value_generator_still_works_for_old_callers():
    """The compatibility wrapper keeps existing callers unaffected."""
    import inspect

    from trustsight.differ import generate_diff

    assert len(inspect.signature(generate_diff).parameters) == 5


@pytest.mark.parametrize("name", [
    "../../etc/passwd", "/etc/passwd", "..", ".", "", "a/b",
    "back\\slash", "a" * 4096,
])
def test_a_hostile_companion_name_is_refused(name):
    """A rendered hunk header names a file the reader can open.

    A name carrying path structure, or an unbounded one, would name a file
    that is not the top-level blob the scanner actually read.
    """
    from trustsight.differ import _is_safe_companion_name

    assert _is_safe_companion_name(name) is False


@pytest.mark.parametrize("name", ["helper.sh", "patch-1.diff", "a.tar.gz", "x"])
def test_an_ordinary_companion_name_is_accepted(name):
    from trustsight.differ import _is_safe_companion_name

    assert _is_safe_companion_name(name) is True


def test_the_pkgbuild_blob_is_size_checked_before_data():
    """`blob.data` materialises everything, so size comes first.

    Asserted behaviourally rather than by reading the source: a blob whose
    ``data`` raises if touched proves the size check short-circuited, which a
    text search for the two names cannot (a comment mentioning ``blob.data``
    satisfies the search and says nothing about order).
    """
    from trustsight import differ

    touched = []

    class _Exploding:
        size = differ.MAX_PKG_BUILD_BYTES * 4

        @property
        def data(self):
            touched.append(True)
            raise AssertionError("data was read before the size check")

    class _Entry:
        id = "pkgbuild-oid"
        name = "PKGBUILD"
        type_str = "blob"

    class _Tree:
        # `_top_level_blob` subscripts the tree by name.  A plain list does
        # not support that, so this fixture used to return None there and
        # the assertions below passed without the size check ever running.
        def __getitem__(self, name):
            if name == "PKGBUILD":
                return _Entry()
            raise KeyError(name)

    class _Commit:
        tree = _Tree()

    class _Repo:
        def get(self, _oid):
            return _Commit()

        def __getitem__(self, _oid):
            return _Exploding()

    assert differ.companion_source_hunks(_Repo(), "head") == ("", True)
    assert not touched, "the oversized blob's data must never be read"


def test_an_oversized_delta_never_has_its_text_requested():
    """`patch.text` allocates the whole patch, so the bound must precede it.

    Every cap after that attribute bounds what is *retained*; only a check
    against the delta's declared file sizes runs before the allocation. This
    asserts it behaviourally - a patch whose ``text`` raises if touched must
    still leave the generator with a result and a truncation flag.
    """
    from trustsight import differ

    touched = []

    class _Side:
        def __init__(self, path, size):
            self.path, self.size = path, size

    class _Delta:
        status = 1

        def __init__(self, size):
            self.old_file = _Side("PKGBUILD", size)
            self.new_file = _Side("PKGBUILD", size)

    class _Exploding:
        def __init__(self, size):
            self.delta = _Delta(size)

        @property
        def text(self):
            touched.append(True)
            raise AssertionError("patch text was read before the size check")

    class _Diff:
        deltas = [_Delta(differ.MAX_PATCH_SOURCE_BYTES * 4)]
        stats = type("S", (), {"insertions": 0, "deletions": 0})()

        def __iter__(self):
            return iter([_Exploding(differ.MAX_PATCH_SOURCE_BYTES * 4)])

    class _Repo:
        def get(self, _oid):
            return type("C", (), {"tree": object()})()

        def diff(self, *_a, **_k):
            return _Diff()

    text, _summary, truncated = differ.generate_diff_bounded(_Repo(), "a", "b")

    assert not touched, "an oversized delta must not have its text requested"
    assert truncated is True, "skipping it must be visible as truncation"
    assert text == ""


def test_an_ordinary_delta_is_still_read():
    """The pre-check is a ceiling, not a ban."""
    from trustsight import differ

    class _Side:
        def __init__(self):
            self.path, self.size = "PKGBUILD", 200

    class _Delta:
        status = 1

        def __init__(self):
            self.old_file = _Side()
            self.new_file = _Side()

    class _Patch:
        delta = _Delta()
        text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n+pkgver=2\n"

    class _Diff:
        deltas = [_Delta()]
        stats = type("S", (), {"insertions": 1, "deletions": 0})()

        def __iter__(self):
            return iter([_Patch()])

    class _Repo:
        def get(self, _oid):
            return type("C", (), {"tree": object()})()

        def diff(self, *_a, **_k):
            return _Diff()

    text, summary, truncated = differ.generate_diff_bounded(_Repo(), "a", "b")

    assert "pkgver=2" in text
    assert truncated is False
    assert summary.files_changed == ["PKGBUILD"]


# ---------------------------------------------------------------------------
# URL classification: a hostname has real limits, and they bound the work.
# ---------------------------------------------------------------------------


def test_a_hostname_is_bounded_to_what_dns_permits():
    """Classification walked every label and every parent domain.

    That is quadratic in label count, and a `source=` URL is written by the
    party under review: one 8 KiB host of dots cost 421 ms, and the
    extraction cap allows 4,096 URLs per side, so a single package could
    spend around half an hour in classification alone.

    The bound is DNS's own: 253 bytes, 127 labels. Nothing past that is a
    hostname anyone can resolve.
    """
    from trustsight.buckets import MAX_HOST_BYTES, MAX_HOST_LABELS, _bounded_host

    long_host = "a." * 5000 + "example.com"
    bounded = _bounded_host(long_host)
    assert len(bounded) <= MAX_HOST_BYTES
    assert len(bounded.split(".")) <= MAX_HOST_LABELS

    # The registrable part is kept: labels are dropped from the left.
    assert bounded.endswith("example.com")

    # An ordinary host is untouched.
    assert _bounded_host("github.com") == "github.com"
    assert _bounded_host("raw.githubusercontent.com") == "raw.githubusercontent.com"


def test_classifying_a_full_cap_of_hostile_urls_is_quick():
    """The bound has to hold at the cap, not just for one URL."""
    import time

    from trustsight.buckets import classify_urls
    from trustsight.differ import MAX_URL_TOKEN_BYTES, MAX_URLS_PER_SIDE

    classify_urls(["https://warm.example/x"])  # one-time setup

    urls = [
        ("https://" + "a." * 4000 + f"u{i}.example/x")[:MAX_URL_TOKEN_BYTES]
        for i in range(MAX_URLS_PER_SIDE)
    ]
    start = time.monotonic()
    classify_urls(urls)
    elapsed = time.monotonic() - start

    assert elapsed < 30.0, f"{elapsed:.1f}s to classify {MAX_URLS_PER_SIDE} URLs"


@pytest.mark.parametrize("host", ["gіthub.com", "gitlаb.com", "sourceforgе.net"])
def test_padding_a_host_does_not_change_its_classification(host):
    """Truncation must not become a way past detection.

    The bound drops labels from the left, so a homograph in the registrable
    domain survives it. Left-padding with thousands of labels - which is
    what an attacker would try once a length bound exists - classifies the
    same as the bare host.
    """
    from trustsight.buckets import classify_url

    bare, _ = classify_url(f"https://{host}/x")
    assert bare == "homograph_attack", "fixture is wrong: bare host not detected"

    padded, _ = classify_url("https://" + "a." * 5000 + host + "/x")
    assert padded == bare, "padding changed the verdict"


@pytest.mark.parametrize("url", [
    "https://", "", "evil.example/x", "https://[::1]:8080/x",
    "https://user:pass@evil.example@good.example/x",
    "https://example.org:99999999999/x",
    "https://ev\x00il.example/x",
    "https://" + "a@" * 5000 + "example.org/",
])
def test_malformed_urls_are_survivable(url):
    from trustsight.buckets import classify_urls

    assert isinstance(classify_urls([url]), dict)
