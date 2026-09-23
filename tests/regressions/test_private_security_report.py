"""Regressions for the private security report of 2026-09-23.

Each test pins one finding, named by its report number.  Where the report's
own reading was wrong, the test pins the corrected behaviour and says so.
"""

import json
import os
import stat
import tarfile

import pygit2
import pytest

from trustsight import discovery
from trustsight.bounded_io import ReadTimedOut, read_capped_with_deadline
from trustsight.cli.inspect import _failed_history_result, _finding_line
from trustsight.config import ensure_dirs
from trustsight.coverage import (
    BINARY_METADATA,
    begin_stage_tracking,
    stage_failures,
)
from trustsight.differ import (
    _resolve_checksum_text,
    binary_metadata_in_text,
    binary_metadata_paths,
)
from trustsight.safe_text import clean
from trustsight.seed_build import SEED_FORMAT_VERSION, build_seed
from trustsight.tokenizer import TokenizerUnavailable


# The conftest autouse fixture replaces `discovery.get_aur_package_info`;
# keep the real one so its offline guard can be exercised.
_REAL_GET_AUR_PACKAGE_INFO = discovery.get_aur_package_info


def _commit(repo, files: dict[str, bytes], parents, message="c"):
    sig = pygit2.Signature("Tester", "tester@example.com")
    builder = repo.TreeBuilder()
    for name, data in files.items():
        builder.insert(name, repo.create_blob(data), pygit2.GIT_FILEMODE_BLOB)
    return repo.create_commit("HEAD", sig, sig, message, builder.write(), parents)


@pytest.fixture
def repo(tmp_path):
    return pygit2.init_repository(str(tmp_path / "repo"))


# --- 2.1: a fetch must advance the analysed commit --------------------------

def test_stale_marker_and_future_dated_commit_still_fetches(tmp_path, monkeypatch):
    """2.1: a marker older than upstream must not be rescued by commit time.

    The report's finding is that HEAD never moves after a fetch.  While
    removing the dead `head.is_remote` branch this exposed a second hole:
    `_is_current` fell through to HEAD's commit time even when it had a
    marker, so a future-dated commit suppressed the fetch.
    """
    from trustsight.fetcher import _is_current, _record_fetch

    repo = pygit2.init_repository(str(tmp_path / "r"))
    author = pygit2.Signature(
        "T", "t@e.com", int(__import__("time").time()) + 10 * 365 * 86400, 0
    )
    blob = repo.create_blob(b"pkgver=1\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    repo.create_commit("HEAD", author, author, "future", builder.write(), [])

    import time

    _record_fetch(repo)
    # Marker is "now"; upstream reports an update 5s later.  However far
    # ahead HEAD claims to be, this is not current.
    assert _is_current(repo, int(time.time()) + 5) is False


# --- 2.2: binary metadata is not a silent skip ------------------------------

def test_binary_pkgbuild_is_detected_at_the_git_level(repo):
    """2.2: a NUL turns the diff into one line with no body."""
    c1 = _commit(repo, {"PKGBUILD": b'pkgver=1\nsource=("https://a/x.tar.gz")\n'}, [])
    c2 = _commit(
        repo,
        {"PKGBUILD": b'pkgver=2\nsource=("https://evil.example/x.sh")\n\x00\n'},
        [c1],
    )
    assert binary_metadata_paths(repo, str(c1), str(c2)) == ["PKGBUILD"]


def test_binary_metadata_marker_is_detected_in_text():
    """2.2: the text path reads the marker git wrote."""
    diff = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        "Binary files a/PKGBUILD and b/PKGBUILD differ\n"
    )
    assert binary_metadata_in_text(diff) == ["PKGBUILD"]


def test_scan_diff_records_the_binary_metadata_gap_and_finding():
    """2.2: the gap and the HIGH finding travel with the text path."""
    from trustsight.analysis.pipeline import scan_diff

    diff = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        "Binary files /dev/null and b/PKGBUILD differ\n"
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "trustsight.analysis.pipeline.binary_metadata_in_text",
            lambda text: ["PKGBUILD"],
        )
        fact = scan_diff(diff, package_name="demo")
    assert BINARY_METADATA in fact.coverage_gaps
    assert any(e.rule_id == "C010" and e.severity == "HIGH"
               for e in fact.score_breakdown)


# --- 2.3: a stage failure is not "nothing found" ----------------------------

def test_dependency_scan_failure_is_recorded(monkeypatch):
    """2.3a: the bare except used to return a neutral False."""
    from trustsight.analysis import pipeline

    def boom(*a, **k):
        raise RuntimeError("parse blew up")

    monkeypatch.setattr("trustsight.deps.extract_dependency_changes", boom)
    begin_stage_tracking()
    assert pipeline._adds_a_dependency("+depends=(foo)\n") is False
    assert "dependency-change-scan" in stage_failures()


def test_dependency_scan_reraise_tokenizer_unavailable(monkeypatch):
    """2.3a: a missing tokenizer is a refusal, not a neutral result."""
    from trustsight.analysis import pipeline

    def dead(*a, **k):
        raise TokenizerUnavailable("forced")

    monkeypatch.setattr("trustsight.deps.extract_dependency_changes", dead)
    begin_stage_tracking()
    with pytest.raises(TokenizerUnavailable):
        pipeline._adds_a_dependency("+depends=(foo)\n")


def test_checksum_resolution_failure_is_recorded(monkeypatch):
    """2.3b: unresolved checksum text must not clear the gap."""
    def boom(lines):
        raise RuntimeError("tokenizer blew up")

    monkeypatch.setattr("trustsight.tokenizer.variable_table", boom)
    begin_stage_tracking()
    out = _resolve_checksum_text("+_cs=SKIP\n", 'sha256sums=("${_cs}")')
    assert out == 'sha256sums=("${_cs}")'
    assert "checksum-resolution" in stage_failures()


# --- 2.4: pattern verdicts are decided once ---------------------------------

def test_refused_pattern_is_cached():
    """2.4: the timing refusal used to be re-decided per call, so the same
    input could score differently under load."""
    from trustsight import rules

    pattern = r"(a+)+$"
    first = rules._compiled(pattern, rule_id="X")
    second = rules._compiled(pattern, rule_id="X")
    assert first is None
    assert second is None
    assert rules._pattern_cache[pattern] is None


def test_precompile_shipped_patterns_runs():
    from trustsight.rules import precompile_shipped_patterns

    precompile_shipped_patterns()


def test_refused_rule_is_reported_as_a_stage_gap():
    """2.4: a refused rule used to be a silent `continue`."""
    from trustsight.rules import apply_rules

    rule = {"id": "Z9", "name": "z", "pattern": r"(a+)+$",
            "severity": "HIGH", "category": "test", "match_target": "raw_line"}
    begin_stage_tracking()
    out = apply_rules(["a" * 64], ["a" * 64], rules=[rule])
    assert out == []
    assert any(stage.startswith("rule:") for stage in stage_failures())


# --- 2.5: the sandbox cannot be spent on purpose -----------------------------

def test_frame_cap_covers_the_escaping_worst_case():
    """2.5: control bytes become six-byte ``\\u00XX`` escapes."""
    from trustsight.sandbox import protocol

    assert protocol.MAX_FRAME_BYTES >= 6 * (5 * 1024 * 1024)


def test_worker_cpu_reading_is_safe_without_a_process():
    from trustsight.sandbox.client import _worker_cpu_seconds, _Worker

    assert _worker_cpu_seconds(_Worker()) == 0.0


def test_worker_cpu_reading_matches_the_process():
    """2.5: the reading must be the child's cumulative CPU, not a constant."""
    import resource

    from trustsight.sandbox.client import _worker_cpu_seconds, _Worker

    class FakeProc:
        pid = os.getpid()

    worker = _Worker()
    worker.proc = FakeProc()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    expected = usage.ru_utime + usage.ru_stime
    assert abs(_worker_cpu_seconds(worker) - expected) < 0.5


def test_isolation_helpers_report_a_bool():
    from trustsight.sandbox import expand_worker

    assert isinstance(expand_worker._no_new_privs(), bool)
    assert isinstance(expand_worker._drop_network(), bool)


def test_worker_spawn_disables_user_site(monkeypatch):
    """2.8: the child must not run a user .pth or sitecustomize."""
    from trustsight.sandbox import client as client_mod

    captured = {}

    class FakeProc:
        pid = 12345
        stdin = stdout = stderr = None

        def poll(self):
            return None

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        return FakeProc()

    monkeypatch.setattr(client_mod.subprocess, "Popen", fake_popen)
    worker = client_mod._Worker()
    worker.start()
    try:
        assert "-s" in captured["argv"]
        assert "-I" not in captured["argv"]
    finally:
        worker.proc = None


# --- 2.6: history rendering and failed commits -------------------------------

def test_finding_line_has_no_escape():
    line = _finding_line({
        "file": "\x1b[31mPKGBUILD", "line": 1,
        "rule_id": "R001", "reason": "\x1b[2Jcleared",
    })
    assert "\x1b" not in line


def test_failed_history_result_is_marked():
    class Commit:
        id = "a" * 40
        commit_time = 0
        message = "evil \x1b[31m"

    row = _failed_history_result(Commit(), "analysis failed: boom")
    assert row["failed"] is True
    assert "boom" in row["error"]


def test_history_plain_renderer_cleans_commit_text(capsys):
    from trustsight.cli.inspect import _render_history_panel_plain

    _render_history_panel_plain(
        {"commit": "abc12345", "commit_message": "\x1b[31mred\x1b[0m",
         "findings": [], "changes": []},
        show_score=False, show_risk=False,
    )
    out = capsys.readouterr().out
    assert "\x1b" not in out


def test_history_rich_renderer_cleans_commit_text(capsys):
    from trustsight.cli.inspect import _render_history_panel_rich

    _render_history_panel_rich(
        {"commit": "abc12345", "commit_message": "\x1b]52;c;payload\x07",
         "findings": [], "changes": [], "package": "demo"},
        show_score=False, show_risk=False, verbose=False,
    )
    out = capsys.readouterr().out
    assert "\x1b" not in out


# --- 2.7: privacy and the seed ----------------------------------------------

def test_aur_rpc_is_off_by_default(monkeypatch):
    """2.7: TRUSTSIGHT_OFFLINE must cover the RPC."""
    monkeypatch.setattr(discovery, "get_aur_package_info", _REAL_GET_AUR_PACKAGE_INFO)
    monkeypatch.setenv("TRUSTSIGHT_OFFLINE", "1")
    import trustsight.db as db

    monkeypatch.setattr(db, "read_aur_cache", lambda names, ttl_minutes=60: {})
    assert discovery.get_aur_package_info(["secret-private-pkg"]) == {}


def test_seed_v3_ships_no_email_hash_or_package_list(tmp_path):
    """2.7: the salt is public, so both are personal data."""
    raw = [{"name": "Alice", "email": "alice@example.com", "packages": ["p"]}]
    build_seed(raw, tmp_path)
    meta = json.loads((tmp_path / "trustsight-seed-v2" / "seed_meta.json").read_text())
    assert meta["format_version"] == SEED_FORMAT_VERSION == "3.0.0"
    row = json.loads(
        (tmp_path / "trustsight-seed-v2" / "maintainers.jsonl").read_text().strip()
    )
    assert "email_hash" not in row
    assert "packages" not in row
    assert row["package_count"] == 1


# --- 2.8: hardening ---------------------------------------------------------

def test_clean_strips_bidi_and_zero_width():
    assert clean("\u202eabc\u200b\u2066def\ufeff") == "abcdef"


def test_ensure_dirs_is_owner_only(tmp_path, monkeypatch):
    import trustsight.config as config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "c")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "d")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    ensure_dirs()
    for path in (config.CONFIG_DIR, config.DATA_DIR, config.CACHE_DIR):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_database_file_is_owner_only(tmp_path, monkeypatch):
    import trustsight.db as db

    monkeypatch.setattr(db, "DATA_DIR", tmp_path)
    db.init_db()
    mode = stat.S_IMODE(db.get_db_path().stat().st_mode)
    assert mode == 0o600


def test_read_deadline_refuses_a_slow_stream():
    class Endless:
        def read(self, n):
            return b"x"

    with pytest.raises(ReadTimedOut):
        read_capped_with_deadline(Endless(), 10**9, "slow", deadline_seconds=-1)


def test_snapshot_manifest_bounds_total_members():
    """2.8: skipped members must count, or a tar of directories walks free.

    The old loop bounded ``len(manifest)``, which stays zero when every
    member is a directory, so the walk consumed the whole archive.  Count
    what the iterator actually yielded.
    """
    from trustsight.full_aur.fetch import _snapshot_manifest

    class EndlessTar:
        def __init__(self, n):
            self.n = n
            self.consumed = 0

        def __iter__(self):
            for i in range(self.n):
                self.consumed += 1
                info = tarfile.TarInfo(f"dir{i}")
                info.type = tarfile.DIRTYPE
                yield info

    fake = EndlessTar(10_000)
    assert _snapshot_manifest(fake, max_members=5) == []
    # At most `max_members` processed plus one already yielded by the
    # iterator when the check breaks the loop.
    assert fake.consumed <= 6


def test_ioc_import_requires_the_pinned_key(tmp_path):
    """2.8: a manifest must not be trusted because it carries its own key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from trustsight.ioc_baseline import InvalidSignatureError, import_baseline

    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes_raw().hex()
    manifest = {
        "version": 1, "source": "evil", "created_at": "2026-01-01T00:00:00",
        "expires_at": "2030-01-01T00:00:00", "signature": "", "public_key": pub_hex,
    }
    iocs = json.dumps({"type": "host", "value": "evil.example"}) + "\n"
    payload = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode() + iocs.encode()
    manifest["signature"] = key.sign(payload).hex()
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "iocs.jsonl").write_text(iocs)

    with pytest.raises(InvalidSignatureError):
        import_baseline(tmp_path)


def test_tampered_manifest_payload_is_rejected(tmp_path):
    """2.8: the exact bytes are signed, not the name or version."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from trustsight.ioc_baseline import InvalidSignatureError, import_baseline

    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes_raw().hex()
    manifest = {
        "version": 1, "source": "x", "created_at": "2026-01-01T00:00:00",
        "expires_at": "2030-01-01T00:00:00", "signature": "", "public_key": pub_hex,
    }
    iocs = json.dumps({"type": "host", "value": "evil.example"}) + "\n"
    payload = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode() + iocs.encode()
    manifest["signature"] = key.sign(payload).hex()
    # Change the signed source after signing.
    manifest["source"] = "tampered"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "iocs.jsonl").write_text(iocs)

    with pytest.raises(InvalidSignatureError):
        import_baseline(tmp_path)
