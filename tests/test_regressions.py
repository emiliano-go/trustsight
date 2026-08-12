"""Regression suite: every past defect that reached a release, pinned.

Each test reproduces a bug that shipped at some point and names the fix
commit in its group comment.  A future change that reintroduces the defect
fails here first, before it reaches a release or a CI gate that only
catches it downstream.
"""

import gzip
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent


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
# 30c1bc9 - reserved names must not be writable through the name-keyed tables
#
# upsert_package had a reserved-name guard; save_pkgbuild_snapshot and
# save_package_profile are keyed by package_name directly, so a baseline
# artifact (or an AUR package actually named __seed__) could slip a row into
# tables the rest of the code treats as internal.  One such import used to
# abort a run over ninety thousand packages.
# ---------------------------------------------------------------------------


def test_is_reserved_name_recognises_sentinels():
    from trustsight.db import is_reserved_name

    assert is_reserved_name("__seed__")
    assert is_reserved_name("__whatever")
    assert not is_reserved_name("firefox")
    assert not is_reserved_name("hmx")


def test_save_pkgbuild_snapshot_rejects_reserved_names(isolated):
    from trustsight.db import save_pkgbuild_snapshot

    with pytest.raises(ValueError, match="reserved package name"):
        save_pkgbuild_snapshot("__seed__", "pkg() {}", "1.0")
    with pytest.raises(ValueError, match="reserved package name"):
        save_pkgbuild_snapshot("__hidden", "pkg() {}", "1.0")


def test_save_package_profile_rejects_reserved_names(isolated):
    from trustsight.db import save_package_profile

    with pytest.raises(ValueError, match="reserved package name"):
        save_package_profile("__seed__", 25)
    with pytest.raises(ValueError, match="reserved package name"):
        save_package_profile("__hidden", 25)


_MANIFEST = {
    "version": 1, "ruleset_version": "t", "scorer_version": "t",
    "corpus_cutoff": "",
}


def _metadata_hash(metadata_list) -> str:
    raw = json.dumps(metadata_list, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _write_artifact(tmp_path, payload, name="ragged.gz") -> Path:
    from trustsight.full_aur.export import canonical_artifact_bytes

    metadata = [{"Name": "demo"}]
    canonical = canonical_artifact_bytes(
        [], [], _metadata_hash(metadata), _MANIFEST
    )
    artifact = {"signature": None, **json.loads(canonical), **payload,
                "metadata_snapshot": metadata}
    path = tmp_path / name
    path.write_bytes(gzip.compress(json.dumps(artifact).encode()))
    return path


def test_import_baseline_skips_reserved_names_not_fatal(isolated):
    """A reserved-name profile or snapshot must be skipped, not fatal."""
    path = _write_artifact(isolated, {
        "profiles": [
            {"package_name": "__seed__", "last_score": 99},
            {"package_name": "firefox", "last_score": 5},
        ],
        "snapshots": [
            {"package_name": "__seed__", "pkgbuild_text": "pkg(){}"},
            {"package_name": "firefox", "pkgbuild_text": "pkg(){}", "version": "1.0"},
        ],
    })

    from trustsight.full_aur.export import import_baseline

    import_baseline(str(path), allow_unsigned=True)  # must not raise

    from trustsight.db import get_package_profile, get_pkgbuild_snapshot

    assert get_package_profile("__seed__") is None
    assert get_pkgbuild_snapshot("__seed__") is None
    assert get_package_profile("firefox") is not None
    assert get_pkgbuild_snapshot("firefox") is not None


def test_corpus_sweep_skips_reserved_members(isolated, monkeypatch):
    """A cluster finding naming __seed__ must not update its profile."""
    import trustsight.full_aur.pipeline as pipeline

    finding = {"severity": "HIGH", "params": {"members": ["__seed__", "firefox"]}}
    monkeypatch.setattr(
        pipeline, "run_corpus_sweep", lambda *a, **k: [finding]
    )
    monkeypatch.setattr(
        pipeline, "load_config", lambda: {"severity_weights": {"HIGH": 25}}
    )

    results = pipeline._run_corpus_sweep({}, {}, processed=set(), scores={})

    from trustsight.db import get_package_profile

    assert get_package_profile("__seed__") is None
    assert get_package_profile("firefox") is not None
    assert results == [finding]


# ---------------------------------------------------------------------------
# 30c1bc9 - code-emitted rules must clamp their input like rules.toml does
#
# apply_rules clamped per line, but the analysis-module regexes matched the
# raw diff text directly: one 5 MiB line cost 0.17s through rules.toml and
# 15s through the code-emitted rules, an attacker-picked multiplier on how
# long a review takes.  clamp_text brings the code path under the same cap
# while keeping every line (so indexes and oversized_lines agree).
# ---------------------------------------------------------------------------


def test_clamp_text_truncates_long_lines_keeping_the_line_count():
    from trustsight.rules import MAX_RULE_LINE_BYTES, clamp_text

    long_line = "+" + "a" * (MAX_RULE_LINE_BYTES * 3)
    text = "pkgname=foo\n" + long_line + "\nsha256sums=('x')\n"
    out = clamp_text(text)

    assert out is not None
    lines = out.split("\n")
    assert len(lines) == len(text.split("\n"))
    assert len(lines[0]) <= MAX_RULE_LINE_BYTES
    assert lines[0] == "pkgname=foo"          # short lines untouched
    assert len(lines[1]) == MAX_RULE_LINE_BYTES
    assert len(lines[1]) < len(long_line)


def test_clamp_text_passes_through_short_and_none():
    from trustsight.rules import MAX_RULE_LINE_BYTES, clamp_text

    assert clamp_text(None) is None
    short = "pkgname=foo\npkgrel=1\n"
    assert clamp_text(short) == short
    assert clamp_text("a" * (MAX_RULE_LINE_BYTES - 1)) == "a" * (MAX_RULE_LINE_BYTES - 1)


def test_scan_diff_survives_a_pathological_long_line(isolated):
    """A giant single line must not stall or crash the code-emitted rules."""
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config
    from trustsight.schema import DiffSummary

    monster = "+payload_" + ("A" * 200_000)
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-bar\n" + monster + "\n"

    fact = scan_diff(
        diff, rules=[], config=load_config(), package_name="p", seen_urls={}
    )

    assert isinstance(fact.diff_summary, DiffSummary)


# ---------------------------------------------------------------------------
# 9ee6204 - the fixture corpus must reject unregistered .diff files
#
# Three scratch .diff files swept in by `git add -A` reached a merge commit
# and failed the Tests run; nothing referenced them.  verify_fixtures is the
# owner of that invariant, run here so the failure surfaces locally, not
# only in CI.
# ---------------------------------------------------------------------------


def test_verify_fixtures_passes_on_the_committed_corpus():
    result = subprocess.run(
        [sys.executable, str(_REPO_ROOT / "scripts" / "verify_fixtures.py")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_verify_fixtures_flags_an_unregistered_scratch_diff(tmp_path):
    (tmp_path / "synthetic").mkdir()
    (tmp_path / "synthetic" / "expected.json").write_text(
        json.dumps({"a.diff": {"rule_ids": []}})
    )
    (tmp_path / "synthetic" / "a.diff").write_text("+x\n")
    (tmp_path / "synthetic" / "orphan.diff").write_text("+y\n")  # unregistered

    result = subprocess.run(
        [sys.executable, str(_REPO_ROOT / "scripts" / "verify_fixtures.py"),
         "--root", str(tmp_path)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "orphan .diff" in (result.stdout + result.stderr)


# ---------------------------------------------------------------------------
# 4a1c05f - crash guards on the humane failure paths
#
# A repository with no readable HEAD used to raise out of analyze_package; a
# machine without rich used to crash the console.  python -m trustsight is
# the documented entry point (4fb94d4) and must resolve.
# ---------------------------------------------------------------------------


def test_python_m_entrypoint_reports_version(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env.setdefault("XDG_CONFIG_HOME", str(tmp_path / "config"))
    env.setdefault("XDG_DATA_HOME", str(tmp_path / "data"))
    env.setdefault("HOME", str(tmp_path))

    result = subprocess.run(
        [sys.executable, "-m", "trustsight", "--version"],
        cwd=str(_REPO_ROOT), env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().startswith("trustsight ")


def test_console_raises_without_rich(monkeypatch):
    from trustsight.cli import display

    monkeypatch.setattr(display, "HAS_RICH", False)
    with pytest.raises(RuntimeError, match="rich is not available"):
        display.console()


def test_print_colored_falls_back_to_plain_print_without_rich(monkeypatch, capsys):
    from trustsight.cli import display

    monkeypatch.setattr(display, "HAS_RICH", False)
    display._print_colored("warning: nothing to see", color="yellow")
    assert capsys.readouterr().out == "warning: nothing to see\n"


def test_analyze_package_tolerates_a_repo_with_no_head(isolated, monkeypatch):
    import pygit2

    import trustsight.analysis.pipeline as pipeline

    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: object())
    monkeypatch.setattr(
        pipeline, "get_head_commit",
        lambda repo: (_ for _ in ()).throw(pygit2.GitError("could not resolve HEAD")),
    )
    monkeypatch.setattr(pipeline, "get_pkgver_from_head", lambda repo: "1.1")
    monkeypatch.setattr(pipeline, "_recent_update", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "_package_is_new", lambda *a, **k: None)

    fact = pipeline.analyze_package("demo", installed_version="1.0")

    assert fact.first_seen is True
    assert fact.old_version == "1.0"
    assert fact.new_version == "1.1"
    assert fact.new_commit == ""


# ---------------------------------------------------------------------------
# b9a332b - inspect / verdict behaviour on first analyses and empty diffs
#
# A first analysis used to report old_version as "" and could produce a
# verdict that implied a diff had been examined.  The first-seen verdict
# must say there is no prior history; the inspect table must not draw a
# "+0 -0" line.
# ---------------------------------------------------------------------------


def test_fallback_verdict_first_seen_without_versions_says_insufficient():
    from trustsight.schema import PackageFact
    from trustsight.verdict import fallback_verdict

    fact = PackageFact(package_name="p", first_seen=True)
    verdict = fallback_verdict(fact)

    assert "No prior history" in verdict
    assert "Insufficient data for a verdict." in verdict


def test_fallback_verdict_first_analysis_says_no_version_bump_confirmed():
    from trustsight.schema import PackageFact
    from trustsight.verdict import fallback_verdict

    fact = PackageFact(
        package_name="p", first_seen=True,
        old_version="1.0", new_version="1.1",
    )
    verdict = fallback_verdict(fact)

    assert verdict.startswith("First analysis.")
    assert "No prior history" in verdict
    assert "No version bump confirmed yet." in verdict


def test_inspect_omits_the_lines_row_on_a_zero_diff(monkeypatch):
    """A review with no diff must not draw a stale '+0 -0' line."""
    from rich.console import Console

    from trustsight.cli import inspect as inspect_cli
    from trustsight.schema import DiffSummary, PackageFact

    out = Console(record=True, width=200)
    monkeypatch.setattr(inspect_cli, "console", lambda: out)

    no_diff = PackageFact(
        package_name="p", old_version="1.0", new_version="1.1",
        diff_summary=DiffSummary(lines_added=0, lines_removed=0),
    )
    with_diff = PackageFact(
        package_name="p", old_version="1.0", new_version="1.1",
        diff_summary=DiffSummary(lines_added=2, lines_removed=3),
    )

    inspect_cli._inspect_rich(no_diff)
    rendered = out.export_text()
    assert "Lines" not in rendered

    out2 = Console(record=True, width=200)
    monkeypatch.setattr(inspect_cli, "console", lambda: out2)
    inspect_cli._inspect_rich(with_diff)
    assert "Lines" in out2.export_text()


# ---------------------------------------------------------------------------
# 91a5659 - the release tarball may not carry the PKGBUILD for its own checksum
#
# git archive honours .gitattributes export-ignore; the release tarball is
# that archive.  A packaging/ that leaks into it makes check() read a
# PKGBUILD whose checksums can never match, the v0.12.0 failure.
# ---------------------------------------------------------------------------


def test_packaging_is_export_ignore_from_archives():
    """The release tarball (git archive) may not carry packaging/ at all."""
    import io
    import tarfile

    result = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=str(_REPO_ROOT), capture_output=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode()
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tf:
        members = {m.name for m in tf.getmembers()}
    assert not any(name.startswith("packaging/") for name in members), (
        "packaging/ leaked into the archive; check .gitattributes export-ignore"
    )