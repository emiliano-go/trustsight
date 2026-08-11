"""IOC Federation baseline system tests (v0.12.0 spec §2)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from trustsight.ioc_baseline import (
    InvalidSignatureError,
    MalformedBaselineError,
    UnsignedBaselineError,
    active_iocs,
    all_ioc_sources,
    import_baseline,
    match_domain,
    match_hash,
    match_ioc,
    match_package,
)


@pytest.fixture
def baseline_dir(tmp_path: Path) -> Path:
    """Return a baseline directory with one of each IOC type."""
    base = tmp_path / "baseline"
    base.mkdir()
    manifest = {
        "version": 1,
        "source": "test-feed",
        "created_at": _now_iso(),
        "expires_at": "",
        "signature": "",
        "public_key": "",
    }
    (base / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    iocs = [
        {"type": "domain", "value": "malware.example", "source": "test-feed",
         "confidence": "high", "provenance": "ASA-2026-0001", "campaign": "2026-06"},
        {"type": "package", "value": "evil-pkg", "source": "test-feed",
         "confidence": "confirmed", "provenance": "ASA-2026-0001"},
        {"type": "hash", "value": "a" * 64, "source": "test-feed",
         "confidence": "high", "provenance": "vendor report"},
    ]
    (base / "iocs.jsonl").write_text(
        "\n".join(json.dumps(row) for row in iocs), encoding="utf-8"
    )
    return base


@pytest.fixture
def signed_baseline_dir(tmp_path: Path) -> tuple[Path, bytes]:
    """Return a signed baseline directory and the public key bytes."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    base = tmp_path / "signed-baseline"
    base.mkdir()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()

    manifest = {
        "version": 1,
        "source": "signed-feed",
        "created_at": _now_iso(),
        "expires_at": "",
        "signature": "",
        "public_key": public_key.hex(),
    }
    manifest_path = base / "manifest.json"
    iocs_path = base / "iocs.jsonl"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    iocs = [
        {"type": "domain", "value": "signed.example", "source": "signed-feed"},
    ]
    iocs_path.write_text(
        "\n".join(json.dumps(row) for row in iocs), encoding="utf-8"
    )

    # Sign the canonical manifest (signature removed) concatenated with iocs.
    signing_manifest = {**manifest, "signature": ""}
    payload = (
        json.dumps(signing_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + iocs_path.read_bytes()
    )
    signature = private_key.sign(payload)
    manifest["signature"] = signature.hex()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    return base, public_key


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """Point the database at a scratch directory."""
    import trustsight.config as config
    from trustsight.db import init_db

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield tmp_path


def test_import_baseline_requires_allow_unsigned_for_unsigned(baseline_dir, isolated_db):
    with pytest.raises(UnsignedBaselineError):
        import_baseline(baseline_dir, allow_unsigned=False)


def test_import_baseline_allow_unsigned(baseline_dir, isolated_db):
    result = import_baseline(baseline_dir, allow_unsigned=True)
    assert result["source"] == "test-feed"
    assert result["entries_imported"] == 3
    assert result["verified"] is False

    sources = all_ioc_sources()
    assert sources == ["test-feed"]


def test_import_baseline_signed(signed_baseline_dir, isolated_db):
    base, _pub = signed_baseline_dir
    result = import_baseline(base, allow_unsigned=False)
    assert result["verified"] is True
    assert result["entries_imported"] == 1
    assert all_ioc_sources() == ["signed-feed"]


def test_import_baseline_signature_tampered(signed_baseline_dir, isolated_db):
    base, _pub = signed_baseline_dir
    manifest_path = base / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["signature"] = "00" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(InvalidSignatureError):
        import_baseline(base, allow_unsigned=False)


def test_import_baseline_source_override(baseline_dir, isolated_db):
    result = import_baseline(baseline_dir, source_name="override", allow_unsigned=True)
    assert result["source"] == "override"
    assert all_ioc_sources() == ["override"]


def test_import_replaces_same_source(baseline_dir, isolated_db):
    import_baseline(baseline_dir, allow_unsigned=True)
    # Re-import with fewer entries; old rows for the source are replaced.
    base2 = isolated_db / "baseline2"
    base2.mkdir()
    manifest = {
        "version": 1, "source": "test-feed", "created_at": _now_iso(),
        "expires_at": "", "signature": "", "public_key": "",
    }
    (base2 / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (base2 / "iocs.jsonl").write_text(
        json.dumps({"type": "domain", "value": "other.example", "source": "test-feed"}),
        encoding="utf-8",
    )
    import_baseline(base2, allow_unsigned=True)
    entries = active_iocs(source="test-feed")
    assert len(entries) == 1
    assert entries[0].value == "other.example"


def test_import_leaves_other_sources_alone(baseline_dir, isolated_db):
    import_baseline(baseline_dir, source_name="alpha", allow_unsigned=True)
    import_baseline(baseline_dir, source_name="beta", allow_unsigned=True)
    assert sorted(all_ioc_sources()) == ["alpha", "beta"]
    assert len(active_iocs(source="alpha")) == 3
    assert len(active_iocs(source="beta")) == 3


def test_import_drops_bad_entries(baseline_dir, isolated_db):
    iocs_path = baseline_dir / "iocs.jsonl"
    bad = [
        {"type": "carrier-pigeon", "value": "x", "source": "test-feed"},
        {"type": "hash", "value": "not-a-digest", "source": "test-feed"},
        {"type": "domain", "value": "valid.example", "source": "test-feed"},
    ]
    iocs_path.write_text("\n".join(json.dumps(row) for row in bad), encoding="utf-8")
    result = import_baseline(baseline_dir, allow_unsigned=True)
    assert result["entries_imported"] == 1


def test_reimport_keeps_expired_rows_of_the_source(baseline_dir, isolated_db):
    """Re-importing a source must replace only its non-expired rows; expired
    history stays attributable (module docstring and schema promise)."""
    manifest = json.loads((baseline_dir / "manifest.json").read_text())
    manifest["source"] = "expiring-feed"
    (baseline_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    rows = [
        {"type": "domain", "value": "old.example", "source": "expiring-feed",
         "expires_at": yesterday},
        {"type": "domain", "value": "new.example", "source": "expiring-feed"},
    ]
    (baseline_dir / "iocs.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows), encoding="utf-8"
    )
    import_baseline(baseline_dir, allow_unsigned=True)

    (baseline_dir / "iocs.jsonl").write_text(
        json.dumps({"type": "domain", "value": "other.example", "source": "expiring-feed"}),
        encoding="utf-8",
    )
    result = import_baseline(baseline_dir, allow_unsigned=True)
    assert result["entries_imported"] == 1
    # The expired row survived the re-import; the replaced row did not.
    expired_view = active_iocs(source="expiring-feed", expired=True)
    values = {e.value for e in expired_view}
    assert "old.example" in values
    assert "new.example" not in values
    assert "other.example" in values


def test_import_duplicate_rows_are_deduped_not_crash(baseline_dir, isolated_db):
    """Two identical (type, value, source) rows in one baseline must import
    once, not raise IntegrityError."""
    (baseline_dir / "iocs.jsonl").write_text(
        "\n".join([
            json.dumps({"type": "domain", "value": "dup.example", "source": "test-feed"}),
            json.dumps({"type": "domain", "value": "dup.example", "source": "test-feed"}),
            json.dumps({"type": "domain", "value": "keep.example", "source": "test-feed"}),
        ]),
        encoding="utf-8",
    )
    result = import_baseline(baseline_dir, allow_unsigned=True)
    assert result["entries_imported"] == 2
    assert len(active_iocs(source="test-feed")) == 2


def test_naive_expires_at_is_treated_as_utc(baseline_dir, isolated_db):
    """A tz-less expires_at must actually expire, not be misread as
    permanently active."""
    manifest = json.loads((baseline_dir / "manifest.json").read_text())
    manifest["source"] = "naive-feed"
    (baseline_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    rows = [
        {"type": "domain", "value": "naive.example", "source": "naive-feed",
         "expires_at": yesterday.replace("+00:00", "")},
    ]
    (baseline_dir / "iocs.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows), encoding="utf-8"
    )
    import_baseline(baseline_dir, allow_unsigned=True)
    assert len(active_iocs(source="naive-feed")) == 0
    assert len(active_iocs(source="naive-feed", expired=True)) == 1


def test_malformed_manifest_version_and_encoding_are_clean_errors(baseline_dir, isolated_db):
    manifest = json.loads((baseline_dir / "manifest.json").read_text())
    manifest["version"] = "abc"
    (baseline_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(MalformedBaselineError, match="version"):
        import_baseline(baseline_dir, allow_unsigned=True)

    (baseline_dir / "manifest.json").write_bytes(b"\xff\xfe\x00manifest")
    with pytest.raises(MalformedBaselineError, match="UTF-8"):
        import_baseline(baseline_dir, allow_unsigned=True)


def test_active_iocs_filters_by_source(baseline_dir, isolated_db):
    import_baseline(baseline_dir, allow_unsigned=True)
    assert len(active_iocs(source="test-feed")) == 3
    assert len(active_iocs(source="missing")) == 0


def test_match_domain_registered_domain(baseline_dir, isolated_db):
    import_baseline(baseline_dir, allow_unsigned=True)
    hits = match_domain("cdn.malware.example")
    assert len(hits) == 1
    assert hits[0].type == "domain"
    assert hits[0].value == "malware.example"


def test_match_domain_exact_host(baseline_dir, isolated_db):
    import_baseline(baseline_dir, allow_unsigned=True)
    hits = match_domain("malware.example")
    assert len(hits) == 1
    assert hits[0].value == "malware.example"


def test_match_domain_no_match(baseline_dir, isolated_db):
    import_baseline(baseline_dir, allow_unsigned=True)
    assert match_domain("example.org") == []


def test_match_hash(baseline_dir, isolated_db):
    import_baseline(baseline_dir, allow_unsigned=True)
    hits = match_hash("A" * 64)
    assert len(hits) == 1
    assert hits[0].type == "hash"


def test_match_package(baseline_dir, isolated_db):
    import_baseline(baseline_dir, allow_unsigned=True)
    hits = match_package("Evil-Pkg")
    assert len(hits) == 1
    assert hits[0].type == "package"


def test_match_ioc_normalizes_value(baseline_dir, isolated_db):
    import_baseline(baseline_dir, allow_unsigned=True)
    assert len(match_ioc("domain", "MALWARE.EXAMPLE.")) == 1
    assert len(match_ioc("hash", "A" * 64)) == 1
    assert len(match_ioc("package", "EVIL-PKG")) == 1


def test_expired_entries_stored_but_not_active(baseline_dir, isolated_db):
    manifest = json.loads((baseline_dir / "manifest.json").read_text())
    manifest["source"] = "expiring-feed"
    (baseline_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    rows = [
        {"type": "domain", "value": "old.example", "source": "expiring-feed",
         "expires_at": yesterday},
        {"type": "domain", "value": "new.example", "source": "expiring-feed"},
    ]
    (baseline_dir / "iocs.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows), encoding="utf-8"
    )
    import_baseline(baseline_dir, allow_unsigned=True)
    assert len(active_iocs(source="expiring-feed")) == 1
    assert active_iocs(source="expiring-feed")[0].value == "new.example"
    assert len(active_iocs(source="expiring-feed", expired=True)) == 2


def test_expired_matches_marked_expired(baseline_dir, isolated_db):
    manifest = json.loads((baseline_dir / "manifest.json").read_text())
    manifest["source"] = "expiring-feed"
    (baseline_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    rows = [
        {"type": "package", "value": "old-pkg", "source": "expiring-feed",
         "expires_at": yesterday},
    ]
    (baseline_dir / "iocs.jsonl").write_text(
        json.dumps(rows[0]), encoding="utf-8"
    )
    import_baseline(baseline_dir, allow_unsigned=True)
    hits = match_package("old-pkg")
    assert len(hits) == 1
    assert hits[0].expired is True


def test_analysis_integration_scan_diff(baseline_dir, isolated_db, monkeypatch):
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    import_baseline(baseline_dir, allow_unsigned=True)
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
        "-source=('https://example.org/x.tar.gz')\n"
        "+source=('https://malware.example/x.tar.gz')\n"
    )
    fact = scan_diff(diff, rules=[], config=load_config(), package_name="demo")
    assert len(fact.ioc_matches) == 1
    assert fact.ioc_matches[0].type == "domain"
    assert fact.ioc_matches[0].value == "malware.example"
    # IOC matches do not affect the score.
    assert not any(e.rule_id == "R106" for e in fact.score_breakdown)


def test_analysis_integration_package_name(baseline_dir, isolated_db, monkeypatch):
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    import_baseline(baseline_dir, allow_unsigned=True)
    diff = "+pkgver=1.0\n"
    fact = scan_diff(diff, rules=[], config=load_config(), package_name="evil-pkg")
    assert len(fact.ioc_matches) == 1
    assert fact.ioc_matches[0].type == "package"


def test_analysis_integration_hash(baseline_dir, isolated_db, monkeypatch):
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    import_baseline(baseline_dir, allow_unsigned=True)
    diff = f"+sha256sums=('{'a' * 64}')\n"
    fact = scan_diff(diff, rules=[], config=load_config(), package_name="demo")
    assert len(fact.ioc_matches) == 1
    assert fact.ioc_matches[0].type == "hash"


def test_analysis_integration_disabled(baseline_dir, isolated_db, monkeypatch):
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    import_baseline(baseline_dir, allow_unsigned=True)
    config = load_config()
    config.setdefault("baselines", {})["ioc"] = {"enabled": False}
    monkeypatch.setattr("trustsight.config.load_config", lambda: config)
    diff = "+source=('https://malware.example/x.tar.gz')\n"
    fact = scan_diff(diff, rules=[], config=config, package_name="demo")
    assert fact.ioc_matches == []


def test_cli_ioc_import(baseline_dir, isolated_db, monkeypatch):
    from typer.testing import CliRunner

    from trustsight.cli.app import app

    runner = CliRunner()
    result = runner.invoke(app, ["ioc", "import", str(baseline_dir), "--allow-unsigned"])
    assert result.exit_code == 0
    # Rich styles the count as its own span, so the literal substring is not
    # in the raw bytes; strip the styling the way the other CLI tests do.
    from trustsight.safe_text import clean

    output = clean(result.output)
    assert "imported 3 IOCs" in output or "Imported 3 IOCs" in output


def test_cli_ioc_list(baseline_dir, isolated_db, monkeypatch):
    from typer.testing import CliRunner

    from trustsight.cli.app import app

    import_baseline(baseline_dir, allow_unsigned=True)
    runner = CliRunner()
    result = runner.invoke(app, ["ioc", "list", "--source", "test-feed"])
    assert result.exit_code == 0
    assert "malware.example" in result.output


def test_cli_ioc_sources(baseline_dir, isolated_db, monkeypatch):
    from typer.testing import CliRunner

    from trustsight.cli.app import app

    import_baseline(baseline_dir, allow_unsigned=True)
    runner = CliRunner()
    result = runner.invoke(app, ["ioc", "sources"])
    assert result.exit_code == 0
    assert "test-feed" in result.output


# --- edge cases -----------------------------------------------------------


def _write_baseline(tmp_path: Path, iocs: list[dict], source: str = "edge-feed") -> Path:
    base = tmp_path / f"baseline-{source}"
    base.mkdir()
    (base / "manifest.json").write_text(json.dumps({
        "version": 1, "source": source, "created_at": _now_iso(),
        "expires_at": "", "signature": "", "public_key": "",
    }))
    (base / "iocs.jsonl").write_text("\n".join(json.dumps(r) for r in iocs))
    return base


def test_domain_matches_across_punycode_and_unicode(tmp_path, isolated_db):
    """An IDN indicator matches whether written as unicode or as xn-- form.

    A homograph campaign registers ``xn--80ak6aa92e.com``; the PKGBUILD may
    write either spelling, and IDNA normalization must collapse both to one
    stored value or the indicator is trivially bypassed by choosing the other.
    """
    base = _write_baseline(tmp_path, [
        {"type": "domain", "value": "xn--80ak6aa92e.com", "source": "edge-feed"},
    ])
    import_baseline(base, allow_unsigned=True)
    # unicode spelling of the same registered domain
    assert match_domain("аррӏе.com")  # аррӏе.com
    assert match_domain("xn--80ak6aa92e.com")


def test_subdomain_matches_registered_domain_end_to_end(tmp_path, isolated_db):
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    base = _write_baseline(tmp_path, [
        {"type": "domain", "value": "evil-cdn.xyz", "source": "edge-feed"},
    ])
    import_baseline(base, allow_unsigned=True)
    diff = "+source=('https://downloads.evil-cdn.xyz/p.tar.gz')\n"
    fact = scan_diff(diff, rules=[], config=load_config(), package_name="demo")
    assert [m.value for m in fact.ioc_matches] == ["evil-cdn.xyz"]
    assert fact.ioc_matches[0].source == "edge-feed"


def test_uppercase_hash_in_pkgbuild_matches_lowercase_ioc(tmp_path, isolated_db):
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    digest = "b" * 64
    base = _write_baseline(tmp_path, [
        {"type": "hash", "value": digest, "source": "edge-feed"},
    ])
    import_baseline(base, allow_unsigned=True)
    diff = f"+sha256sums=('{digest.upper()}')\n"
    fact = scan_diff(diff, rules=[], config=load_config(), package_name="demo")
    assert [m.type for m in fact.ioc_matches] == ["hash"]


def test_an_ioc_match_never_changes_the_score(tmp_path, isolated_db, monkeypatch):
    """B1: the same PKGBUILD scores identically with or without an IOC hit."""
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    diff = "+source=('https://malware.example/x.tar.gz')\n"
    cfg = load_config()
    cfg.setdefault("baselines", {})["ioc"] = {"enabled": False}
    monkeypatch.setattr("trustsight.config.load_config", lambda: cfg)
    before = scan_diff(diff, rules=[], config=cfg, package_name="demo").final_score

    base = _write_baseline(tmp_path, [
        {"type": "domain", "value": "malware.example", "source": "edge-feed"},
    ])
    import_baseline(base, allow_unsigned=True)
    cfg["baselines"]["ioc"] = {"enabled": True, "sources": []}
    matched = scan_diff(diff, rules=[], config=cfg, package_name="demo")
    assert matched.ioc_matches, "the known-bad domain should have matched"
    assert matched.final_score == before
    assert not any("ioc" in (e.rule_id or "").lower() for e in matched.score_breakdown)


def test_malformed_baseline_is_rejected(tmp_path, isolated_db):
    base = tmp_path / "bad"
    base.mkdir()
    (base / "manifest.json").write_text("{ not json")
    (base / "iocs.jsonl").write_text("")
    with pytest.raises(MalformedBaselineError):
        import_baseline(base, allow_unsigned=True)


def test_missing_baseline_files_are_rejected(tmp_path, isolated_db):
    base = tmp_path / "empty"
    base.mkdir()
    with pytest.raises(FileNotFoundError):
        import_baseline(base, allow_unsigned=True)


def test_cli_ioc_export_emits_the_merged_view(baseline_dir, isolated_db):
    from typer.testing import CliRunner

    from trustsight.cli.app import app

    import_baseline(baseline_dir, allow_unsigned=True)
    result = CliRunner().invoke(app, ["ioc", "export", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    values = {row["value"] for row in payload}
    assert "malware.example" in values
    assert all(row.get("source") for row in payload), "every exported IOC names its source"


# --- scripts/build_ioc_baseline.py: signed build round-trips through import ---


def _build_script():
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "build_ioc_baseline", root / "scripts" / "build_ioc_baseline.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_ioc_baseline_signed_round_trips(tmp_path, isolated_db):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    bib = _build_script()
    key_path = tmp_path / "k.raw"
    key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())

    rows = [
        {"type": "domain", "value": "evil.example", "confidence": "confirmed",
         "provenance": "advisory-1", "campaign": "inc-1"},
        {"type": "hash", "value": "b" * 64, "campaign": "inc-1"},
    ]
    entries = bib._normalise_entries(rows, "curator-x")
    out = tmp_path / "baseline"
    res = bib.build(entries, "curator-x", out, "inc-1", 30, key_path)
    assert res["signed"] is True

    # The real importer verifies the signature (no allow_unsigned).
    result = import_baseline(out, allow_unsigned=False)
    assert result["verified"] is True
    assert result["entries_imported"] == 2
    assert match_domain("evil.example")


def test_build_ioc_baseline_unsigned_needs_allow_unsigned(tmp_path, isolated_db):
    bib = _build_script()
    entries = bib._normalise_entries(
        [{"type": "package", "value": "bad-pkg"}], "curator-x")
    out = tmp_path / "unsigned"
    res = bib.build(entries, "curator-x", out, None, 30, None)
    assert res["signed"] is False
    with pytest.raises(UnsignedBaselineError):
        import_baseline(out, allow_unsigned=False)
    assert import_baseline(out, allow_unsigned=True)["entries_imported"] == 1


def test_build_ioc_baseline_rejects_a_bad_indicator(tmp_path):
    bib = _build_script()
    with pytest.raises(ValueError):
        bib._normalise_entries([{"type": "hash", "value": "not-a-digest"}], "c")
    with pytest.raises(ValueError):
        bib._normalise_entries([{"type": "carrier-pigeon", "value": "x"}], "c")
