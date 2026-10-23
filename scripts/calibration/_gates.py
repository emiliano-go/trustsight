"""Extracted from calibration_gates.py: _gates."""

import json
from collections import Counter
from pathlib import Path
from trustsight.analysis import scan_diff
from trustsight.config import ensure_default_configs, load_config
from trustsight.rules import (
    load_rules,
)
from scripts.calibration._core import CLASS_C_RULES, CLASS_D_RULES, FIXTURES, Gate, MANIFEST_CORPUS, MAX_BENIGN_FIRE_RATE, MAX_SCORE_SIZE_CORRELATION, MAX_X_RATE_DRIFT, X_RULES, _META_ESCALATORS, _NOT_RULES, _S_RULES, _fixture_failures, _gap_detected_by_another_rule, _is_attack_fixture, pearson, percentile, scan_corpus, shipped_config, warm_dependency_corpus
from scripts.calibration._ledger import (DISPOSITION_PLANS, DISPOSITION_STATUSES,
                                         unmet_expectations)

__all__ = ['gate_benign_fire_rates', 'gate_cluster_rate_below_members', 'gate_coverage_expectations', 'gate_d_series_warm', 'gate_h035_position', 'gate_homograph_single_script', 'gate_ioc_exact_match', 'gate_known_gaps_unchanged', 'gate_malicious_recall', 'gate_manifest_benign_corpus', 'gate_meta_escalation_below_cap', 'gate_published_figures', 'gate_s_series_fixture_pairs', 'gate_s_series_last_fired_coverage', 'gate_score_not_size', 'gate_separation', 'gate_stateful_rules_stay_out', 'gate_weight_zero_annotations', 'gate_x_series_rate_stability']

def gate_benign_fire_rates(benign: list[dict]) -> Gate:
    """`benign_fire_rate(rule) < 0.30` for every *scoring* rule.

    Weight-0 findings are exempt by construction, not by indulgence: the
    plan requires neutral facts to be reported (a new dependency, an install
    hook, a version bump), and a fact that moves the score by 0 cannot
    produce a false positive.  ``gate_weight_zero_annotations`` is what
    keeps that exemption honest.
    """
    n = len(benign)
    counts: Counter = Counter()
    for result in benign:
        scoring = {
            e["rule_id"] for e in result["entries"]
            if e["rule_id"] not in _NOT_RULES and e["weight"] != 0
        }
        for rule_id in scoring:
            counts[rule_id] += 1
    rates = {rid: c / n for rid, c in counts.items()} if n else {}
    over = {rid: round(r, 4) for rid, r in rates.items() if r >= MAX_BENIGN_FIRE_RATE}
    worst = max(rates.values(), default=0.0)
    return Gate(
        "benign_fire_rate(rule) < 0.30", not over, round(worst, 4),
        MAX_BENIGN_FIRE_RATE,
        "" if not over else f"over threshold: {over}",
    )

def gate_meta_escalation_below_cap(benign: list[dict]) -> Gate:
    """The M escalation rules pass the cluster-rate gate.

    M002/M003 move the *band* one step, so they are not covered by the
    weight-based fire-rate gate (they are weight 0).  The constitutional rule
    - a composition rule passes the cluster-rate gate before its threshold
    ships - is enforced here instead: each escalation rule's benign-corpus
    rate stays under ``MAX_BENIGN_FIRE_RATE``, the same cap every scoring
    rule obeys.  A breach means the escalation over-fires on benign diffs and
    must be re-tuned or reported-only again.
    """
    n = len(benign)
    rates = {}
    for rule_id in _META_ESCALATORS:
        hits = sum(
            1 for row in benign
            if any(e["rule_id"] == rule_id for e in row["entries"])
        )
        rates[rule_id] = round(hits / n, 4) if n else 0.0
    over = {rid: r for rid, r in rates.items() if r >= MAX_BENIGN_FIRE_RATE}
    return Gate(
        "M escalation stays below the benign cap", not over, rates,
        MAX_BENIGN_FIRE_RATE,
        "" if not over else f"over threshold: {over}",
    )

def gate_separation(benign: list[dict], malicious: list[dict]) -> Gate:
    """`benign_p95 < CRITICAL_p5` - the two populations must not overlap."""
    benign_p95 = percentile([r["score"] for r in benign], 0.95)
    critical = [r["score"] for r in malicious if _is_attack_fixture(r)]
    critical_p5 = percentile(critical, 0.05)
    return Gate(
        "benign_p95 < malicious_p5", benign_p95 < critical_p5,
        {"benign_p95": benign_p95, "malicious_p5": critical_p5}, "strict <",
        "" if benign_p95 < critical_p5 else "score populations overlap",
    )

def gate_published_figures(benign: list[dict], malicious: list[dict]) -> Gate:
    """The published distribution equals the one this scan measures.

    The docs and the site quote these figures, so a scoring change that
    moves the distribution has to move them in the same commit.  The table
    is not a threshold the gate sets: it is the published record, and this
    gate is what keeps the record from outliving the measurement.
    """
    from trustsight.scoring import FLAG_THRESHOLD

    published = json.loads(
        (FIXTURES / "published-figures.json").read_text()
    )["calibration"]
    n = len(benign)
    scores = sorted(r["score"] for r in benign)
    benign_p95 = percentile(scores, 0.95)
    critical = sorted(r["score"] for r in malicious if _is_attack_fixture(r))
    malicious_p5 = percentile(critical, 0.05)
    measured = {
        "corpus_diffs": n,
        "benign_zero_rate_pct": round(
            sum(1 for s in scores if s == 0) / n * 100, 1),
        "benign_p95": benign_p95,
        "malicious_p5": malicious_p5,
        "malicious_minimum": critical[0] if critical else 0,
        "benign_above_threshold_pct": round(
            sum(1 for s in scores if s > FLAG_THRESHOLD) / n * 100, 1),
        "threshold_percentile": round(
            sum(1 for s in scores if s <= FLAG_THRESHOLD) / n * 100, 1),
        "separation_margin": malicious_p5 - benign_p95,
        "ruleset_trigger_rate_pct": round(
            sum(1 for r in benign
                if any(e["severity"] != "INFO" for e in r["entries"])) / n * 100,
            1,
        ),
    }
    mismatch = {
        key: {"measured": measured[key], "published": published.get(key)}
        for key in measured
        if key in published and measured[key] != published[key]
    }
    return Gate(
        "published figures match the measurement",
        not mismatch, measured,
        {key: published.get(key) for key in measured},
        "" if not mismatch else (
            "update docs and tests/fixtures/published-figures.json: "
            f"{mismatch}"
        ),
    )

def gate_score_not_size(benign: list[dict]) -> Gate:
    """`|pearson(score, diff_lines)| < 0.30` - a big diff is not a bad one."""
    r = pearson([x["score"] for x in benign], [x["lines"] for x in benign])
    return Gate(
        "|pearson(score, diff_lines)| < 0.30", abs(r) < MAX_SCORE_SIZE_CORRELATION,
        round(r, 4), MAX_SCORE_SIZE_CORRELATION,
        "" if abs(r) < MAX_SCORE_SIZE_CORRELATION else "score tracks diff size",
    )

def gate_weight_zero_annotations(benign: list[dict]) -> Gate:
    """Weight-0 rules move the score by exactly 0.

    Annotations (H040/H043/H050/H057/H060/H061 and every INFO finding) exist
    to say *what happened*, never to add to the number.  A severity that
    quietly acquires weight would double-count evidence another rule already
    scored.
    """
    offenders = {
        (e["rule_id"], e["weight"])
        for r in benign for e in r["entries"]
        if e["severity"] == "INFO" and e["weight"] != 0
        and e["rule_id"] not in _NOT_RULES  # bucket/novelty/evidence modifiers
    }
    return Gate(
        "weight-0 rules score exactly 0", not offenders,
        sorted(offenders), 0,
        "" if not offenders else f"INFO findings carrying weight: {sorted(offenders)}",
    )

def gate_h035_position(benign: list[dict]) -> Gate:
    """`H035.fire_rate(benign, position=build|prepare) == 0`."""
    hits = [
        f"{r['package']}:{e['params'].get('position')}"
        for r in benign for e in r["entries"]
        if e["rule_id"] == "H035"
        and e["params"].get("position") in ("build", "prepare")
    ]
    return Gate(
        "H035 never fires in build()/prepare()", not hits, len(hits), 0,
        "" if not hits else f"position-scoping broken: {hits[:5]}",
    )

def gate_stateful_rules_stay_out(benign: list[dict]) -> Gate:
    """Class C/D rules must not fire without their state.

    The stateless diff path has no property history and no corpus cycle, so
    a Class C or D rule appearing here is the cold-start gate failing:
    `fire_rate(cold_db) == 0` and `fire_rate(no_baseline) == 0`.
    """
    fired = {
        e["rule_id"] for r in benign for e in r["entries"]
        if e["rule_id"] in CLASS_C_RULES or e["rule_id"] in CLASS_D_RULES
    }
    return Gate(
        "Class C/D silent without state", not fired, sorted(fired), 0,
        "" if not fired else f"stateful rules fired on a stateless scan: {sorted(fired)}",
    )

def gate_ioc_exact_match(benign: list[dict]) -> Gate:
    """Class E: H056 exact-match only.

    Two halves: the shipped list fires on nothing (it is empty, and an
    install must not invent indicators), and a populated list of plausible
    indicators still fires on nothing - equality never drifts into
    resemblance.
    """
    from trustsight.analysis.ioc import _ioc_findings
    from trustsight.iocs import load_indicators

    shipped_hits = sum(
        1 for r in benign for e in r["entries"] if e["rule_id"] == "H056"
    )

    probe = load_indicators({
        "meta": {"version": 0},
        "entries": [
            {"type": "domain", "value": "malware.example", "confidence": "confirmed"},
            {"type": "package", "value": "evil-pkg", "confidence": "confirmed"},
            {"type": "hash", "value": "a" * 64, "confidence": "confirmed"},
        ],
    })
    probe_hits = 0
    for result in benign:
        text = result["path"].read_text(errors="replace")
        found: list = []
        _ioc_findings(
            text, result["package"], {},
            lambda *a, **k: found.append(a), indicators=probe,
        )
        probe_hits += len(found)

    total = shipped_hits + probe_hits
    return Gate(
        "H056 exact-match only", total == 0,
        {"shipped": shipped_hits, "synthetic": probe_hits}, 0,
        "" if total == 0 else "an indicator matched something it does not equal",
    )

def gate_homograph_single_script() -> Gate:
    """`R013b` must not fire on single-script non-ASCII domains.

    A Greek or Cyrillic domain is not an attack on a Latin one; only script
    *mixing* plus confusability with a configured target is.
    """
    from trustsight.buckets import has_homograph

    single_script = [
        "https://παράδειγμα.gr/x.tar.gz",
        "https://пример.рф/x.tar.gz",
        "https://例え.jp/x.tar.gz",
    ]
    fired = [url for url in single_script if has_homograph(url)]
    return Gate(
        "R013b silent on single-script IDNs", not fired, len(fired), 0,
        "" if not fired else f"fired on {fired}",
    )

def gate_manifest_benign_corpus() -> Gate:
    """The U-series' scored rules stay silent on benign manifest edits.

    The locked AUR corpus contains no dependency manifests, so the scored
    U003/U004 would otherwise never be measured against benign input.
    This gate scans a curated manifest corpus through the real ruleset and
    requires the two scored rules to stay at zero, while at least one
    weight-0 ledger rule fires - a corpus that exercises nothing would make
    the gate vacuous.
    """
    name = "manifest corpus: scored U-rules silent, ledger exercised"
    if not MANIFEST_CORPUS.exists():
        return Gate(name, False, 0, 0, "manifest corpus missing")
    rows = scan_corpus(MANIFEST_CORPUS)
    fired: Counter = Counter()
    for row in rows:
        for entry in row["entries"]:
            fired[entry["rule_id"]] += 1
    problems: list[str] = []
    for rule_id in ("U003", "U004"):
        if fired.get(rule_id, 0):
            problems.append(f"{rule_id} fired on {fired[rule_id]} benign diff(s)")
    if not (fired.get("U002") or fired.get("U006")):
        problems.append("corpus exercised no U ledger rule (vacuous)")
    detail = ("; ".join(problems) or
              f"{len(rows)} diffs; U002={fired.get('U002', 0)} "
              f"U006={fired.get('U006', 0)}")
    return Gate(name, not problems, len(rows), 0, detail)

def gate_malicious_recall(malicious: list[dict]) -> Gate:
    """Every labelled fixture still detects what it is labelled for."""
    failures: list[str] = []
    for result in malicious:
        if result["expected"].get("known_gap"):
            continue
        failures.extend(_fixture_failures(result))
    return Gate(
        "labelled attacks still detected", not failures, len(failures), 0,
        "" if not failures else "; ".join(failures[:8]),
    )

def gate_known_gaps_unchanged(malicious: list[dict]) -> Gate:
    """A fixture marked as an uncovered gap must still be uncovered.

    Recording a gap is honest; leaving the record stale is not.  When a new
    rule closes one, this gate fails so the label is removed rather than
    quietly keeping a passing fixture filed under "we do not detect this".
    A gap closed by a *different* rule than the one filed is reported the
    same way: the shape is covered, and the fixture names the wrong rule.
    """
    closed = [
        result["name"] for result in malicious
        if result["expected"].get("known_gap") and not _fixture_failures(result)
    ]
    other_rule = [
        f"{result['name']} ({', '.join(_gap_detected_by_another_rule(result))})"
        for result in malicious
        if _gap_detected_by_another_rule(result)
    ]
    total = sum(1 for r in malicious if r["expected"].get("known_gap"))
    problems = closed + other_rule
    return Gate(
        "known gaps still open (relabel if closed)", not problems,
        {
            "open": total - len(closed) - len(other_rule),
            "newly_covered": closed,
            "detected_by_another_rule": other_rule,
        },
        0,
        "" if not problems else f"now detected, drop known_gap: {problems}",
    )

def gate_s_series_fixture_pairs(benign: list[dict], malicious: list[dict]) -> Gate:
    """Every S rule has a firing payload and a silent lookalike.

    The near-miss is the rule: `rm -rf "$srcdir"` for S002, a file target
    for S003, the package's own service for S006.  A rule with no lookalike
    is one edit away from flagging the ordinary shape, and a rule with no
    payload fixture can stop firing without a test noticing.  The family's
    zero-fire claim on the locked corpus is asserted here too, on whatever
    benign rows the caller scanned.
    """
    lookalikes = [r for r in malicious if "lookalike" in r["name"]]
    payload_rules = {
        rid for r in malicious if "lookalike" not in r["name"]
        for rid in r["fired"] if rid in _S_RULES
    }
    lookalike_rules = sorted({
        rid for r in lookalikes for rid in r["scored"] if rid in _S_RULES
    })
    corpus_fires = sorted({
        e["rule_id"] for r in benign for e in r["entries"]
        if e["rule_id"] in _S_RULES
    })
    problems = {
        "payload_without_fixture": [
            rid for rid in _S_RULES if rid not in payload_rules],
        "rule_without_lookalike": [
            rid for rid in _S_RULES
            if not any(r["name"].startswith(rid) for r in lookalikes)],
        "lookalike_scored": lookalike_rules,
        "benign_corpus_fires": corpus_fires,
    }
    problems = {k: v for k, v in problems.items() if v}
    return Gate(
        "S-series fixture pairs (payload fires, lookalike silent)",
        not problems,
        problems if problems else f"{len(_S_RULES)} pairs",
        0,
        "" if not problems else f"S-series pair problems: {problems}",
    )

def gate_s_series_last_fired_coverage(
        benign: list[dict], malicious: list[dict]) -> Gate:
    """S1: where each S rule last fired, and what never has.

    S rules have near-zero corpus rates, so "no S finding" is weak evidence.
    The ledger names, per rule, its corpus count and the fixtures it fired
    in; a rule that has never fired outside its own paired fixture is
    labelled, so the report carries honest confidence levels rather than
    silence.  Reporting only - it never fails.
    """
    ledger: dict[str, dict] = {}
    never: list[str] = []
    for rule_id in sorted(_S_RULES):
        corpus = sum(
            1 for row in benign
            if any(e["rule_id"] == rule_id for e in row["entries"])
        )
        own = sorted({
            r["name"] for r in malicious
            if r["name"].startswith(rule_id) and rule_id in r["fired"]
        })
        outside = sorted({
            f"{r['group']}/{r['name']}" for r in malicious
            if rule_id in r["fired"] and not r["name"].startswith(rule_id)
        })
        fired_outside = corpus > 0 or bool(outside)
        if not fired_outside:
            never.append(rule_id)
        ledger[rule_id] = {
            "corpus": corpus, "own_fixture": own, "outside_fixture": outside,
        }
    return Gate(
        "S-series last-fired coverage", True, ledger, 0,
        ("never fired outside its own fixture: " + ", ".join(never))
        if never else "every S rule has fired outside its own fixture",
    )


def gate_coverage_ledger_complete(ledger_path: Path | None = None) -> Gate:
    """Every catalog id has exactly one coverage state and a reason.

    The ledger is the expansion's control panel.  A rule missing from it, a
    state outside the closed set, or a non-measured rule with no reason is a
    silent hole in the claim that the corpus covers the catalog.
    """
    from trustsight.contract import pseudo_rule_ids, rule_ids

    name = "coverage ledger is complete"
    path = ledger_path or FIXTURES / "coverage-ledger.json"
    if not path.exists():
        return Gate(name, False, 0, 0, "coverage-ledger.json missing")
    doc = json.loads(path.read_text())
    rows = doc.get("rules") or {}
    expected = set(rule_ids()) | set(pseudo_rule_ids())
    states = {"measured", "zero_fire", "cold_only", "adversarial_only"}
    problems: list[str] = []
    missing = sorted(expected - set(rows))
    extra = sorted(set(rows) - expected)
    if missing:
        problems.append(f"missing ids: {missing[:8]}")
    if extra:
        problems.append(f"unknown ids: {extra[:8]}")
    bad_state = sorted(rid for rid, row in rows.items()
                       if row.get("state") not in states)
    if bad_state:
        problems.append(f"bad state: {bad_state[:8]}")
    no_reason = sorted(rid for rid, row in rows.items()
                       if row.get("state") != "measured" and not row.get("reason"))
    if no_reason:
        problems.append(f"no reason: {no_reason[:8]}")
    measured_no_source = sorted(rid for rid, row in rows.items()
                                if row.get("state") == "measured" and not row.get("sources"))
    if measured_no_source:
        problems.append(f"measured without source: {measured_no_source[:8]}")
    return Gate(name, not problems, {"rules": len(rows), "expected": len(expected)},
                0, "; ".join(problems))


def gate_coverage_expectations(ledger_path: Path | None = None) -> Gate:
    """Every unmet expected rule is a reviewed, dispositioned gap.

    This is a ratchet, not a demand that every rule fire on benign data.  An
    expected rule must either be exercised by a benign source or carry a
    ``deferred`` disposition naming the plan that will exercise it.  A
    ``resolved`` disposition whose plan says the rule is attack-only or not
    measurable must not still be declared as a benign expectation.
    """
    name = "coverage expectations are met or dispositioned"
    path = ledger_path or FIXTURES / "coverage-ledger.json"
    if not path.exists():
        return Gate(name, False, 0, 0, f"{path.name} missing")
    doc = json.loads(path.read_text())
    rows = doc.get("rules") or {}
    expected = {
        rid: row.get("expected_strata") or []
        for rid, row in rows.items() if row.get("expected_strata")
    }
    unmet = unmet_expectations(doc, expected)
    missing: list[str] = []
    bad_status: list[str] = []
    bad_plan: list[str] = []
    stale_add: list[str] = []
    stale_expectation: list[str] = []
    no_expectation_plans = {
        "attack_only", "not_measurable", "expectation_wrong",
        "weight_zero", "unverifiable", "pseudo", "known_false_positive",
    }
    for rid in sorted(unmet):
        disposition = rows.get(rid, {}).get("disposition")
        if not isinstance(disposition, dict):
            missing.append(rid)
            continue
        status = disposition.get("status")
        plan = disposition.get("plan")
        if status not in DISPOSITION_STATUSES:
            bad_status.append(f"{rid}:{status}")
        if plan not in DISPOSITION_PLANS:
            bad_plan.append(f"{rid}:{plan}")
    for rid, row in sorted(rows.items()):
        disposition = row.get("disposition")
        if not isinstance(disposition, dict):
            continue
        status = disposition.get("status")
        plan = disposition.get("plan")
        if plan and str(plan).startswith("add_") and row.get("expected_met"):
            stale_add.append(rid)
        if status == "resolved" and plan in no_expectation_plans and row.get("expected_strata"):
            stale_expectation.append(rid)
    problems: list[str] = []
    if missing:
        problems.append(f"unmet without disposition: {', '.join(missing[:12])}")
    if bad_status:
        problems.append(f"bad status: {', '.join(bad_status[:8])}")
    if bad_plan:
        problems.append(f"bad plan: {', '.join(bad_plan[:8])}")
    if stale_add:
        problems.append(f"stale add_* disposition: {', '.join(stale_add[:8])}")
    if stale_expectation:
        problems.append(
            f"resolved non-benign plan still expected: {', '.join(stale_expectation[:8])}")
    return Gate(
        name, not problems,
        {"expectations": len(expected), "unmet": len(unmet),
         "missing_disposition": len(missing), "stale_disposition": len(stale_add),
         "stale_expectation": len(stale_expectation)},
        0, "; ".join(problems))


def gate_artifact_corpus() -> Gate:
    """The A-series has shape coverage and a clean negative control.

    Diffs never touch artifacts, so the A rules were exercised only by unit
    tests.  The committed manifest corpus gives every stratum a representative
    artifact; the font manifest is the negative control and must trip nothing.
    """
    from trustsight.analysis.artifact import inspect_manifest

    name = "artifact corpus: A-series coverage, negative control clean"
    root = FIXTURES / "artifact-corpus"
    expected_path = root / "expected.json"
    if not expected_path.exists():
        return Gate(name, False, 0, 0, "artifact corpus missing")
    expected = json.loads(expected_path.read_text())
    problems: list[str] = []
    fired: set[str] = set()
    for filename, record in sorted(expected.items()):
        path = root / filename
        if not path.exists():
            problems.append(f"{filename}: missing")
            continue
        doc = json.loads(path.read_text())
        findings = inspect_manifest(doc.get("manifest") or [],
                                    doc.get("declared") or {})
        ids = {f["rule_id"] for f in findings}
        fired |= ids
        want = set(record.get("expected") or ())
        if ids != want:
            problems.append(f"{filename}: fired {sorted(ids)}, expected {sorted(want)}")
    if not fired:
        problems.append("corpus exercises no A rule (vacuous)")
    return Gate(name, not problems, sorted(fired), "A001-A008",
                "; ".join(problems))

def gate_x_series_rate_stability(benign: list[dict]) -> Gate:
    """Every X rule's benign rate matches the committed baseline.

    ``baseline.json`` records all 31 X rates, including the silent zeros.
    The X series is the composition surface - these rules fire on the
    co-occurrence of other findings - so a rule change can shrink one of
    them without moving any published figure.  A drift past
    ``MAX_X_RATE_DRIFT`` fails here; the fix is a changelog adjudication
    plus a deliberate ``scripts/rebaseline.py`` run, never a quiet edit.
    """
    doc = json.loads((FIXTURES / "baseline.json").read_text())
    recorded = doc.get("x_rates")
    if not isinstance(recorded, dict):
        return Gate(
            "X-series rates match the baseline", False, {"x_rates": "absent"},
            MAX_X_RATE_DRIFT,
            "baseline.json records no x_rates; run scripts/rebaseline.py",
        )
    n = len(benign)
    counts: Counter = Counter()
    for result in benign:
        for entry in result["entries"]:
            if entry["rule_id"] in X_RULES:
                counts[entry["rule_id"]] += 1
    measured = {rid: (counts[rid] / n if n else 0.0) for rid in X_RULES}
    drift = {
        rid: {"measured": round(measured[rid], 4),
              "baseline": round(recorded.get(rid, 0.0), 4)}
        for rid in X_RULES
        if abs(measured[rid] - recorded.get(rid, 0.0)) > MAX_X_RATE_DRIFT
    }
    return Gate(
        "X-series rates match the baseline", not drift,
        {"rules": len(X_RULES), "drifted": drift}, MAX_X_RATE_DRIFT,
        "" if not drift else (
            f"X-rate drift beyond {MAX_X_RATE_DRIFT}: {drift}"),
    )

def gate_cluster_rate_below_members(benign: list[dict]) -> Gate:
    """H098 fires only with its members, and never above their union.

    The cluster is the one weight-bearing composition rule, so a diff that
    carries it must carry at least two of the member findings it is
    composed from - that is what keeps the wiring honest - and the
    cluster's corpus rate cannot exceed the sum of the member rates.  A
    bound "below every single member" is *not* the invariant: a 2-of-9
    cluster can fire on pairs, so one silent member would fail it.
    """
    from trustsight.analysis.composition import _NAMING_CLUSTER_MEMBERS

    members = frozenset(_NAMING_CLUSTER_MEMBERS)
    n = len(benign)
    cluster_rows = [
        r for r in benign
        if any(e["rule_id"] == "H098" for e in r["entries"])
    ]
    under = [
        f"{row['package']}: H098 with members "
        f"{sorted({e['rule_id'] for e in row['entries']} & members)}"
        for row in cluster_rows
        if len({e["rule_id"] for e in row["entries"]} & members) < 2
    ]
    member_rates = {
        rid: (sum(1 for r in benign
                  if any(e["rule_id"] == rid for e in r["entries"])) / n
              if n else 0.0)
        for rid in sorted(members)
    }
    cluster_rate = len(cluster_rows) / n if n else 0.0
    union = sum(member_rates.values())
    problems = {}
    if under:
        problems["fired_without_members"] = under
    if cluster_rate > union + 1e-9:
        problems["cluster_rate"] = {
            "measured": round(cluster_rate, 5), "union": round(union, 5)}
    return Gate(
        "H098 cluster stays below its members", not problems,
        {"cluster_rate": round(cluster_rate, 5),
         "member_rates": {k: round(v, 5)
                          for k, v in member_rates.items() if v}},
        0,
        "" if not problems else f"H098 problems: {problems}",
    )

def gate_d_series_warm(
    warm_root: Path = FIXTURES / "malicious" / "warm",
) -> Gate:
    """The corpus-dependent rules fire warm and stay silent cold.

    D001/D002 read ``dependency_names``; the main gates run cold by design,
    so the evasion fixtures that add a novel dependency can only be gated
    under a seeded corpus.  This gate scans the warm fixtures twice: once
    with the committed corpus loaded, where the labels must pass, and once
    cold, where D001/D002 must not fire.  The pair is the property the
    cold-start guard exists for.
    """
    expected = json.loads((warm_root / "expected.json").read_text())
    fixtures = sorted(warm_root.glob("*.diff"))
    failures: list[str] = []
    warm_fired: dict[str, list[str]] = {}

    with warm_dependency_corpus():
        ensure_default_configs()
        config = load_config()
        rules = load_rules()
        for path in fixtures:
            fact = scan_diff(path.read_text(errors="replace"), rules=rules,
                             config=config, package_name=path.stem, seen_urls={})
            fired = {e.rule_id for e in fact.score_breakdown}
            scored = {
                e.rule_id for e in fact.score_breakdown
                if e.weight != 0 or e.severity == "FATAL"
            }
            warm_fired[path.name] = sorted(fired)
            failures.extend(_fixture_failures({
                "name": path.name,
                "score": fact.final_score,
                "fired": fired,
                "scored": scored,
                "expected": expected.get(path.name, {}),
            }))

    with shipped_config():
        ensure_default_configs()
        config = load_config()
        rules = load_rules()
        for path in fixtures:
            fact = scan_diff(path.read_text(errors="replace"), rules=rules,
                             config=config, package_name=path.stem, seen_urls={})
            cold = {"D001", "D002"} & {e.rule_id for e in fact.score_breakdown}
            if cold:
                failures.append(f"{path.name}: {sorted(cold)} fired cold")

    return Gate(
        "D-series warm fixtures fire warm and stay silent cold",
        not failures,
        {"warm": warm_fired, "failures": failures},
        0,
        "" if not failures else "; ".join(failures[:6]),
    )
