"""Phase 8 - the §10 calibration gates, enforced.

`rebaseline.py` records what the fire rates *are*; this script decides
whether they are *allowed*.  Every gate here is one line of the plan's §10
list turned into a number and a comparison, so a rule that drifts into
noise, a weight-0 annotation that quietly starts scoring, or a detection
that stops detecting fails the build instead of being noticed a month later
in a drift issue.

Usage:
    python scripts/calibration_gates.py
    python scripts/calibration_gates.py --sample 4 --json gates.json

Exit code is 1 if any gate fails, 0 otherwise.  `--sample N` scans every
Nth benign diff, which the test suite uses to keep a full corpus replay out
of the default run; the CI job runs it whole.
"""

import argparse
import json
import math
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path

import trustsight.config as config_module
import trustsight.db as db_module
from trustsight.analysis import scan_diff
from trustsight.config import ensure_default_configs, load_config
from trustsight.rules import load_rules

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

# Score-breakdown entries that are not rules: bucket, novelty and evidence
# modifiers.  They have their own baselines and no fire-rate gate.
_NOT_RULES = frozenset({
    "SOURCE_BUCKET", "NOVELTY", "VERIFICATION", "PINNING", "COVERAGE",
}) | frozenset(f"P{n:03d}" for n in range(1, 100))

# §10 thresholds.
MAX_BENIGN_FIRE_RATE = 0.30
MAX_SCORE_SIZE_CORRELATION = 0.30
# A fixture claiming this score or more is claiming a whole attack, not one
# signal: 40 is the floor of the High band (scoring.risk_level).
CRITICAL_MIN_SCORE = 40

# Rules that may never fire in the stateless diff path: they need corpus or
# longitudinal state, and firing here would mean firing on a cold database.
CLASS_C_RULES = frozenset({"R083", "R094", "R095", "R096", "R097", "R098", "R102"})
CLASS_D_RULES = frozenset({
    "R090", "R092", "R093", "R100", "R101", "R105", "R107", "R108", "R110",
    "R111", "R112", "R125", "R126",
})


@contextmanager
def shipped_config():
    """Run the gates against the *shipped* config, never the machine's.

    ``rules.toml`` and friends are written once, at install time, and are
    never rewritten - so a developer box carries whatever the defaults were
    on the day it was first run.  Measuring against that file makes the
    numbers unreproducible and can hide a rule that has since been removed
    from the shipped set (or resurrect one that has).  The database is
    isolated for the same reason: novelty and maturity must start cold.
    """
    tmp = Path(tempfile.mkdtemp(prefix="trustsight-gates-"))
    saved_config, saved_data = config_module.CONFIG_DIR, db_module.DATA_DIR
    config_module.CONFIG_DIR = tmp / "config"
    db_module.DATA_DIR = tmp / "data"
    db_module.DATA_DIR.mkdir(parents=True, exist_ok=True)
    config_module._toml_cache.clear()
    try:
        ensure_default_configs()
        yield tmp
    finally:
        config_module.CONFIG_DIR = saved_config
        db_module.DATA_DIR = saved_data
        config_module._toml_cache.clear()
        shutil.rmtree(tmp, ignore_errors=True)


class Gate:
    """One §10 gate: a measurement, a threshold, and how it failed."""

    def __init__(self, name: str, passed: bool, measured, threshold, detail: str = ""):
        self.name = name
        self.passed = passed
        self.measured = measured
        self.threshold = threshold
        self.detail = detail

    def as_dict(self) -> dict:
        return {
            "gate": self.name, "passed": self.passed,
            "measured": self.measured, "threshold": self.threshold,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def _diff_line_count(text: str) -> int:
    return sum(
        1 for line in text.splitlines()
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    )


def scan_corpus(corpus: Path, sample: int = 1) -> list[dict]:
    """Scan every (or every *sample*-th) benign diff.

    Novelty is order-dependent, so the replay shares one ``seen_urls`` map
    and walks packages in a stable order - the same shape as
    ``rebaseline.py``.  Sampling keeps that property by thinning whole
    packages' diffs uniformly rather than reordering them.
    """
    ensure_default_configs()
    config = load_config()
    rules = load_rules()

    by_pkg: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(corpus.rglob("*.diff")):
        by_pkg[path.name.split("__")[0]].append(path)

    seen_urls: dict[str, set[str]] = {}
    results: list[dict] = []
    index = 0
    for pkg in sorted(by_pkg):
        for path in sorted(by_pkg[pkg], key=lambda p: p.stem):
            index += 1
            if sample > 1 and index % sample:
                continue
            text = path.read_text(errors="replace")
            fact = scan_diff(text, rules=rules, config=config,
                             package_name=pkg, seen_urls=seen_urls)
            results.append({
                "package": pkg,
                "path": path,
                "score": fact.final_score,
                "lines": _diff_line_count(text),
                "entries": [
                    {"rule_id": e.rule_id, "severity": e.severity,
                     "weight": e.weight, "params": e.params or {}}
                    for e in fact.score_breakdown
                ],
            })
    return results


def scan_malicious(root: Path) -> list[dict]:
    """Scan the labelled malicious fixtures, carrying their expectations."""
    ensure_default_configs()
    config = load_config()
    rules = load_rules()

    results: list[dict] = []
    for group in sorted(p for p in root.iterdir() if p.is_dir()):
        expected_path = group / "expected.json"
        expected = json.loads(expected_path.read_text()) if expected_path.exists() else {}
        for path in sorted(group.glob("*.diff")):
            fact = scan_diff(path.read_text(errors="replace"), rules=rules,
                             config=config, package_name=path.stem, seen_urls={})
            results.append({
                "group": group.name,
                "name": path.name,
                "score": fact.final_score,
                "fired": {e.rule_id for e in fact.score_breakdown},
                # A weight-0 finding is a reported fact, not a flag: R004 on a
                # justified SKIP says "this is a -git package's SKIP", which is
                # exactly what a must_not_fire label means to allow.
                "scored": {
                    e.rule_id for e in fact.score_breakdown
                    if e.weight != 0 or e.severity == "FATAL"
                },
                "expected": expected.get(path.name, {}),
            })
    return results


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile; 0.0 for an empty sample."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, int(math.ceil(q * len(ordered))) - 1))
    return ordered[rank]


def pearson(xs: list[float], ys: list[float]) -> float:
    """Pearson correlation; 0.0 when either series has no variance."""
    n = len(xs)
    if n < 2:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    dx = [x - mean_x for x in xs]
    dy = [y - mean_y for y in ys]
    denom = math.sqrt(sum(d * d for d in dx)) * math.sqrt(sum(d * d for d in dy))
    if denom == 0:
        return 0.0
    return sum(a * b for a, b in zip(dx, dy)) / denom


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


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


def _is_attack_fixture(result: dict) -> bool:
    """True for a fixture that stands for a whole attack.

    Most synthetic fixtures are single-signal probes - "does R004 fire on a
    SKIP" - and a lone MEDIUM signal is *supposed* to score like an ordinary
    suspicious diff.  Including them would measure the unit fixtures, not
    the separation the gate is about.  What counts is the historical corpus
    (real incidents) plus any synthetic fixture whose own label claims a
    High-or-worse outcome.
    """
    if result["group"] == "holdout" or "control" in result["name"]:
        return False
    if result["expected"].get("known_gap"):
        return False
    if result["group"] == "historical":
        return True
    return (result["expected"].get("min_score") or 0) >= CRITICAL_MIN_SCORE


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

    Annotations (R086/R089/R097/R107/R111/R112 and every INFO finding) exist
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


def gate_r081_position(benign: list[dict]) -> Gate:
    """`R081.fire_rate(benign, position=build|prepare) == 0`."""
    hits = [
        f"{r['package']}:{e['params'].get('position')}"
        for r in benign for e in r["entries"]
        if e["rule_id"] == "R081"
        and e["params"].get("position") in ("build", "prepare")
    ]
    return Gate(
        "R081 never fires in build()/prepare()", not hits, len(hits), 0,
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
    """Class E: R106 exact-match only.

    Two halves: the shipped list fires on nothing (it is empty, and an
    install must not invent indicators), and a populated list of plausible
    indicators still fires on nothing - equality never drifts into
    resemblance.
    """
    from trustsight.analysis.ioc import _ioc_findings
    from trustsight.iocs import load_indicators

    shipped_hits = sum(
        1 for r in benign for e in r["entries"] if e["rule_id"] == "R106"
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
        "R106 exact-match only", total == 0,
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


def _fixture_failures(result: dict) -> list[str]:
    expected = result["expected"]
    failures: list[str] = []
    for rule_id in expected.get("must_fire", []):
        if rule_id not in result["fired"]:
            failures.append(f"{result['name']}: {rule_id} did not fire")
    for rule_id in expected.get("must_not_fire", []):
        if rule_id in result["scored"]:
            failures.append(f"{result['name']}: {rule_id} scored")
    low = expected.get("min_score")
    if low is not None and result["score"] < low:
        failures.append(f"{result['name']}: score {result['score']} < {low}")
    high = expected.get("max_score")
    if high is not None and result["score"] > high:
        failures.append(f"{result['name']}: score {result['score']} > {high}")
    return failures


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
    """
    closed = [
        result["name"] for result in malicious
        if result["expected"].get("known_gap") and not _fixture_failures(result)
    ]
    total = sum(1 for r in malicious if r["expected"].get("known_gap"))
    return Gate(
        "known gaps still open (relabel if closed)", not closed,
        {"open": total - len(closed), "newly_covered": closed}, 0,
        "" if not closed else f"now detected, drop known_gap: {closed}",
    )


def run_gates(corpus: Path = FIXTURES / "benign-corpus",
              malicious_root: Path = FIXTURES / "malicious",
              sample: int = 1) -> list[Gate]:
    with shipped_config():
        benign = scan_corpus(corpus, sample=sample)
        malicious = scan_malicious(malicious_root) if malicious_root.exists() else []
        return _evaluate(benign, malicious)


def _evaluate(benign: list[dict], malicious: list[dict]) -> list[Gate]:

    gates = [
        gate_benign_fire_rates(benign),
        gate_score_not_size(benign),
        gate_weight_zero_annotations(benign),
        gate_r081_position(benign),
        gate_stateful_rules_stay_out(benign),
        gate_ioc_exact_match(benign),
        gate_homograph_single_script(),
    ]
    if malicious:
        gates.append(gate_separation(benign, malicious))
        gates.append(gate_malicious_recall(malicious))
        gates.append(gate_known_gaps_unchanged(malicious))
    return gates


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the §10 calibration gates")
    parser.add_argument("--corpus", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--malicious", type=Path, default=FIXTURES / "malicious")
    parser.add_argument("--sample", type=int, default=1,
                        help="Scan every Nth benign diff (default: all)")
    parser.add_argument("--json", type=Path, help="Write the gate results here")
    args = parser.parse_args()

    if not args.corpus.exists():
        print(f"Corpus not found: {args.corpus}", file=sys.stderr)
        print("Reconstruct it with scripts/build_corpus.py --from-manifest",
              file=sys.stderr)
        return 2

    gates = run_gates(args.corpus, args.malicious, sample=args.sample)

    width = max(len(g.name) for g in gates)
    for gate in gates:
        status = "PASS" if gate.passed else "FAIL"
        print(f"{status}  {gate.name:<{width}}  measured={gate.measured}")
        if gate.detail:
            print(f"        {gate.detail}")

    if args.json:
        args.json.write_text(
            json.dumps([g.as_dict() for g in gates], indent=2, default=str) + "\n"
        )

    failed = [g for g in gates if not g.passed]
    print(f"\n{len(gates) - len(failed)}/{len(gates)} gates passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
