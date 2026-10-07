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
import multiprocessing
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import trustsight.config as config_module
import trustsight.db as db_module
from trustsight.analysis import scan_diff
from trustsight.analysis.base import _GLOBAL_URL_KEY
from trustsight.analysis.pipeline import scored_source_urls
from trustsight.config import ensure_default_configs, load_config
from trustsight.novelty import normalize_url
from trustsight.rules import (
    load_rules,
    precompile_patterns,
    precompile_structural_patterns,
    resolve_generated_patterns,
)
from trustsight.sandbox.client import reset_after_fork

FIXTURES = ROOT / "tests" / "fixtures"

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
CLASS_C_RULES = frozenset({"H037", "H047", "H048", "H049", "H050", "H051", "H054"})
CLASS_D_RULES = frozenset({
    "H044", "H045", "H046", "H052", "H053", "H055", "H057", "H058", "H059",
    "H060", "H061", "H073", "H074",
    # H086 needs a recorded prior AUR orphan observation and H088 composes
    # it, so both are stateful and must be silent on the stateless path.
    # H087 is deliberately absent: it reads the diff alone, so it has a real
    # benign fire rate (11.5% on the locked corpus) and belongs to the
    # fire-rate gate rather than this one.
    "H086", "H088",
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

    The host's pacman answer is host state too: with a sync database
    present, ``official_package_names`` makes ``is_established_package``
    fire D004/H064 on benign provides-transitions that a machine without
    pacman (CI, a container) never reports - the benign flag rate measured
    7.9% with pacman and 7.8% without.  The frozen empty answer is the
    cold machine every environment can reproduce.
    """
    tmp = Path(tempfile.mkdtemp(prefix="trustsight-gates-"))
    saved_config, saved_data = config_module.CONFIG_DIR, db_module.DATA_DIR
    saved_official = db_module._official_names
    config_module.CONFIG_DIR = tmp / "config"
    db_module.DATA_DIR = tmp / "data"
    db_module.DATA_DIR.mkdir(parents=True, exist_ok=True)
    # An empty set, not None: None means "never asked" and would re-query
    # pacman; the empty answer is what a machine without pacman gives.
    db_module._official_names = frozenset()
    config_module._toml_cache.clear()
    try:
        ensure_default_configs()
        yield tmp
    finally:
        config_module.CONFIG_DIR = saved_config
        db_module.DATA_DIR = saved_data
        db_module._official_names = saved_official
        config_module._toml_cache.clear()
        shutil.rmtree(tmp, ignore_errors=True)


@contextmanager
def warm_dependency_corpus():
    """The shipped config plus the committed dependency corpus.

    D001/D002 answer from ``dependency_names``, and the main gates run cold
    on purpose: an unseeded install must not make every dependency look
    novel.  This context is the warm half of that pair, seeding a small
    committed corpus so the corpus-dependent rules can be gated without
    moving the cold corpus figures.
    """
    with shipped_config() as tmp:
        from trustsight.db import init_db, record_dependency_names

        init_db()
        names = json.loads(
            (FIXTURES / "dependency-corpus.json").read_text()
        )["names"]
        # Ten observations each, the same warm-up the seeded-DB unit tests
        # use: enough for the typosquat candidate ranking to include them.
        for _ in range(10):
            record_dependency_names(names)
        yield tmp


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


def default_jobs() -> int:
    """The worker count a CLI run uses unless told otherwise."""
    return max(1, min(8, os.cpu_count() or 1))


def _resolve_jobs(jobs: int | None) -> int:
    """One worker unless a caller asks for more.

    Direct library callers (the tests) stay serial; the CLIs pass
    :func:`default_jobs` so a corpus run uses the machine.
    """
    if jobs is None or int(jobs) <= 0:
        return 1
    return max(1, int(jobs))


def _benign_row(
    package: str, path: Path, text: str, fact, include_location: bool
) -> dict:
    entries = []
    for e in fact.score_breakdown:
        entry = {"rule_id": e.rule_id, "severity": e.severity,
                 "weight": e.weight, "params": e.params or {}}
        if include_location:
            entry["file"] = e.file
            entry["line"] = e.line
        entries.append(entry)
    return {
        "package": package,
        "path": path,
        "score": fact.final_score,
        "lines": _diff_line_count(text),
        "entries": entries,
    }


def _ordered_benign_packages(corpus: Path) -> dict[str, list[Path]]:
    by_pkg: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(corpus.rglob("*.diff")):
        by_pkg[path.name.split("__")[0]].append(path)
    return by_pkg


def _scan_corpus_serial(
    corpus: Path, sample: int, config: dict, rules,
    include_location: bool,
) -> list[dict]:
    by_pkg = _ordered_benign_packages(corpus)
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
            results.append(_benign_row(pkg, path, text, fact, include_location))
    return results


def _benign_plan(
    corpus: Path, sample: int, config: dict
) -> list[tuple[str, list[Path], frozenset[str]]]:
    """Per-package diff lists plus each package's exact global-URL prefix.

    Walks the corpus once in the same order and through the same URL path
    ``scan_diff`` uses, so a worker starting at a package sees exactly the
    global novelty a serial run would have by then.  Within a package the
    diffs stay serial in the worker, so per-package novelty is preserved.
    """
    by_pkg = _ordered_benign_packages(corpus)
    plan: list[tuple[str, list[Path], frozenset[str]]] = []
    global_seen: set[str] = set()
    index = 0
    for pkg in sorted(by_pkg):
        selected: list[Path] = []
        additions: list[str] = []
        for path in sorted(by_pkg[pkg], key=lambda p: p.stem):
            index += 1
            if sample > 1 and index % sample:
                continue
            selected.append(path)
            text = path.read_text(errors="replace")
            additions.extend(
                normalize_url(url)
                for url in scored_source_urls(text, config, pkg)
            )
        if selected:
            plan.append((pkg, selected, frozenset(global_seen)))
        global_seen.update(additions)
    return plan


_WORKER_RULES: list[dict] | None = None
_WORKER_CONFIG: dict | None = None
_WORKER_INCLUDE_LOCATION = False


def _init_worker(
    config_dir: str, data_dir: str, rules, config, include_location: bool
) -> None:
    """Install the parent's shipped config and drop inherited state.

    The pool forks, so the parent's rule-safety verdicts and config paths
    are inherited; the database connection and the tokenizer worker pool
    are not safe to share across a fork and are reset here.  The parent's
    sandbox workers are left alone: their pids name live processes in the
    parent's table, and stopping one would kill the parent's pool.
    """
    global _WORKER_RULES, _WORKER_CONFIG, _WORKER_INCLUDE_LOCATION
    config_module.CONFIG_DIR = Path(config_dir)
    config_module._toml_cache.clear()
    db_module.DATA_DIR = Path(data_dir)
    db_module._official_names = frozenset()
    cached = getattr(db_module._local, "cached", None)
    if cached is not None:
        try:
            cached[1].close()
        except Exception:
            pass
        db_module._local.cached = None
    db_module.init_db()
    reset_after_fork()
    _WORKER_RULES = rules
    _WORKER_CONFIG = config
    _WORKER_INCLUDE_LOCATION = include_location


def _precompile_patterns(rules) -> None:
    """Decide pattern safety once, single-threaded, before forking.

    The safety probe is wall-clock; under pool contention a shipped pattern
    can be refused in one worker and accepted in another (B1).  The parent's
    verdict is inherited by each forked worker, so every worker agrees.
    Generated patterns (R013, R047, R048, R152) are filled in first, or the
    placeholder would be vetted and the real pattern re-timed in every
    worker - exactly the R013 refusal this fixes.
    """
    resolve_generated_patterns(rules)
    precompile_patterns(r.get("pattern", "") for r in rules)
    precompile_structural_patterns()


def _scan_package_task(task):
    package, paths, prefix = task
    pkg_seen: set[str] = set()
    global_seen = set(prefix)
    rows = []
    for path_str in paths:
        path = Path(path_str)
        text = path.read_text(errors="replace")
        fact = scan_diff(
            text, rules=_WORKER_RULES, config=_WORKER_CONFIG,
            package_name=package,
            seen_urls={package: pkg_seen, _GLOBAL_URL_KEY: global_seen},
        )
        rows.append(
            _benign_row(package, path, text, fact, _WORKER_INCLUDE_LOCATION)
        )
    return rows


def _scan_corpus_parallel(
    plan, workers: int, rules, config: dict, include_location: bool
) -> list[dict]:
    tasks = [
        (pkg, [str(p) for p in paths], prefix)
        for pkg, paths, prefix in plan
    ]
    context = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(
        max_workers=workers, mp_context=context,
        initializer=_init_worker,
        initargs=(str(config_module.CONFIG_DIR), str(db_module.DATA_DIR),
                  rules, config, include_location),
    ) as pool:
        results: list[dict] = []
        for package_rows in pool.map(_scan_package_task, tasks, chunksize=1):
            results.extend(package_rows)
    return results


def scan_corpus(
    corpus: Path, sample: int = 1, jobs: int | None = None,
    include_location: bool = False,
) -> list[dict]:
    """Scan every (or every *sample*-th) benign diff.

    Novelty is order-dependent, so the replay walks packages in a stable
    order - the same shape as ``rebaseline.py``.  Sampling keeps that
    property by thinning whole packages' diffs uniformly rather than
    reordering them.  ``jobs`` > 1 runs packages in worker processes: each
    package's diffs stay serial inside its worker and the global URL prefix
    is precomputed exactly, so the results are the serial results.
    ``include_location`` adds the finding's file and line to each entry.
    """
    ensure_default_configs()
    config = load_config()
    rules = load_rules()
    workers = _resolve_jobs(jobs)
    if workers <= 1:
        return _scan_corpus_serial(corpus, sample, config, rules, include_location)
    # Decide pattern safety on the idle parent; the forked workers inherit
    # the verdict.  The schema exists before workers open read connections.
    _precompile_patterns(rules)
    db_module.init_db()
    plan = _benign_plan(corpus, sample, config)
    return _scan_corpus_parallel(plan, workers, rules, config, include_location)


def _malicious_row(group: str, path: Path, fact, expected: dict) -> dict:
    return {
        "group": group,
        "name": path.name,
        "score": fact.final_score,
        "fired": {e.rule_id for e in fact.score_breakdown},
        # A weight-0 finding is a reported fact, not a flag: H001 on a
        # justified SKIP says "this is a -git package's SKIP", which is
        # exactly what a must_not_fire label means to allow.
        "scored": {
            e.rule_id for e in fact.score_breakdown
            if e.weight != 0 or e.severity == "FATAL"
        },
        "expected": expected.get(path.name, {}),
    }


def _scan_malicious_task(task):
    group, path_str, expected = task
    path = Path(path_str)
    text = path.read_text(errors="replace")
    fact = scan_diff(text, rules=_WORKER_RULES, config=_WORKER_CONFIG,
                     package_name=path.stem, seen_urls={})
    return _malicious_row(group, path, fact, expected)


def scan_malicious(root: Path, jobs: int | None = None) -> list[dict]:
    """Scan the labelled malicious fixtures, carrying their expectations.

    The ``warm`` group is skipped: its rules read the dependency corpus and
    this is the cold scanner.  ``gate_d_series_warm`` scans it under the
    seeded corpus and asserts the cold half itself.  Fixtures are
    independent (each starts from an empty novelty state), so they run in
    parallel when ``jobs`` asks for it.
    """
    ensure_default_configs()
    config = load_config()
    rules = load_rules()

    tasks = []
    for group in sorted(
            p for p in root.iterdir() if p.is_dir() and p.name != "warm"):
        expected_path = group / "expected.json"
        expected = json.loads(expected_path.read_text()) if expected_path.exists() else {}
        for path in sorted(group.glob("*.diff")):
            tasks.append((group.name, str(path), expected))

    workers = _resolve_jobs(jobs)
    if workers <= 1:
        return [
            _scan_malicious_task(task) for task in tasks
        ]
    _precompile_patterns(rules)
    db_module.init_db()
    context = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(
        max_workers=workers, mp_context=context,
        initializer=_init_worker,
        initargs=(str(config_module.CONFIG_DIR), str(db_module.DATA_DIR),
                  rules, config, False),
    ) as pool:
        return list(pool.map(_scan_malicious_task, tasks, chunksize=1))


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

    Most synthetic fixtures are single-signal probes - "does H001 fire on a
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


def gate_published_figures(benign: list[dict], malicious: list[dict]) -> Gate:
    """The published distribution equals the one this scan measures.

    The docs and the site quote these figures, so a scoring change that
    moves the distribution has to move them in the same commit.  The table
    is not a threshold the gate sets: it is the published record, and this
    gate is what keeps the record from outliving the measurement.
    """
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
            sum(1 for s in scores if s > 20) / n * 100, 1),
        "threshold_percentile": round(
            sum(1 for s in scores if s <= 20) / n * 100, 1),
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


#: Entries that describe the analysis rather than the shape.  A known-gap
#: fixture scoring only from these is still open: a coverage note or an
#: unknown-host prior is not a detection.
_GAP_PRIOR_RULES = frozenset({"COVERAGE", "SOURCE_BUCKET", "NOVELTY"})


def _gap_detected_by_another_rule(result: dict) -> list[str]:
    """Scored findings on a known-gap fixture whose named rule did not fire.

    The gap record names the rule that was *meant* to catch the shape.
    When a later rule catches it instead, ``must_fire`` still fails and the
    fixture sits filed under "we do not detect this" forever: that is how
    the array-subscript, nameref and command-substitution gaps survived
    after the crossfire family closed them.  A fixture that clears its
    score bar with a real finding is covered, whatever rule produced it.
    """
    expected = result["expected"]
    if not expected.get("known_gap"):
        return []
    must = expected.get("must_fire", [])
    if all(rule in result["fired"] for rule in must):
        # The named rule fired; the label's own check reports it.
        return []
    min_score = expected.get("min_score")
    if min_score is not None and result["score"] < min_score:
        return []
    return sorted(result["scored"] - _GAP_PRIOR_RULES)


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


#: The sabotage family, one payload/lookalike pair per rule.
_S_RULES = ("S001", "S002", "S003", "S004", "S005", "S006", "S007", "S008")

#: The composition family, whose benign rates are recorded whole (including
#: the silent zeros) so a shrink is visible.
X_RULES = tuple(f"X{i:03d}" for i in range(1, 32))

#: Absolute drift the X-rate gate tolerates per rule: 0.002 of the locked
#: corpus is about seven diffs.  The X series fires on the co-occurrence of
#: other findings, so a rule change can shrink one of them without moving
#: any published figure; a drift past this must be adjudicated in the
#: changelog with a deliberate ``scripts/rebaseline.py`` run.
MAX_X_RATE_DRIFT = 0.002


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


def run_gates(corpus: Path = FIXTURES / "benign-corpus",
              malicious_root: Path = FIXTURES / "malicious",
              sample: int = 1, jobs: int | None = None) -> list[Gate]:
    with shipped_config():
        benign = scan_corpus(corpus, sample=sample, jobs=jobs)
        malicious = (scan_malicious(malicious_root, jobs=jobs)
                     if malicious_root.exists() else [])
        gates = _evaluate(benign, malicious)
        warm_root = malicious_root / "warm"
        if warm_root.exists():
            gates.append(gate_d_series_warm(warm_root))
        # The published distribution can only be compared against a whole
        # corpus: a sample moves every percentile.  `_evaluate` stays the
        # ten plan gates the sampled test run checks; this one rides the CI
        # job, which replays the corpus whole.
        if sample == 1:
            gates.append(gate_published_figures(benign, malicious))
            gates.append(gate_x_series_rate_stability(benign))
        return gates


def _evaluate(benign: list[dict], malicious: list[dict]) -> list[Gate]:

    gates = [
        gate_benign_fire_rates(benign),
        gate_score_not_size(benign),
        gate_weight_zero_annotations(benign),
        gate_h035_position(benign),
        gate_stateful_rules_stay_out(benign),
        gate_ioc_exact_match(benign),
        gate_homograph_single_script(),
    ]
    if malicious:
        gates.append(gate_separation(benign, malicious))
        gates.append(gate_malicious_recall(malicious))
        gates.append(gate_known_gaps_unchanged(malicious))
        gates.append(gate_s_series_fixture_pairs(benign, malicious))
    gates.append(gate_cluster_rate_below_members(benign))
    return gates


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the §10 calibration gates")
    parser.add_argument("--corpus", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--malicious", type=Path, default=FIXTURES / "malicious")
    parser.add_argument("--sample", type=int, default=1,
                        help="Scan every Nth benign diff (default: all)")
    parser.add_argument("--jobs", type=int, default=default_jobs(),
                        help="Analysis worker processes (default: min(8, CPUs))")
    parser.add_argument("--json", type=Path, help="Write the gate results here")
    args = parser.parse_args()

    if not args.corpus.exists():
        print(f"Corpus not found: {args.corpus}", file=sys.stderr)
        print("Reconstruct it with scripts/build_corpus.py --from-manifest",
              file=sys.stderr)
        return 2

    gates = run_gates(args.corpus, args.malicious, sample=args.sample,
                      jobs=args.jobs)

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
