"""Spec §10: ``trustsight explain`` - why one rule fired on one line.

The report is deterministic evidence, but the evidence stops at the
citation.  Findings are projections over a shared document, so "why did
this rule fire on this line" is mechanically answerable by re-running the
one rule over the stored diff.  v1 covers document-projection rules;
a rule with an external read (novelty/seed, dependency corpus, official
names) names that input and shows the cached value it used.
"""

from __future__ import annotations

import json
import types

import typer

from .inspect import analyze_package
from ..config import ensure_default_configs, load_rules
from ..db import get_analysis, init_db

#: Rules whose firing depends on an input outside the document.  The
#: explanation names the input and the cached value instead of pretending
#: the rule is re-runnable in isolation.
_EXTERNAL_INPUTS = {
    "D001": "dependency corpus (observation counts)",
    "D002": "dependency corpus (observation counts)",
    "D003": "dependency corpus (observation counts)",
    "D004": "official package names",
    "H029": "package observation history",
    "H064": "official package names",
    "NOVELTY": "seed/baseline URL and maintainer history",
    "SOURCE_BUCKET": "seed/baseline URL history",
}


def build_explanation(fact, finding: dict, definition: dict | None,
                      diff_text: str) -> dict:
    """The mechanical answer to "why did this fire here" (spec §10).

    Re-reads the document, re-runs the rule's pattern when it has one,
    and returns the rule definition, the matching lines with both line
    numbers, the document facts the rule read, and any external input the
    rule needed.
    """
    from ..diffdoc import parse_diff

    rule_id = str(finding.get("rule_id", ""))
    path = finding.get("file") or ""
    line = finding.get("line")
    document = parse_diff(diff_text) if diff_text else None

    matching: list[dict] = []
    if document is not None:
        for entry in document.lines:
            if not entry.is_content or (path and entry.file != path):
                continue
            if line is not None and line not in (
                entry.new_lineno, entry.old_lineno
            ):
                continue
            matching.append({
                "file": entry.file,
                "side": entry.side,
                "old_lineno": entry.old_lineno,
                "new_lineno": entry.new_lineno,
                "raw": entry.raw,
            })

    pattern_matches: list[dict] = []
    pattern = (definition or {}).get("pattern")
    if pattern and document is not None:
        import re

        try:
            compiled = re.compile(pattern)
        except re.error:
            compiled = None
        if compiled is not None:
            for entry in document.lines:
                if entry.is_content and compiled.search(entry.raw):
                    pattern_matches.append({
                        "file": entry.file,
                        "old_lineno": entry.old_lineno,
                        "new_lineno": entry.new_lineno,
                        "raw": entry.raw,
                    })

    external = _EXTERNAL_INPUTS.get(rule_id)
    external_value = None
    if external:
        novelty = getattr(fact, "novelty_context", None)
        external_value = {
            "observation_count": getattr(novelty, "observation_count", 0),
        }
    return {
        "package": getattr(fact, "package_name", ""),
        "rule_id": rule_id,
        "rule": {
            "id": (definition or {}).get("id", rule_id),
            "severity": (definition or {}).get("severity", finding.get("severity", "")),
            "pattern": pattern or "",
            "match_target": (definition or {}).get("match_target", ""),
            "scope": (definition or {}).get("scope", ""),
            "description": (definition or {}).get("description", ""),
        },
        "finding": dict(finding),
        "lines": matching,
        "pattern_matches": pattern_matches,
        # The document facts the rule read; the change delta is the shared
        # evidence object (spec §1), so the explanation cannot disagree
        # with the report it explains.
        "facts": {
            "change": dict(getattr(fact, "change", {}) or {}),
            "evidence": dict(finding.get("evidence") or {}),
        },
        "external_input": external,
        "external_value": external_value,
    }


def _explanation_from_history(row: dict, rule_id: str, occurrence: int) -> dict:
    """Reconstruct the ORIGINAL recorded analysis for one history row.

    Nothing is re-run with today's rules: the stored ``fact_json`` carries
    the score breakdown (rule, file, line, evidence), coverage gaps,
    suppressions and the config fingerprint the analysis was recorded
    with, and ``raw_diff_blob`` carries the exact diff the rules matched
    against.
    """
    try:
        stored = json.loads(row.get("fact_json") or "{}")
    except (ValueError, TypeError):
        stored = {}
    if not isinstance(stored, dict):
        stored = {}

    entries = [
        e for e in (stored.get("score_breakdown") or [])
        if isinstance(e, dict) and e.get("rule_id") == rule_id
    ]
    if not entries:
        return {}
    entry = entries[min(occurrence - 1, len(entries) - 1)]
    # Rows written before file/line/evidence were stored have neither;
    # the explanation says so rather than guessing from today's diff.
    finding = {
        "rule_id": rule_id,
        "file": entry.get("file") or None,
        "line": entry.get("line"),
        "description": entry.get("reason") or "",
        "template": entry.get("template") or "",
        "params": entry.get("params") or {},
        "evidence": entry.get("evidence") or {},
        "severity": entry.get("severity") or "",
        "weight": entry.get("weight", 0),
    }
    if finding["file"] is None and finding["line"] is None:
        finding["note"] = "file/line not recorded for this analysis"

    diff_text = row.get("raw_diff_blob") or ""
    if isinstance(diff_text, bytes):
        diff_text = diff_text.decode("utf-8", errors="replace")

    fact = types.SimpleNamespace(
        package_name=stored.get("package_name") or "",
        novelty_context=types.SimpleNamespace(observation_count=0),
        change=stored.get("change") or {},
    )
    definition = next(
        (rule for rule in load_rules() if rule.get("id") == rule_id),
        None,
    )
    explanation = build_explanation(fact, finding, definition, diff_text)
    explanation["analysis"] = {
        "id": row.get("id"),
        "timestamp": row.get("timestamp") or "",
        "package": stored.get("package_name") or "",
        "old_version": row.get("old_version") or "",
        "new_version": row.get("new_version") or "",
        "old_commit": row.get("old_commit") or "",
        "new_commit": row.get("new_commit") or "",
        "score": row.get("final_score", 0),
        "risk": stored.get("risk") or "",
        "coverage_gaps": stored.get("coverage_gaps") or [],
        "config_fingerprint": stored.get("config_fingerprint") or "",
        "suppressed_rules": stored.get("suppressed_rules") or [],
        "acknowledged_urls": stored.get("acknowledged_urls") or [],
    }
    return explanation


def register_commands(app: typer.Typer):
    """Register the ``explain`` subcommand on *app*."""
    @app.command()
    def explain(
        package: str = typer.Argument(None, help="Package name (positionally required by the CLI; ignored when --history-id is given)"),
        rule_id: str = typer.Argument(..., help="Rule id, e.g. C003"),
        occurrence: int = typer.Option(
            1, "--occurrence",
            help="Which occurrence of the rule, 1-based (as inspect lists them)",
        ),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
        depth: int = typer.Option(
            None, "--depth", help="AUR dependency levels to analyse",
        ),
        history_id: int = typer.Option(
            None, "--history-id",
            help="Explain a recorded analysis by its history id: reproduces "
                 "the ORIGINAL run (stored findings, diff, config) instead "
                 "of re-analysing with today's rules. Ids are listed by "
                 "'trustsight history <package>'.",
        ),
    ):
        """Explain why one rule fired on one finding."""
        def _fail(message: str) -> None:
            if json_output:
                typer.echo(json.dumps({"error": message}))
            else:
                typer.echo(message, err=True)
            raise typer.Exit(code=2)

        if occurrence < 1:
            _fail("--occurrence must be >= 1")
        ensure_default_configs()
        init_db()

        if history_id is not None:
            row = get_analysis(history_id)
            if row is None:
                _fail(f"No recorded analysis with id {history_id}")
            stored = {}
            try:
                stored = json.loads(row.get("fact_json") or "{}")
            except (ValueError, TypeError):
                stored = {}
            pkg_name = (stored or {}).get("package_name") or ""
            explanation = _explanation_from_history(row, rule_id.upper(), occurrence)
            if not explanation:
                _fail(
                    f"{rule_id.upper()} did not fire in recorded analysis "
                    f"#{history_id} ({pkg_name})"
                )
            analysis = explanation["analysis"]
            if json_output:
                typer.echo(json.dumps(explanation, indent=2))
                return
            typer.echo(
                f"Analysis #{analysis['id']} ({analysis['timestamp']}): "
                f"{analysis['package']} "
                f"{analysis['old_version']} -> {analysis['new_version']} "
                f"[{analysis['old_commit'][:8]}..{analysis['new_commit'][:8]}]"
            )
            typer.echo(
                f"{rule_id.upper()} on {analysis['package']}: "
                f"{explanation['finding'].get('description', '')}"
            )
            if explanation["finding"].get("note"):
                typer.echo(f"  {explanation['finding']['note']}")
            else:
                where = explanation["finding"].get("file") or "?"
                typer.echo(
                    f"  cited: {where} line {explanation['finding'].get('line')}"
                )
            if explanation["analysis"].get("config_fingerprint"):
                typer.echo(
                    f"  config: {explanation['analysis']['config_fingerprint']}"
                )
            for match in explanation["lines"]:
                typer.echo(
                    f"  line: {match['raw']} "
                    f"(old {match['old_lineno']}, new {match['new_lineno']})"
                )
            for gap in analysis.get("coverage_gaps") or []:
                from ..coverage import GAP_REASONS
                typer.echo(f"  not fully vetted: {GAP_REASONS.get(gap, gap)}")
            for r in analysis.get("suppressed_rules") or []:
                scope = r.get("override_package") or "ALL packages"
                typer.echo(
                    f"  suppressed: {r.get('rule_id', '')} ({scope}) "
                    f"{r.get('override_reason', '')}"
                )
            return

        if not package:
            _fail("Package name is required unless --history-id is given")
        try:
            fact = analyze_package(package, depth=depth, record=False)
        except Exception as exc:
            _fail(f"Analysis of '{package}' failed: {exc}")

        from ..reporting import finding_rows
        from ..fetcher import clone_or_fetch
        from ..differ import generate_diff_bounded

        rows = [
            row for row in finding_rows(fact)
            if row.get("rule_id") == rule_id
        ]
        if not rows:
            message = f"{rule_id} did not fire on {package}"
            unresolved = list(getattr(fact, "unresolved_assignments", ()) or ())
            if unresolved:
                message += (
                    f"; {len(unresolved)} unresolved assignment(s) bound the "
                    "analysis (see inspect)"
                )
            _fail(message)
        finding = rows[min(occurrence - 1, len(rows) - 1)]

        diff_text = ""
        try:
            repo = clone_or_fetch(package)
            if fact.old_commit and fact.new_commit:
                diff_text, _summary, _trunc = generate_diff_bounded(
                    repo, fact.old_commit, fact.new_commit)
        except Exception:
            # The explanation still answers from the finding's own facts;
            # the line re-read is best-effort.
            diff_text = ""
        definition = next(
            (rule for rule in load_rules() if rule.get("id") == rule_id),
            None,
        )
        explanation = build_explanation(fact, finding, definition, diff_text)

        if json_output:
            typer.echo(json.dumps(explanation, indent=2))
            return
        typer.echo(f"{rule_id} on {package}: {finding.get('description', '')}")
        where = finding.get("file") or "?"
        typer.echo(f"  cited: {where} line {finding.get('line')}")
        if definition:
            target = definition.get("match_target") or "resolved"
            typer.echo(
                f"  rule: {definition.get('severity', '?')} "
                f"match_target={target} pattern={definition.get('pattern', '')}"
            )
        for match in explanation["lines"]:
            typer.echo(
                f"  line: {match['raw']} "
                f"(old {match['old_lineno']}, new {match['new_lineno']})"
            )
        if explanation["external_input"]:
            typer.echo(
                f"  external input: {explanation['external_input']} "
                f"(cached: {explanation['external_value']})"
            )
