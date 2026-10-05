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

import typer

from .inspect import analyze_package
from ..config import ensure_default_configs, load_rules
from ..db import init_db

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


def register_commands(app: typer.Typer):
    """Register the ``explain`` subcommand on *app*."""
    @app.command()
    def explain(
        package: str = typer.Argument(..., help="Package name"),
        rule_id: str = typer.Argument(..., help="Rule id, e.g. C003"),
        occurrence: int = typer.Option(
            1, "--occurrence",
            help="Which occurrence of the rule, 1-based (as inspect lists them)",
        ),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
        depth: int = typer.Option(
            None, "--depth", help="AUR dependency levels to analyse",
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
