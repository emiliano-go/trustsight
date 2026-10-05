"""Spec §8 v2: ``trustsight lint`` - pre-submission recipe hygiene.

Lint runs ``parse_recipe`` on a local file and reports what the typed core
saw: parse status, unresolved assignments, the function inventory, the
array inventory (with duplicate and ordering notes), and the rules that
can run without a diff (the function-scoped rules from §7/§9).  It is
explicitly **not** a verdict: no score, no finding severity, no history.
"""

from __future__ import annotations

import json
import pathlib

import typer

from ..bounded_io import read_file_capped
from ..tokenizer import split_lines


def lint_report(text: str, filename: str) -> dict:
    """The hygiene report for one recipe's text (spec §8 v2)."""
    from ..coverage import (
        _COMMAND_SUBSTITUTION_RE,
        _SOURCE_ASSIGN_RE,
        unresolved_assignment_rows,
    )
    from ..recipedoc import parse_recipe

    recipe = parse_recipe(text, file=filename)
    # The same union the analysis paths report: tokenizer refusals plus the
    # coverage layer's own (a `source=` computed at build time is kept as a
    # literal by the tokenizer but is still never seen).
    computed_sources = [
        line.strip() for line in split_lines(text)
        if _SOURCE_ASSIGN_RE.match(line)
        and _COMMAND_SUBSTITUTION_RE.search(line)
    ]
    unresolved = unresolved_assignment_rows(
        text, file=filename, extra_lines=computed_sources)
    arrays = {}
    for name, entries in recipe.arrays.items():
        counts: dict[str, int] = {}
        for entry in entries:
            counts[entry] = counts.get(entry, 0) + 1
        duplicates = sorted(entry for entry, n in counts.items() if n > 1)
        notes = []
        if duplicates:
            notes.append(f"{len(duplicates)} duplicated entr"
                         f"{'y' if len(duplicates) == 1 else 'ies'}")
        if any(entry.strip().upper() in ("SKIP", "NONE") for entry in entries):
            notes.append("contains SKIP/NONE")
        arrays[name] = {
            "entries": len(entries),
            "duplicates": duplicates,
            "notes": notes,
        }

    findings: list[dict] = []
    package_body = recipe.functions.get("package", "")
    if package_body:
        from ..analysis.structural import _package_fetch_client

        client = _package_fetch_client(package_body)
        if client:
            findings.append({
                "rule_id": "C015",
                "severity": "HIGH",
                "message": f"package() fetches with '{client}'",
            })
    if filename.endswith(".install"):
        from ..analysis.structural import _HOOK_INTERPRETER_RE, _hook_names
        from ..analysis.structural import _raw_targets, _user_writable_target
        from ..line_lex import strip_comment

        for name in _hook_names(recipe):
            body = recipe.functions.get(name, "")
            match = _HOOK_INTERPRETER_RE.search(body)
            if match:
                findings.append({
                    "rule_id": "C016", "severity": "HIGH",
                    "message": f"{name}() invokes '{match.group(0).strip()}'",
                })
            for raw_line in split_lines(body):
                hit = next(
                    (t for t in _raw_targets(strip_comment(raw_line))
                     if _user_writable_target(t)), None)
                if hit:
                    findings.append({
                        "rule_id": "C017", "severity": "HIGH",
                        "message": f"{name}() writes to {hit.strip()}",
                    })
                    break

    return {
        "file": filename,
        "parsed": True,
        "scalars": {
            key: recipe.scalars[key]
            for key in ("pkgname", "pkgver", "pkgrel", "epoch", "url", "install")
            if key in recipe.scalars
        },
        "arrays": arrays,
        "functions": {
            name: {
                "line": recipe.function_spans[name].line
                if name in recipe.function_spans else None,
            }
            for name in recipe.functions
        },
        "unresolved_assignments": unresolved,
        "rules": findings,
        # Lint is not a verdict: no score field, by construction.
        "score": None,
    }


def register_commands(app: typer.Typer):
    """Register the ``lint`` subcommand on *app*."""
    @app.command()
    def lint(
        path: str = typer.Argument(..., help="Local PKGBUILD or .install path"),
        json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    ):
        """Recipe hygiene for a local file: no diff, no score."""
        from ..api import MAX_API_TEXT_BYTES

        def _fail(message: str) -> None:
            if json_output:
                typer.echo(json.dumps({"error": message}))
            else:
                typer.echo(message, err=True)
            raise typer.Exit(code=2)

        target = pathlib.Path(path)
        if not target.is_file():
            _fail(f"not a file: {path}")
        try:
            raw = read_file_capped(
                target, MAX_API_TEXT_BYTES, what="lint input")
        except Exception as exc:
            _fail(f"could not read {path}: {exc}")
        text = raw.decode("utf-8", errors="replace")
        try:
            report = lint_report(text, target.name)
        except Exception as exc:
            _fail(f"could not parse {path}: {exc}")

        if json_output:
            typer.echo(json.dumps(report, indent=2))
            return
        typer.echo(f"Lint: {report['file']}")
        if report["scalars"]:
            scalars = ", ".join(
                f"{k}={v}" for k, v in sorted(report["scalars"].items()))
            typer.echo(f"  scalars: {scalars}")
        for name, info in sorted(report["arrays"].items()):
            note = f" [{'; '.join(info['notes'])}]" if info["notes"] else ""
            typer.echo(f"  array {name}: {info['entries']} entries{note}")
        typer.echo(
            f"  functions: {', '.join(report['functions']) or '(none)'}")
        for row in report["unresolved_assignments"]:
            typer.echo(f"  unresolved: {row['name']}: {row['line']}")
        for finding in report["rules"]:
            typer.echo(
                f"  {finding['rule_id']} ({finding['severity']}): "
                f"{finding['message']}")
        typer.echo("  score: none (lint is not a verdict)")
