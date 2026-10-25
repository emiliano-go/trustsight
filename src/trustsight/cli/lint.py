"""``trustsight lint`` - pre-submission recipe hygiene.

Lint runs ``parse_recipe`` on a local file and reports what the typed core
saw: parse status, unresolved assignments, the function inventory, the
array inventory (with duplicate and ordering notes), and the rules that
can run without a diff (the function-scoped rules). It is
explicitly **not** a verdict: no score, no finding severity, no history.
"""

from __future__ import annotations

import json
import pathlib

import typer

from ..bounded_io import read_file_capped
from ..config import load_config
from ..tokenizer import split_lines


def _all_added_diff(text: str, filename: str) -> str:
    """A unified diff in which every line of ``text`` is an addition.

    The diff-free rules read a diff's *added* lines; handing them the whole
    file as additions reuses that logic without a second code path.
    """
    lines = split_lines(text)
    header = (f"--- a/{filename}\n+++ b/{filename}\n"
              f"@@ -1,{len(lines)} +1,{len(lines)} @@\n")
    return header + "".join(f"+{line}\n" for line in lines)


def lint_report(text: str, filename: str) -> dict:
    """The hygiene report for one recipe's text."""
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
    from ..analysis.structural import _is_checksum_array

    n_source = len(recipe.arrays.get("source", ()))
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
        # an ordering note. A checksum array whose entry count differs
        # from source=() cannot be in positional parity, so a hash sits in a
        # slot a reviewer would not check.
        if _is_checksum_array(name) and n_source and len(entries) != n_source:
            notes.append(
                f"{len(entries)} entries, source=() has {n_source} "
                "(out of parity)")
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
        from ..line_lex import strip_comment, unwrap_shell_cexec

        for name in _hook_names(recipe):
            body = recipe.functions.get(name, "")
            # Same wrapper unwrap as the analyzer: a literal `sh -c '<lit>'`
            # re-exec reports the code it runs, not the wrapper token.
            match = _HOOK_INTERPRETER_RE.search(unwrap_shell_cexec(body))
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

    # / diff-free rules: H076 (build write outside the staging root) and
    # H091 (checksum array shorter than source=()).  Neither needs a diff, so
    # a first-seen recipe gets the same hygiene view as a change.
    from ..analysis.edges import build_context
    from ..analysis.persistence_engine import emit_outside_staging
    from ..analysis.structural import recipe_checksum_parity_finding

    hits: list[dict] = []

    def _collect(rule_id, name, severity, category, match, **extra):
        hits.append({
            "rule_id": rule_id, "severity": severity, "message": match,
            "file": extra.get("file", filename), "line": extra.get("line"),
        })

    emit_outside_staging(
        build_context(_all_added_diff(text, filename), load_config(),
                      current_text=text),
        _collect)
    findings.extend(hits)

    parity = recipe_checksum_parity_finding(text)
    if parity is not None:
        findings.append({
            "rule_id": parity["rule_id"], "severity": parity["severity"],
            "message": parity["match"],
        })

    from ..analysis.placeholder import placeholder_finding

    placeholder = placeholder_finding(text)
    if placeholder is not None:
        findings.append({
            "rule_id": placeholder["rule_id"],
            "severity": placeholder["severity"],
            "message": placeholder["match"],
        })

    from ..analysis.dependencies import name_shadow_findings

    for shadow in name_shadow_findings(
        text, str(recipe.scalars.get("pkgname", "") or ""),
    ):
        findings.append({
            "rule_id": shadow["rule_id"],
            "severity": shadow["severity"],
            "message": shadow["match"],
        })

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
    from ..safe_text import clean

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
                typer.echo(clean(message), err=True)
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
        typer.echo(clean(f"Lint: {report['file']}"))
        if report["scalars"]:
            scalars = ", ".join(
                f"{k}={v}" for k, v in sorted(report["scalars"].items()))
            typer.echo(clean(f"  scalars: {scalars}"))
        for name, info in sorted(report["arrays"].items()):
            note = f" [{'; '.join(info['notes'])}]" if info["notes"] else ""
            typer.echo(clean(f"  array {name}: {info['entries']} entries{note}"))
        typer.echo(clean(
            f"  functions: {', '.join(report['functions']) or '(none)'}"))
        for row in report["unresolved_assignments"]:
            typer.echo(clean(f"  unresolved: {row['name']}: {row['line']}"))
        for finding in report["rules"]:
            typer.echo(clean(
                f"  {finding['rule_id']} ({finding['severity']}): "
                f"{finding['message']}"))
        typer.echo("  score: none (lint is not a verdict)")
