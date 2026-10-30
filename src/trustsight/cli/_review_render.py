import typer

from ..coverage import GAP_REASONS
from ..safe_text import clean, safe_markup
from .display import (
    DEPTH_TRUNCATED_NOTE,
    RISK_COLORS,
    console,
    dependency_cards_rich,
    dependency_lines_plain,
    display_version,
    finding_where,
)


def _version_cell(result: dict) -> str:
    """Version text for one review row, honest about comparability."""
    from ..analysis.version import COMPARISON_INCONCLUSIVE

    old = display_version(result.get("old_version"))
    new = display_version(result.get("new_version"))
    if result.get("version_comparison") == COMPARISON_INCONCLUSIVE:
        from ..schema import PackageFact
        from ..verdict import inconclusive_reason

        # No "AUR pkgver": the AUR side is its declared version when one can
        # be read, and no bare pkgver phrase survives anyway.  The review
        # row and the inspect version line must name the same cause, or the
        # same comparison disagrees with itself between the two surfaces.
        reason = inconclusive_reason(PackageFact(
            old_version=result.get("old_version"),
            new_version=result.get("new_version"),
            coverage_gaps=result.get("coverage_gaps") or [],
        ))
        return f"{old} installed / {new} declared in the AUR (not comparable: {reason})"
    return f"{old}  \u2192  {new}"


def _summary_caption(reviewed, failed, flagged, total_installed, all_packages,
                     outdated_total, show_score, deps_only=False) -> str:
    """The one-line summary, counting what was found separately from what
    was read.

    These used to be the same number. `--limit 5` against 40 outdated
    packages printed "5 package(s) needing update and reviewed": the count
    of packages *needing an update* was silently replaced by the count of
    packages the limit allowed through, and the 35 skipped were never
    mentioned. A review that stops early is a coverage gap, and this tool's
    rule for a coverage gap is that it is stated rather than absorbed.
    """
    if deps_only:
        # The subject is not "packages needing an update" here, and saying
        # so would misreport both what was reviewed and what it was
        # reviewed out of.
        caption = f"{reviewed} AUR dependenc{'y' if reviewed == 1 else 'ies'} reviewed"
        if total_installed:
            caption += f" for {total_installed} installed package(s)"
    elif all_packages and total_installed:
        caption = f"{reviewed} package(s) reviewed out of {total_installed} installed"
    else:
        caption = f"{reviewed} package(s) needing update and reviewed"
        if total_installed:
            caption += f" out of {total_installed} installed"
    skipped = max(0, outdated_total - (reviewed + failed))
    if skipped:
        caption += (
            f"; {skipped} more needed review and were NOT read "
            f"(--limit); pass --limit 0 for all of them"
        )
    if show_score and flagged:
        from ..review_policy import review_policy

        policy = review_policy()
        caption += f", {flagged} above the {policy.threshold}-point {policy.name} review threshold"
    if failed:
        caption += f", {failed} could NOT be vetted"
    return caption


def _finding_line(finding: dict) -> str:
    """One finding as `file line N  description`, for either renderer.

    The rule id is not added here: the description already carries it, and
    the two renderers previously disagreed about that - the Rich one
    printed it twice and the plain one once. A finding with no file (an
    aggregate such as `SOURCE_BUCKET`) used to open with a stray space
    where the filename would have been.
    """
    where = finding_where(finding.get("file", "") or "", finding.get("line"))
    desc = clean(finding.get("description", ""))
    return f"{where}  {desc}" if where else desc


#: Shown once under an ordinary review, and only when there is something for
#: it to point at. A dependency was analysed and summarised in a card, but
#: the card is a summary: `--deps` reviews each one as a package in its own
#: right and says which packages require it. Suppressed under `--deps`
#: itself (already there), under `--json` (a document, not a conversation),
#: and when nothing reported a dependency (advice about an empty set).
_DEPS_HINT = (
    "Tip: those dependencies are summarised, not reviewed. "
    "`trustsight review --deps` reviews each as a package in its own right "
    "and names what requires it; add `--depth n` for deeper levels."
)


def _deps_hint(results, deps_only: bool) -> str:
    """The `--deps` recommendation, or "" when it would be noise."""
    if deps_only:
        return ""
    if not any(r.get("dependencies") for r in results):
        return ""
    return _DEPS_HINT


def _render_version_cell(result: dict) -> str:
    """Resolve through the legacy facade so existing monkeypatches still apply."""
    from . import review

    return review._version_cell(result)


def _render_results_plain(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total=0, deps_only=False):
    """The review render for a terminal without Rich.

    Extracted from ``_run_analysis_loop`` so it can be exercised: a renderer
    that cannot be called without a CLI invocation cannot be gated, and an
    ungateable path is where the dropped field will be.  See
    ``docs/contributing/security-review.md``.
    """
    for r in results:
        if r.get("failed"):
            typer.echo(f"{clean(r['package'])} {_render_version_cell(r)}")
            if r.get("aur_note"):
                typer.echo(f"  {clean(r['aur_note'])}")
            typer.echo(f"  {clean(r['verdict'])}")
            typer.echo()
            continue

        # `--verbose` means the full report, on both renderers. The Rich
        # path has always handed off to the inspect panel here; this one
        # did not, so asking for more detail without Rich installed
        # silently returned the same summary - the drop this function's
        # docstring exists to prevent.
        if verbose and r.get("_verbose_fact"):
            from .inspect import _inspect_plain

            _inspect_plain(r["_verbose_fact"], verbose=verbose,
                           show_score=show_score, show_risk=show_risk)
            continue

        typer.echo(f"{clean(r['package'])} {_render_version_cell(r)}")

        findings = r.get("findings", [])
        file_changes = r.get("file_changes", [])
        is_trivial = r.get("is_trivial", False)

        if r.get("aur_note"):
            typer.echo(f"  {clean(r['aur_note'])}")
        elif r.get("first_seen"):
            typer.echo("  First analysis. No prior history for this package.")
        elif is_trivial:
            typer.echo("  Only pkgver and sha256sums changed. Review the diff before building.")
        else:
            typer.echo("  The update is not trivial. Review it.")

        # Findings and files changed are sections of their own, not clauses of
        # the status: the status describes the diff, and a package whose
        # commit has not moved still fires non-diff findings (H029, H003,
        # SOURCE_BUCKET, NOVELTY). Both renderers show them so the status
        # cannot read as "nothing was found".
        from ..reporting import render_cap

        _cap = render_cap()
        _shown = findings if _cap <= 0 else findings[:_cap]
        for f in _shown:
            typer.echo(f"  {_finding_line(f)}")
        if _cap > 0 and len(findings) > _cap:
            typer.echo(
                f"  ... and {len(findings) - _cap} more finding(s) (see --json)")
        if file_changes:
            for fc in file_changes:
                status = fc.get("status", "")
                path = fc.get("path", "")
                prefix = {"added": "+", "removed": "-", "modified": "~"}.get(status, " ")
                typer.echo(f"  {prefix} {clean(path)}")

        # The Contact Ledger panel: weight 0, warm-only (see the Rich render).
        contacts = r.get("contacts") or {}
        if contacts.get("available") is False:
            typer.echo(f"  First contact: {clean(contacts.get('note', ''))}")
        elif contacts.get("records"):
            typer.echo("  First contact (weight 0):")
            for c in contacts["records"]:
                typer.echo(f"    {clean(c.get('kind', ''))} "
                           f"{clean(c.get('value', ''))} "
                           f"({clean(c.get('basis', ''))})")

        if show_score and not r.get("failed"):
            risk = r.get("risk_label") or r.get("risk", "")
            score_val = r.get("score", 0)
            typer.echo(f"  Score: {score_val}/100 ({risk})")
        elif show_risk and not r.get("failed"):
            label = r.get("risk_label") or r.get("risk", "")
            typer.echo(f"  Risk: {label}")

        for entry in r.get("changes", []):
            typer.echo(f"  ~ {clean(entry)}")
        required_by_names = r.get("required_by") or []
        if required_by_names:
            typer.echo(f"  Required by: {clean(', '.join(required_by_names))}")
        for line in dependency_lines_plain(r.get("dependencies", []),
                                           show_score=show_score,
                                           show_risk=show_risk):
            typer.echo(line)
        if r.get("depth_truncated"):
            typer.echo(f"  [{DEPTH_TRUNCATED_NOTE}]")

        # B5, same omission as the Rich render above: visible on screen, not
        # only in the JSON body.
        for entry in r.get("suppressed_rules", []):
            scope = entry.get("override_package") or "ALL packages"
            corroborated = (" (indicator corroborated)"
                            if entry.get("indicator_corroborated") else "")
            typer.echo(
                f"  [Suppressed: {clean(entry.get('rule_id', ''))} "
                f"({clean(scope)}) {clean(entry.get('override_reason', ''))}"
                f"{corroborated}]"
            )
        # A lapsed override is named too (B5): silence must not mean both
        # "no override" and "the override expired".
        for rid in r.get("overrides_expired", []):
            typer.echo(
                f"  [Override expired: {clean(str(rid))}; no longer suppressing]"
            )
        for m in r.get("ioc_matches", []):
            expired = " [EXPIRED]" if m.expired else ""
            line = f" line {m.line}" if m.line is not None else ""
            typer.echo(
                f"  [IOC] [{clean(m.source)}] {clean(m.type)}={clean(m.value)}"
                f"{line} ({clean(m.surface)}){expired}"
            )
        for gap in r.get("coverage_gaps", []):
            typer.echo(f"  [Not fully vetted: {GAP_REASONS.get(gap, gap)}.]")

        typer.echo()

    from ..review_policy import review_policy
    policy = review_policy()
    flagged = sum(1 for r in results if policy.flagged(r["score"] or 0))
    failed = sum(1 for r in results if r.get("failed"))
    reviewed = len(results) - failed
    caption = _summary_caption(
        reviewed, failed, flagged, total_installed, all_packages,
        outdated_total, show_score, deps_only,
    )
    typer.echo(caption)
    hint = _deps_hint(results, deps_only)
    if hint:
        typer.echo(hint)


def _render_results_rich(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total=0, deps_only=False):
    from rich.panel import Panel
    from rich.text import Text

    con = console()
    for r in results:
        if verbose and not r.get("failed") and r.get("_verbose_fact"):
            from .inspect import _inspect_rich as _render_inspect
            _render_inspect(
                r["_verbose_fact"],
                verbose=verbose,
                show_score=show_score,
                show_risk=show_risk,
            )
            continue

        from rich.table import Table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(no_wrap=True)
        table.add_column()

        table.add_row("Version", Text(_render_version_cell(r)))

        if r.get("failed"):
            table.add_row("Status", Text(clean(r["verdict"])))
            panel = Panel(table, title=Text(clean(r["package"])), border_style="red")
            con.print(panel)
            continue

        if r.get("aur_note"):
            table.add_row("Status", Text(clean(r["aur_note"])))
        elif r.get("first_seen"):
            table.add_row("Status", "First analysis. No prior history for this package.")
        elif r.get("is_trivial"):
            table.add_row("Status", "Only pkgver and sha256sums changed. Review the diff before building.")
        else:
            table.add_row("Status", "The update is not trivial. Review it.")

        # Findings are rendered independently of that status line. The
        # no-change and trivial branches describe the *diff*; a finding they
        # would not show is still a finding. H029 (name typosquat), H003,
        # SOURCE_BUCKET and NOVELTY are computed from the head recipe and the
        # database, so a package whose commit has not moved still fires them -
        # and the dependency card and `inspect` have always printed them.
        # Nesting this loop in the `else` made the status a claim that nothing
        # was found, which is not what the status says.
        from ..reporting import render_cap

        _findings = r.get("findings", [])
        _cap = render_cap()
        _shown = _findings if _cap <= 0 else _findings[:_cap]
        for f in _shown:
            # The description already ends with `[R001]` - `verdict._render`
            # puts it there, and the JSON body and the plain renderer both
            # carry it that way. Adding a second copy in front printed
            # every finding as
            #   `PKGBUILD line 4 [R001]  Remote Script Execution: ... [R001]`
            # and made this renderer disagree with the plain one about the
            # same finding.
            table.add_row("", Text(clean(_finding_line(f))))
        if _cap > 0 and len(_findings) > _cap:
            table.add_row(
                "", f"  [dim]... and {len(_findings) - _cap} more finding(s) "
                    "(see --json)[/]")

        file_changes = r.get("file_changes", [])
        if file_changes:
            table.add_row("", "")
            table.add_row("Files changed", "")
            for fc in file_changes:
                status = fc.get("status", "")
                path = fc.get("path", "")
                prefix = {"added": "[green]+[/]", "removed": "[red]-[/]", "modified": "[yellow]~[/]"}.get(status, " ")
                table.add_row("", f"  {prefix} {safe_markup(path)}")

        # The Contact Ledger panel: weight 0, warm-only.  A cold replay shows
        # the standing note so an empty panel is never read as a clean one.
        contacts = r.get("contacts") or {}
        if contacts.get("available") is False:
            table.add_row("First contact", Text(clean(contacts.get("note", ""))))
        elif contacts.get("records"):
            table.add_row("First contact", "weight 0")
            for c in contacts["records"]:
                table.add_row("", Text(
                    f"  {clean(c.get('kind', ''))} {clean(c.get('value', ''))} "
                    f"({clean(c.get('basis', ''))})"))

        changes = r.get("changes", [])
        if changes:
            table.add_row("Changed", Text(clean(changes[0])))
            for entry in changes[1:]:
                table.add_row("", Text(clean(entry)))

        # `--deps`: the subject of this panel is a dependency, so the
        # relationship worth naming is the reverse one. A dependency nobody
        # in the reviewed set requires is not what was asked for; one that
        # three packages require is the reason to read it first.
        required_by_names = r.get("required_by") or []
        for position, name in enumerate(required_by_names):
            table.add_row("Required by" if position == 0 else "", Text(clean(name)))

        # Dependency mini-cards: each is its own analysis, so it gets its
        # own card nested in this one rather than a line in this package's
        # finding list.
        deps = r.get("dependencies", [])
        if deps:
            table.add_row("", "")
            table.add_row("Dependencies", "")
            for card in dependency_cards_rich(deps, show_score=show_score,
                                       show_risk=show_risk):
                table.add_row("", card)
            if r.get("depth_truncated"):
                table.add_row("", Text(DEPTH_TRUNCATED_NOTE, style="yellow"))

        # B5: a suppression a reader cannot see is one they cannot audit.
        # This render carried it in the JSON body and nowhere on screen, so
        # a rule switched off by an override looked, to anyone reading the
        # terminal, exactly like one that never matched.
        suppressed = r.get("suppressed_rules", [])
        if suppressed:
            table.add_row("Suppressed", "")
            for entry in suppressed:
                rule_id = entry.get("rule_id", "")
                scope = entry.get("override_package") or "ALL packages"
                reason = entry.get("override_reason", "")
                corroborated = ("  (indicator corroborated)"
                                if entry.get("indicator_corroborated") else "")
                table.add_row("", Text(
                    f"  {clean(rule_id)}  ({clean(scope)})  {clean(reason)}"
                    f"{corroborated}"))

        expired_overrides = r.get("overrides_expired", [])
        if expired_overrides:
            table.add_row("Overrides expired", "")
            for rid in expired_overrides:
                table.add_row("", Text(
                    f"  {clean(str(rid))}  no longer suppressing"))

        ioc_matches = r.get("ioc_matches", [])
        if ioc_matches:
            table.add_row("IOC matches", "")
            for m in ioc_matches:
                expired = " [EXPIRED]" if m.expired else ""
                line = f" line {m.line}" if m.line is not None else ""
                table.add_row("", Text(
                    f"  [{clean(m.source)}] {clean(m.type)}={clean(m.value)}"
                    f"{line} ({clean(m.surface)}){expired}"
                ))

        for gap in r.get("coverage_gaps", []):
            table.add_row("Not vetted", GAP_REASONS.get(gap, gap))

        risk = r.get("risk", "")
        label = r.get("risk_label") or risk
        score_val = r.get("score", 0)
        border = RISK_COLORS.get(risk, "blue") if (show_score or show_risk) else "blue"

        if show_score and not r.get("failed"):
            table.add_row("Score", f"{score_val}/100 ({label})")
        elif show_risk and not r.get("failed"):
            table.add_row("Risk", clean(label))

        panel = Panel(table, title=Text(clean(r["package"])), border_style=border)
        con.print(panel)

    from ..review_policy import review_policy
    policy = review_policy()
    flagged = sum(1 for r in results if policy.flagged(r["score"] or 0))
    failed = sum(1 for r in results if r.get("failed"))
    reviewed = len(results) - failed
    caption = _summary_caption(
        reviewed, failed, flagged, total_installed, all_packages,
        outdated_total, show_score, deps_only,
    )
    con.print(caption)
    hint = _deps_hint(results, deps_only)
    if hint:
        con.print(f"[dim]{hint}[/]")
