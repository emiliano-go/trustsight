"""The review table, rendered inside the sandbox."""

from __future__ import annotations

from types import SimpleNamespace

from ..coverage import GAP_REASONS
from ..safe_text import clean, safe_markup
from .display import RISK_COLORS, console, dependency_cards

DEPTH_TRUNCATED_NOTE = "dependency walk cut short; part of the closure was not analysed"


def _version_cell(result: dict) -> str:
    if result.get("version_text") is not None:
        return result["version_text"]
    from ..analysis.version import COMPARISON_INCONCLUSIVE
    from ..verdict import display_version, inconclusive_reason

    old = display_version(result.get("old_version"))
    new = display_version(result.get("new_version"))
    if result.get("version_comparison") == COMPARISON_INCONCLUSIVE:
        reason = inconclusive_reason(SimpleNamespace(
            old_version=result.get("old_version"),
            new_version=result.get("new_version"),
            coverage_gaps=result.get("coverage_gaps") or [],
        ))
        return f"{old} installed / {new} declared in the AUR (not comparable: {reason})"
    return f"{old}  \u2192  {new}"


def _summary_caption(reviewed, failed, flagged, total_installed, all_packages,
                     outdated_total, show_score, deps_only=False,
                     policy_threshold=20, policy_name="default") -> str:
    if deps_only:
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
        caption += (f", {flagged} above the {policy_threshold}-point "
                    f"{policy_name} review threshold")
    if failed:
        caption += f", {failed} could NOT be vetted"
    return caption


def _finding_line(finding: dict) -> str:
    from ..safe_text import clean as _clean

    file = finding.get("file", "") or ""
    line = finding.get("line")
    where = _clean(file)
    if where and line is not None:
        where = f"{where} line {line}"
    desc = _clean(finding.get("description", ""))
    return f"{where}  {desc}" if where else desc


_DEPS_HINT = (
    "Tip: those dependencies are summarised, not reviewed. "
    "`trustsight review --deps` reviews each as a package in its own right "
    "and names what requires it; add `--depth n` for deeper levels."
)


def _deps_hint(results, deps_only: bool) -> str:
    if deps_only:
        return ""
    if not any(r.get("dependencies") for r in results):
        return ""
    return _DEPS_HINT


def render_results(*, results, total_installed, all_packages, show_score,
                   show_risk, verbose, outdated_total=0, deps_only=False,
                   render_cap_value=50, policy_threshold=20,
                   policy_name="default"):
    from rich.panel import Panel
    from rich.text import Text

    con = console()
    for r in results:
        if verbose and not r.get("failed") and r.get("verbose_fact"):
            from .inspect import render_panel

            render_panel(
                fact=r["verbose_fact"],
                layers_line=r.get("verbose_layers_line") or "",
                contact_lines=r.get("verbose_contact_lines") or [],
                status_text=r.get("verbose_status_text") or "",
                show_score=show_score,
                show_risk=show_risk,
                verbose=verbose,
                render_cap_value=render_cap_value,
                policy_threshold=policy_threshold,
            )
            continue

        from rich.table import Table

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(no_wrap=True)
        table.add_column()

        table.add_row("Version", Text(_version_cell(r)))

        if r.get("failed"):
            table.add_row("Status", Text(clean(r["verdict"])))
            error = r.get("error")
            if error:
                table.add_row("Error", Text(clean(str(error))))
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

        _findings = r.get("findings", [])
        _cap = render_cap_value
        _shown = _findings if _cap <= 0 else _findings[:_cap]
        for f in _shown:
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
                prefix = {"added": "[green]+[/]", "removed": "[red]-[/]",
                          "modified": "[yellow]~[/]"}.get(status, " ")
                table.add_row("", f"  {prefix} {safe_markup(path)}")

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

        required_by_names = r.get("required_by") or []
        for position, name in enumerate(required_by_names):
            table.add_row("Required by" if position == 0 else "", Text(clean(name)))

        deps = r.get("dependencies", [])
        if deps:
            table.add_row("", "")
            table.add_row("Dependencies", "")
            for card in dependency_cards(
                    deps, show_score=show_score, show_risk=show_risk,
                    policy_threshold=policy_threshold):
                table.add_row("", card)
            if r.get("depth_truncated"):
                table.add_row("", Text(DEPTH_TRUNCATED_NOTE, style="yellow"))

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

    flagged = sum(1 for r in results if (r["score"] or 0) > policy_threshold)
    failed = sum(1 for r in results if r.get("failed"))
    reviewed = len(results) - failed
    caption = _summary_caption(
        reviewed, failed, flagged, total_installed, all_packages,
        outdated_total, show_score, deps_only,
        policy_threshold=policy_threshold, policy_name=policy_name,
    )
    con.print(caption)
    hint = _deps_hint(results, deps_only)
    if hint:
        con.print(f"[dim]{hint}[/]")
