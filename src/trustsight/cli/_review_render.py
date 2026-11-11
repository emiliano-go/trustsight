import typer

from ..coverage import GAP_REASONS
from ..safe_text import clean
from .display import (
    DEPTH_TRUNCATED_NOTE,
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


def _plain(value):
    """Project a review row to JSON-safe plain data."""
    if hasattr(value, "to_dict"):
        return _plain(value.to_dict())
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _render_results_rich(results, total_installed, all_packages, show_score, show_risk, verbose, outdated_total=0, deps_only=False):
    """Send the review rows to the render sandbox and emit its text."""
    import sys
    from ..sandbox import render_client
    from . import display
    from .inspect._render import (
        _layers_and_boundaries_line,
        _status_text,
    )
    from ..contacts import contact_panel, panel_lines
    from ..schema import fact_to_dict
    from ..reporting import render_cap
    from ..review_policy import review_policy

    policy = review_policy()
    payload_results = []
    for r in results:
        item = dict(r)
        item.pop("fact", None)
        item["version_text"] = _version_cell(r)
        fact = item.pop("_verbose_fact", None)
        if verbose and fact is not None and not item.get("failed"):
            item["verbose_fact"] = fact_to_dict(fact)
            item["verbose_layers_line"] = _layers_and_boundaries_line(fact) or ""
            item["verbose_contact_lines"] = panel_lines(contact_panel(fact))
            item["verbose_status_text"] = _status_text(fact)
        payload_results.append(_plain(item))

    text = render_client.render("review_results", {
        "results": payload_results,
        "total_installed": total_installed,
        "all_packages": all_packages,
        "show_score": show_score,
        "show_risk": show_risk,
        "verbose": verbose,
        "outdated_total": outdated_total,
        "deps_only": deps_only,
        "render_cap_value": render_cap(),
        "policy_threshold": policy.threshold,
        "policy_name": policy.name,
    })
    con = display._console
    stream = getattr(con, "file", None) if con is not None else None
    target = stream if stream is not None else sys.stdout
    target.write(text)
    target.flush()
