import json
import logging

import typer

from ..config import ensure_default_configs
from ..db import init_db
from ..override import (
    FATAL_RULES,
    OVERRIDES_PATH,
    add_override,
    add_url_ack,
    list_overrides,
    list_url_acks,
    remove_override,
    remove_url_ack,
)
from ..safe_text import clean
from .completion import installed_packages
from .display import _print_colored, emit, use_rich

log = logging.getLogger(__name__)

override_app = typer.Typer(
    help="Suppress a rule that misfires on your packages",
    no_args_is_help=True, add_completion=False,
)


# --- override subcommands ---

@override_app.command("list")
def override_list(
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """List all rule overrides and acknowledged source URLs."""
    ensure_default_configs()
    overrides = list_overrides()
    url_acks = list_url_acks()

    if not overrides and not url_acks:
        msg = (
            f"No overrides configured. File: {OVERRIDES_PATH}\n"
            f"Add one with: trustsight override add H001 --package mypkg --reason \"...\"\n"
            f"Acknowledge a URL with: trustsight override add-url PACKAGE URL --reason \"...\""
        )
        if json_output:
            typer.echo(json.dumps({"overrides": [], "url_acks": []}))
        elif use_rich():
            _print_colored(msg)
        else:
            print(msg)
        return

    if json_output:
        typer.echo(json.dumps({
            "overrides": [
                {"rule_id": o.rule_id, "package": o.package,
                 "reason": o.reason, "created_at": o.created_at}
                for o in overrides
            ],
            "url_acks": [
                {"package": a.package, "url": a.url,
                 "reason": a.reason, "created_at": a.created_at}
                for a in url_acks
            ],
        }, indent=2))
        return

    if use_rich():
        from ..sandbox.render_client import render

        note = (
            f"{', '.join(sorted(FATAL_RULES))} cannot be overridden; a FATAL "
            f"finding is never suppressed. An acknowledged URL stops scoring "
            f"SOURCE_BUCKET and NOVELTY and stands R152 down for that package "
            f"only."
        )
        emit(render("override_tables", {
            "overrides": [
                {"path": str(OVERRIDES_PATH), "rule_id": o.rule_id,
                 "package": o.package, "reason": o.reason,
                 "created_at": o.created_at}
                for o in overrides
            ],
            "url_acks": [
                {"package": a.package, "url": a.url, "reason": a.reason,
                 "created_at": a.created_at}
                for a in url_acks
            ],
            "note": note,
        }))
    else:
        for o in overrides:
            print(f"{clean(o.rule_id):<8} {clean(o.package or 'all'):<20} "
                  f"{clean(o.reason)}")
        for a in url_acks:
            print(f"{'URL':<8} {clean(a.package):<20} {clean(a.url)}  "
                  f"{clean(a.reason)}")


@override_app.command("add")
def override_add(
    rule_id: str = typer.Argument(..., help="Rule to suppress, e.g. H001"),
    reason: str = typer.Option(..., "--reason", help="Why this rule is being suppressed (required)"),
    package: str | None = typer.Option(
        None, "--package", help="Limit to one package (recommended; omit only together with --global)",
        autocompletion=installed_packages,
    ),
    global_scope: bool = typer.Option(
        False, "--global",
        help="Suppress this rule for ALL packages. Persistent: it also hides "
             "the rule on packages you have not reviewed yet, so this asks "
             "for confirmation (or --yes).",
    ),
    yes: bool = typer.Option(
        False, "--yes", help="Skip the global-scope confirmation prompt",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Disable a detection rule for future changes (a persistent override).

    A package-scoped override (--package) is the recommended path: it hides
    the rule on one package you have reviewed. To acknowledge one specific
    change instead of disabling a rule, use ``override add-url`` (for source
    URLs) or review the finding without an override.
    """
    ensure_default_configs()
    if package and global_scope:
        msg = "--package and --global cannot be combined"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    if package is None and not json_output and not yes:
        # Global scope hides the rule on every package, including ones the
        # operator has never reviewed. Show exactly what is about to happen
        # and ask; --yes and --json are the non-interactive escape hatches,
        # matching the forget command's conventions.
        _print_colored(
            f"Rule: {rule_id.upper()}", "yellow", stderr=True)
        _print_colored(
            "Scope: ALL packages — global (use --package to limit this to "
            "one package)", "yellow", stderr=True)
        _print_colored(f"Reason: {reason}", "yellow", stderr=True)
        try:
            confirm = input(
                "This override disables the rule everywhere. Are you sure? [y/N] ")
        except EOFError:
            _print_colored("Aborted.", "yellow", stderr=True)
            raise typer.Exit(code=2)
        if confirm.lower() not in ("y", "yes"):
            _print_colored("Aborted.", "yellow", stderr=True)
            raise typer.Exit(code=2)
    try:
        ov = add_override(rule_id, reason, package)
    except ValueError as exc:
        msg = str(exc)
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    scope = ov.package or "all packages"
    msg = f"Override added: {ov.rule_id} for {scope}"
    if json_output:
        typer.echo(json.dumps({
            "status": "ok",
            "rule_id": ov.rule_id,
            "package": ov.package,
            "reason": ov.reason,
        }))
    else:
        _print_colored(msg, "green")


@override_app.command("add-url")
def override_add_url(
    package: str = typer.Argument(..., help="Package the URL belongs to"),
    url: str = typer.Argument(..., help="Source URL to acknowledge"),
    reason: str = typer.Option(..., "--reason", help="Why this URL is known (required)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Acknowledge one source URL for one package.

    This is the "I reviewed this particular change" flow: the URL no longer
    scores SOURCE_BUCKET or NOVELTY for this package, and R152 stands down
    for it, while a rule override (``override add``) is the "disable this
    detection for future changes" flow. A different URL, or the same URL in
    another package, is judged as before.

    Note: the URL is normalised before it is stored - version, hash and
    date components are stripped - so this acknowledgement can carry
    across version bumps of the same source.
    """
    ensure_default_configs()
    if not json_output:
        _print_colored(
            "Note: URL acknowledgement strips version/hash/date components, "
            "so it can carry across version bumps of the same source.",
            "yellow", stderr=True,
        )
    try:
        ack = add_url_ack(package, url, reason)
    except ValueError as exc:
        msg = str(exc)
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    if json_output:
        typer.echo(json.dumps({
            "status": "ok",
            "package": ack.package,
            "url": ack.url,
            "reason": ack.reason,
        }))
    else:
        _print_colored(
            f"URL acknowledged: {ack.url} for {ack.package}", "green"
        )


@override_app.command("rm-url")
def override_rm_url(
    package: str = typer.Argument(..., help="Package the URL belongs to"),
    url: str = typer.Argument(..., help="Source URL to stop acknowledging"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Remove an acknowledged source URL."""
    ensure_default_configs()
    if remove_url_ack(package, url):
        msg = f"URL acknowledgement removed: {url} for {package}"
        if json_output:
            typer.echo(json.dumps({
                "status": "ok", "package": package, "url": url,
            }))
        else:
            _print_colored(msg, "green")
    else:
        msg = f"No acknowledgement for {url} in {package}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "yellow")
        raise typer.Exit(code=2)


@override_app.command("wizard")
def override_wizard(
    package: str = typer.Argument(
        ..., help="Package to configure overrides for", autocompletion=installed_packages,
    ),
):
    """Interactive wizard to suppress rules that misfire on a package.

    Every override added here is scoped to this package only - the
    recommended path. Overrides are persistent: they disable the rule for
    future changes of the package. Acknowledging a specific source URL
    (``override add-url``) is the one-off "I reviewed this change" flow.
    """
    ensure_default_configs()
    init_db()

    from ..analysis import analyze_package
    from ..override import get_active_overrides

    from ..sandbox import render_client

    render_client.start_progress(
        "override-analyze", f"Analyzing {package}...", kind="spinner")
    try:
        fact = analyze_package(package)
    except Exception as exc:
        msg = f"Could not analyze '{package}': {exc}"
        _print_colored(msg, "red", stderr=True)
        raise typer.Exit(code=2)
    finally:
        render_client.stop_progress("override-analyze")

    existing = get_active_overrides(package=package)
    existing_ids = {o.rule_id for o in existing}

    non_fatal = [e for e in fact.score_breakdown if e.rule_id not in FATAL_RULES]
    already_suppressed = [e for e in non_fatal if e.rule_id in existing_ids]
    available = [e for e in non_fatal if e.rule_id not in existing_ids]

    if not non_fatal:
        _print_colored(
            f"No suppressible rules triggered for '{package}'. "
            f"(FATAL rules cannot be overridden.)", "yellow")
        return

    if available:
        from ..sandbox.render_client import render

        emit(render("override_wizard_table", {
            "package": package,
            "rows": [
                {"rule_id": e.rule_id, "severity": e.severity, "reason": e.reason}
                for e in available
            ],
            "already_suppressed": [e.rule_id for e in already_suppressed],
        }))
        added = []
        while True:
            try:
                pick = typer.prompt(
                    "Enter rule ID or # to suppress (or q to quit)",
                    default="q",
                    show_default=False,
                )
            except EOFError:
                # stdin is not interactive (piped/CI): stop cleanly.
                _print_colored("Input closed; no more overrides added.", "yellow")
                break
            if pick.lower() in ("q", "quit", ""):
                break

            matched = None
            if pick.isdigit():
                idx = int(pick) - 1
                if 0 <= idx < len(available):
                    matched = available[idx]
            else:
                pick_upper = pick.upper()
                for e in available:
                    if e.rule_id == pick_upper:
                        matched = e
                        break

            if matched is None:
                _print_colored(f"No rule matches '{pick}'. Try again or enter q to quit.", "red")
                continue

            reason = None
            try:
                reason = typer.prompt(f"Reason for suppressing {matched.rule_id}")
            except EOFError:
                _print_colored("Input closed; override not added.", "yellow")
                break
            if not reason or not reason.strip():
                _print_colored("Reason cannot be empty.", "red")
                continue

            add_override(matched.rule_id, reason, package=package)
            added.append(matched.rule_id)
            available = [e for e in available if e.rule_id != matched.rule_id]
            _print_colored(f"Override added: {matched.rule_id} for {package}", "green")

            if not available:
                _print_colored("All suppressible rules have been handled.")
                break

        if added:
            _print_colored(f"Done. Added {len(added)} override(s) for '{package}':", "green")
            for rid in added:
                _print_colored(f"  \u2713 {rid}", "green")
        else:
            _print_colored("No overrides were added.", "yellow")
    else:
        _print_colored(f"All triggered rules for '{package}' are already suppressed.", "yellow")
        if already_suppressed:
            print(f"  Existing: {', '.join(e.rule_id for e in already_suppressed)}")


@override_app.command("rm")
def override_rm(
    rule_id: str = typer.Argument(..., help="Rule to stop suppressing"),
    package: str | None = typer.Option(
        None, "--package", help="Scope the removal to one package",
        autocompletion=installed_packages,
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Remove a rule override."""
    ensure_default_configs()
    if remove_override(rule_id.upper(), package):
        msg = f"Override removed: {rule_id.upper()}"
        if json_output:
            typer.echo(json.dumps({"status": "ok", "rule_id": rule_id.upper()}))
        else:
            _print_colored(msg, "green")
    else:
        msg = f"No matching override for {rule_id.upper()}"
        if json_output:
            typer.echo(json.dumps({"error": msg}))
        else:
            _print_colored(msg, "yellow")
        raise typer.Exit(code=2)


def register_commands(app: typer.Typer):
    """Register the ``override`` subcommand group on *app*."""
    app.add_typer(override_app, name="override")
