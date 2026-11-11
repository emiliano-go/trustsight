"""Simple Rich tables rendered inside the render sandbox.

Each function takes plain data only.  The parent gathers rows, computes any
config-dependent notes, and sends them here.
"""

from __future__ import annotations

from ..safe_text import clean
from .display import (
    RISK_COLORS,
    console,
    score_text,
    severity_text,
    weight_text,
)


def rules_table(*, rows):
    from rich.table import Table

    table = Table(title=f"Rules ({len(rows)} total)")
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("UID", no_wrap=True)
    table.add_column("Category")
    table.add_column("Status")
    for row in rows:
        table.add_row(row["id"], row["uid"], row["category"], row["status"])
    console().print(table)


def list_table(*, rows):
    from rich.table import Table
    from rich.text import Text

    con = console()
    table = Table(title=f"Tracked packages ({len(rows)} total)")
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version")
    table.add_column("Maintainer", overflow="ellipsis")
    table.add_column("Last Checked")
    table.add_column("Score", justify="right")
    table.add_column("Risk")
    for r in rows:
        score = r["score"]
        risk = r["risk"]
        if score is not None:
            score_cell = score_text(score, risk)
        else:
            score_cell = Text("-", style="dim")
        if risk == "-" or risk == "Inconclusive":
            risk_obj = Text(risk, style="yellow")
        else:
            risk_obj = Text(risk, style=RISK_COLORS.get((risk or "").split(" (")[0], "white"))
        table.add_row(
            Text(clean(r["name"])),
            Text(r["version"]),
            Text(clean(r["maintainer"])) if r["maintainer"] else "[dim]-[/]",
            r["last_checked"][:10] if r["last_checked"] else "[dim]-[/]",
            score_cell,
            risk_obj,
        )
    con.print(table)


def history_table(*, package, records, breakdown_rows=None, show_breakdown=False):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table
    from rich.text import Text

    con = console()
    table = Table(title=Text(f"History: {clean(package)}"))
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Date", style="dim")
    table.add_column("Old", justify="right")
    table.add_column("-> New", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Risk")

    for h in records:
        ts = h.get("timestamp", "")[:10] if h.get("timestamp") else ""
        score = h.get("final_score", 0)
        band = h.get("band", "")
        score_cell = Text(f"{score}/100", style=RISK_COLORS.get((band or "").split(" (")[0], "white"))
        risk_cell = Text(clean(band))
        if not h.get("complete", True):
            risk_cell.append(" (incomplete)", style="yellow")
        table.add_row(str(h.get("id", "")), ts, h.get("old_version", ""),
                      h.get("new_version", ""), score_cell, risk_cell)
    con.print(table)

    if show_breakdown:
        if breakdown_rows:
            bd = Table(title="Latest run: rules that fired", box=SIMPLE_HEAD)
            bd.add_column("Rule", style="cyan")
            bd.add_column("Severity")
            for r in breakdown_rows:
                bd.add_row(Text(clean(r["rule_id"])), severity_text(r["severity"]))
            con.print(bd)
        else:
            con.print("[dim]No rules fired on the latest run.[/]")


def config_tables(*, rows, weights):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table
    from rich.text import Text

    table = Table(title="TrustSight configuration", box=SIMPLE_HEAD)
    table.add_column("Key", style="cyan")
    table.add_column("Value", overflow="fold")
    for k, v in rows:
        table.add_row(k, v)
    console().print(table)

    table = Table(title="Scoring weights", box=SIMPLE_HEAD)
    table.add_column("Group", style="dim")
    table.add_column("Key", style="cyan")
    table.add_column("Weight", justify="right")
    for group, key, value in weights:
        try:
            weight_int = int(value)
        except (TypeError, ValueError):
            table.add_row(group, key, Text(str(value), style="dim"))
        else:
            table.add_row(group, key, weight_text(weight_int))
    console().print(table)


def seed_info_table(*, data, salt, algorithm, maint_count):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table
    from rich.text import Text

    table = Table(title="TrustSight seed", box=SIMPLE_HEAD)
    table.add_column("Key", style="cyan")
    table.add_column("Value", overflow="fold")
    table.add_row("Seeded", "Yes" if data["seeded"] else "No")
    table.add_row("Salt", Text(clean(salt or "-")))
    table.add_row("Hash algorithm", Text(clean(algorithm or "-")))
    table.add_row("Hashed maintainers", f"{maint_count:,}")
    table.add_row("Seed observations", f"{data['seed_observations']:,}")
    table.add_row("Seed version", Text(clean(data["seed_version"] or "-")))
    table.add_row("Seed hash", Text(clean(data["seed_hash"] or "-")))
    table.add_row("Seed origin", Text(clean(data["seed_origin"] or "-")))
    console().print(table)


def seed_stats_tables(*, total, with_email, total_packages, sources):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table
    from rich.text import Text

    table = Table(title="Hashed maintainer corpus", box=SIMPLE_HEAD)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Total maintainers", f"{total:,}")
    table.add_row("With email hash", f"{with_email:,}")
    table.add_row("Total package count", f"{int(total_packages):,}")
    console().print(table)
    if sources:
        src_table = Table(title="By source", box=SIMPLE_HEAD)
        src_table.add_column("Source", style="dim")
        src_table.add_column("Count", justify="right")
        for r in sources:
            src_table.add_row(Text(clean(r["source"] or "(none)")), f"{r['count']:,}")
        console().print(src_table)


def seed_imported_table(*, stats, effective):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table

    table = Table(title="Novelty seed imported", box=SIMPLE_HEAD)
    table.add_column("Item", style="dim")
    table.add_column("Count", justify="right")
    table.add_row("Source URLs added", f"{stats['urls_added']:,}")
    table.add_row("Source URLs total", f"{stats['urls_total']:,}")
    table.add_row("Maintainers", f"{stats['maintainers']:,}")
    table.add_row("Bootstrap observations", f"{stats['observations']:,}")
    table.add_row("Effective observations", f"{effective:,}")
    console().print(table)
    console().print(
        "[dim]Maturity now reflects a warm database, so Medium verdicts are "
        "no longer downgraded to INCONCLUSIVE.[/]"
    )


def ioc_sources_table(*, configured, imported, feeds, enabled):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table
    from rich.text import Text

    table = Table(title="IOC baseline sources", box=SIMPLE_HEAD)
    table.add_column("Kind", style="dim")
    table.add_column("Name")
    table.add_column("Status")
    for source in configured:
        table.add_row("configured", Text(clean(source)),
                      "enabled" if enabled else "disabled")
    for source in imported:
        table.add_row("imported", Text(clean(source)), "")
    for feed in feeds:
        table.add_row(
            "feed",
            str(feed.get("name", "")),
            "enabled" if feed.get("enabled", False) else "disabled",
        )
    console().print(table)
    if not configured and not imported:
        console().print(
            "[dim]No sources configured; imported baselines are all "
            "shown unless a configured source restricts them.[/]"
        )


def ioc_list_table(*, entries):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table
    from rich.text import Text

    table = Table(title="IOC baseline entries", box=SIMPLE_HEAD)
    table.add_column("Type", style="dim")
    table.add_column("Value")
    table.add_column("Source")
    table.add_column("Confidence", style="dim")
    for e in entries:
        value = e["value"]
        if e.get("expired"):
            value += " [EXPIRED]"
        table.add_row(Text(clean(e["type"])), Text(clean(value)),
                      Text(clean(e["source"])),
                      Text(clean(e.get("confidence") or "-")))
    console().print(table)


def override_tables(*, overrides, url_acks, note):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table
    from rich.text import Text

    con = console()
    if overrides:
        table = Table(title=f"Rule overrides ({overrides[0]['path']})", box=SIMPLE_HEAD)
        table.add_column("Rule", style="cyan")
        table.add_column("Scope")
        table.add_column("Reason", overflow="fold")
        table.add_column("Added", style="dim")
        for o in overrides:
            table.add_row(Text(clean(o["rule_id"])),
                          Text(clean(o["package"] or "all packages")),
                          Text(clean(o["reason"])), Text(clean(o["created_at"])))
        con.print(table)
    if url_acks:
        table = Table(title="Acknowledged source URLs", box=SIMPLE_HEAD)
        table.add_column("Package", style="cyan")
        table.add_column("URL", overflow="fold")
        table.add_column("Reason", overflow="fold")
        table.add_column("Added", style="dim")
        for a in url_acks:
            table.add_row(Text(clean(a["package"])), Text(clean(a["url"])),
                          Text(clean(a["reason"])), Text(clean(a["created_at"])))
        con.print(table)
    con.print(f"[dim]{note}[/]")


def override_wizard_table(*, package, rows, already_suppressed):
    from rich.box import SIMPLE_HEAD
    from rich.table import Table
    from rich.text import Text

    con = console()
    con.print(f"\n[bold]Triggered rules for [cyan]{clean(package)}[/][/]\n")
    table = Table(box=SIMPLE_HEAD)
    table.add_column("#", style="dim", justify="right")
    table.add_column("Rule", style="cyan")
    table.add_column("Severity")
    table.add_column("Reason", overflow="fold")
    for i, e in enumerate(rows, 1):
        table.add_row(Text(str(i)), Text(clean(e["rule_id"])),
                      Text(clean(e["severity"])), Text(clean(e["reason"])))
    con.print(table)
    if already_suppressed:
        con.print(
            f"\n[dim](Already suppressed: {', '.join(already_suppressed)})[/]"
        )
    con.print()


def pivot_table(*, header, sources, matches):
    from rich.table import Table
    from rich.text import Text

    con = console()
    con.print(Text(clean(header), style="bold cyan"))
    table = Table(show_header=True, header_style="bold")
    table.add_column("Package")
    table.add_column("Surface")
    table.add_column("Reference")
    for match in matches:
        table.add_row(
            Text(clean(match["package"])),
            Text(clean(match["surface"])),
            Text(clean(match["detail"], limit=200)),
        )
    con.print(table)
    con.print(f"[dim]searched: {', '.join(sources)}[/]")


def anergic_table(*, rows):
    from rich.table import Table
    from rich.text import Text

    con = console()
    table = Table(title="Anergic rules (weight 0 pending signal)")
    table.add_column("Rule")
    table.add_column("Status")
    table.add_column("Signal")
    table.add_column("Since")
    table.add_column("Promotion")
    table.add_column("Weight")
    for row in rows:
        table.add_row(
            Text(clean(row["label"])),
            Text(clean(row["status"])),
            Text(clean(row["signal"])),
            Text(clean(row["since"])),
            Text(clean(row["promotion"])),
            Text("-" if row.get("weight") is None else str(row["weight"])),
        )
    con.print(table)


def property_transitions_table(*, package, rows):
    from rich.table import Table
    from rich.text import Text

    con = console()
    table = Table(title=Text(f"Property transitions: {clean(package)}"))
    table.add_column("Date", style="dim")
    table.add_column("Property")
    table.add_column("Old")
    table.add_column("-> New")
    for r in rows:
        old = r.get("old_value")
        table.add_row(
            Text((r.get("observed_at") or "")[:10]),
            Text(clean(r.get("property_key", ""))),
            Text(clean(old) if old is not None else "(none)"),
            Text(clean(r.get("new_value") or "")),
        )
    con.print(table)


def lint_table(*, source, findings, total_rules, errors, warnings, missing, outdated):
    from rich.table import Table
    from rich.text import Text

    con = console()
    if not findings:
        con.print(f"[green]\u2713[/] {total_rules} rules, no issues.")
    else:
        table = Table(title=f"Rule Lint: {source}")
        table.add_column("Rule", style="cyan")
        table.add_column("Level")
        table.add_column("Check", style="dim")
        table.add_column("Message")
        for f in findings:
            style = "red" if f["level"] == "error" else "yellow"
            table.add_row(Text(clean(f["rule_id"])),
                          Text(f["level"], style=style),
                          Text(clean(f["check"])), Text(clean(f["message"])))
        con.print(table)
        con.print(
            f"\n{total_rules} rules checked: "
            f"[red]{len(errors)} error(s)[/], [yellow]{len(warnings)} warning(s)[/]"
        )
    if missing:
        con.print(
            f"\n[yellow]{len(missing)} shipped rule(s) are missing from this file: "
            f"{', '.join(missing)}.\n"
            f"rules.toml is only written when absent, so an existing install "
            f"never receives newly shipped rules.\n"
            f"Run 'trustsight config sync-rules' to append them "
            f"(additive; your edits are preserved).[/]"
        )
    if outdated:
        con.print(
            f"\n[red]{len(outdated)} rule(s) use a superseded pattern: "
            f"{', '.join(outdated)}.\n"
            f"These were corrected upstream. Run 'trustsight config sync-rules --update'.[/]"
        )


def status_table(*, data, dependency_note="", rules_note="", age_note=""):
    from rich.table import Table
    from rich.text import Text

    con = console()
    table = Table(title="TrustSight Status")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    table.add_row("Packages tracked", str(data["packages_tracked"]))
    table.add_row("Total analyses", f"{data['total_analyses']:,}")
    table.add_row("Effective observations", f"{data['effective_observations']:,}")
    table.add_row("Seed observations", f"{data['seed_observations']:,}")
    table.add_row(
        "Dependency corpus",
        Text("Loaded", style="green") if data["dependency_corpus_loaded"]
        else Text("Not loaded", style="yellow"),
    )
    stale = data["stale_rule_patterns"]
    table.add_row(
        "Rule patterns",
        Text("Up to date", style="green") if not stale
        else Text(f"{len(stale)} stale", style="yellow"),
    )
    con.print(table)
    if dependency_note:
        con.print(dependency_note)
    if rules_note:
        con.print(rules_note)
    if age_note:
        con.print(f"[yellow]{age_note}[/]")


def sync_result(*, title, body):
    from rich.panel import Panel

    console().print(Panel(body, title=title, border_style="green"))


def sync_wizard_summary(*, target, missing, outdated, drift, table_rows):
    from rich.panel import Panel
    from rich.table import Table

    con = console()
    parts = []
    if missing:
        parts.append(f"[bold]{len(missing)}[/bold] new rule(s)")
    if outdated:
        parts.append(f"[bold]{len(outdated)}[/bold] outdated pattern(s)")
    if drift:
        parts.append(f"[bold]{len(drift)}[/bold] drifted field(s)")
    con.print(Panel(
        f"Your rules.toml is out of date: {', '.join(parts)}.",
        title=str(target), border_style="yellow",
    ))
    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule", style="cyan", width=8)
    table.add_column("Type", width=12)
    table.add_column("Detail")
    for row in table_rows:
        table.add_row(*row)
    con.print(table)


def sync_menu():
    con = console()
    con.print()
    con.print("[bold]How would you like to sync?[/bold]")
    con.print("  [cyan]1[/cyan]  Full update    (overwrite all rules with shipped defaults)")
    con.print("  [cyan]2[/cyan]  Safe update    (add missing + update superseded patterns only)")
    con.print("  [cyan]3[/cyan]  Skip           (don't change anything)")
    con.print()
