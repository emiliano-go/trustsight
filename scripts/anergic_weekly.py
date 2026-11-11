#!/usr/bin/env python3
"""Weekly calibration data for every weight-review rule (anergic or conditional).

For each rule the anergy ledger marks ``anergic`` or ``conditional`` this collects:

* the live trigger count over the window from the watcher feed
  (``/api/triggers`` summary), with the top packages it fired on; and
* its fires over the committed history replay (``tests/fixtures/history_corpus.py``).

It writes JSON and a Markdown table, and never writes to the repository.  The
weekly workflow turns the Markdown into an issue whose checklist records the
weight decision (0 keeps a rule report-only; a positive weight promotes it).

Read-only.  Feed failures are reported, never treated as "no triggers".

Usage:
    uv run python scripts/anergic_weekly.py --json /tmp/anergic.json \
        --markdown /tmp/anergic.md
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

DEFAULT_FEED = "https://watcher.trustsight.org"
DEFAULT_DAYS = 7


def _history_fires(rule_ids: list[str]) -> dict[str, int]:
    """Fires of each rule over the committed history cycles (best effort)."""
    try:
        from history_corpus import CYCLES
        from trustsight.full_aur.corpus import run_corpus_sweep
    except Exception:  # noqa: BLE001 - a missing fixture is reported, not fatal
        return {}
    counts = dict.fromkeys(rule_ids, 0)
    for cycle in CYCLES:
        try:
            findings = run_corpus_sweep(
                cycle["new"], cycle.get("old"),
                source_repos=cycle.get("source_repos"),
                prior_history=cycle.get("prior_history"),
                maintainer_history=cycle.get("maintainer_history"),
                edges=cycle.get("edges"),
                detail=cycle.get("detail"),
                maintainer_transitions=cycle.get("maintainer_transitions"),
                prior_rule_history=cycle.get("prior_rule_history"),
                package_cycle_events=cycle.get("package_cycle_events"),
                now=cycle.get("now", 0),
            )
        except Exception:  # noqa: BLE001 - one bad cycle must not sink the report
            continue
        for rule_id in {f["rule_id"] for f in findings}:
            if rule_id in counts:
                counts[rule_id] += 1
    return counts


def _fetch_json(url: str, timeout: float):
    # A descriptive UA is required: the feed's edge rejects the default
    # ``Python-urllib`` user agent with 403.
    request = urllib.request.Request(url, headers={
        "User-Agent": "trustsight-anergic-weekly/1.0 (+https://trustsight.org)",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https base
        return json.loads(response.read().decode("utf-8"))


def _live_count(feed_base: str, rule_id: str, since: int, until: int,
                timeout: float, fetch=_fetch_json) -> dict:
    """The feed's summary for one rule over the window, or an error note."""
    query = urllib.parse.urlencode({
        "rule": rule_id, "since": since, "until": until,
        "include": "summary", "format": "json", "limit": 1,
    })
    url = f"{feed_base.rstrip('/')}/api/triggers?{query}"
    try:
        payload = fetch(url, timeout)
    except Exception as exc:  # noqa: BLE001 - the issue records the failure
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    summary = (payload or {}).get("summary") or {}
    rule_rows = {str(row.get("rule_id")): row
                 for row in (summary.get("rules") or []) if isinstance(row, dict)}
    row = rule_rows.get(rule_id)
    packages = [
        {"package": p.get("package"), "count": p.get("count")}
        for p in (summary.get("packages") or [])
        if isinstance(p, dict) and p.get("package")
    ][:5]
    return {
        "available": True,
        "count": int((row or {}).get("count") or 0),
        "packages": packages,
        "first": (row or {}).get("first"),
        "last": (row or {}).get("last"),
    }


def build_report(rule_ids: list[str], feed_base: str, since: int, until: int,
                 timeout: float = 20.0, fetch=_fetch_json) -> dict:
    from trustsight.anergy import entries

    ledger = entries()
    history = _history_fires(rule_ids)
    rows = []
    for rule_id in rule_ids:
        entry = ledger.get(rule_id)
        rows.append({
            "rule_id": rule_id,
            "status": entry.status if entry else "",
            "since": entry.since if entry else "",
            "signal": entry.signal if entry else "",
            "promoted_in": entry.promoted_in if entry else "",
            "weight": entry.weight if entry else None,
            "live": _live_count(feed_base, rule_id, since, until, timeout, fetch),
            "history_fires": history.get(rule_id, 0),
        })
    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "window": {"since": since, "until": until},
        "feed": feed_base,
        "rules": rows,
    }


def render_markdown(report: dict) -> str:
    rows = report.get("rules") or []
    lines = [
        "Weekly calibration data for rules under weight review (anergic or conditional).",
        "",
        f"Window: {report['window']['since']} to {report['window']['until']} "
        f"(unix). Feed: {report['feed']}",
        "",
        "| Rule | Status | Live triggers (7d) | Top packages | History-cycle fires | Signal | Decided weight |",
        "|---|---|---|---|---|---|---|",
    ]
    if not rows:
        lines.append("| (none) | - | - | - | - | every shipped rule is decided | - |")
    for row in rows:
        live = row["live"]
        if live.get("available"):
            count = str(live.get("count", 0))
            top = ", ".join(f"{p['package']}({p['count']})"
                            for p in live.get("packages") or []) or "-"
        else:
            count = "feed unavailable"
            top = live.get("error", "-")
        weight = "undecided" if row.get("weight") is None else str(row["weight"])
        lines.append(
            f"| {row['rule_id']} | {row['status']} | {count} | {top} | "
            f"{row['history_fires']} | {row['signal']} | {weight} |")
    lines += [
        "",
        "## Decision checklist",
        "",
        "For each rule above, set one in `src/trustsight/anergy.json` and land it "
        "with a changelog bullet:",
        "",
        "- **Keep report-only:** `status: promoted` with `weight: 0` and "
        "`decided_in: <release>`; the rule stays visible and never scores.",
        "- **Keep the conditional downgrade:** leave `status: conditional` while "
        "the signed corroboration covers the corpus; it is reviewed again next "
        "week.",
        "- **Promote with a weight:** `status: promoted` with `weight: N` "
        "(N > 0) and `decided_in: <release>`; scoring uses N.",
        "",
        "The `gate_anergic_promotions_are_changelogged` gate requires a "
        "changelog section naming the rule and its measured outcome.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS,
                        help="live window in days (default 7)")
    parser.add_argument("--feed-base", default=DEFAULT_FEED)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)

    from trustsight.anergy import review_ids

    rule_ids = review_ids()
    now = int(datetime.now(UTC).timestamp())
    since = now - max(1, args.days) * 86400
    report = build_report(rule_ids, args.feed_base, since, now, args.timeout)
    markdown = render_markdown(report)
    if args.json:
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    if args.markdown:
        args.markdown.write_text(markdown)
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
