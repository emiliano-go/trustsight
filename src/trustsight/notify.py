"""Webhook notifications for new watch-cycle alerts.

``full-aur --watch`` announces a cluster the first time it is seen and
then goes quiet about it; an unattended watcher therefore needs a push
channel, or the announcement scrolls past nobody.  The channel is one
HTTPS POST of a JSON document per cycle that produced new alerts - generic
enough for any webhook receiver, and ntfy accepts the same POST and shows
the document as the message text.

The watcher must never die because a notification did: every failure here
is logged and swallowed by :func:`maybe_notify`.
"""

import json
import logging
import time
import urllib.request

from .bounded_io import read_capped_with_deadline

log = logging.getLogger(__name__)

#: Total wall-clock budget for one POST.  A hung receiver must not stall
#: the next cycle.
_TIMEOUT_S = 15

#: The response body is never read for its content; it is drained only so a
#: slow receiver cannot hold the socket open.  64 KiB is far past any
#: plausible webhook acknowledgement.
_MAX_RESPONSE_BYTES = 64 * 1024

#: Reads `[notify] webhook` from config.toml.
_CONFIG_SECTION = "notify"
_CONFIG_KEY = "webhook"


def alert_payload(cycle) -> dict:
    """The JSON document for one cycle's new alerts.

    Counts travel with the alerts so a receiver can tell "three packages
    changed, one alerted" from "three hundred changed, one alerted"
    without asking again.  ``over_threshold`` carries the packages that
    scored above the alerting bar, each with the context a notification is
    for: the version transition, the AUR change date, the rules that
    fired and a link to the package page.  ``priority`` is "urgent" when
    the list is non-empty: those are the packages outside everything the
    benign corpus does.  While backfilling, ``day`` names the AUR day
    being replayed.
    """
    urgent = bool(cycle.over_threshold) or bool(getattr(cycle, "ioc_hits", []))
    detail = getattr(cycle, "detail", {}) or {}
    day = getattr(cycle, "backfill_day", "") or ""
    over = []
    for package, score in cycle.over_threshold:
        entry = {"package": package, "score": score,
                 "aur": f"https://aur.archlinux.org/packages/{package}"}
        d = detail.get(package) or {}
        if d.get("old_version") or d.get("new_version"):
            entry["version"] = (
                f"{d.get('old_version') or '?'} -> {d.get('new_version') or '?'}"
            )
        if d.get("last_modified"):
            entry["last_modified"] = time.strftime(
                "%Y-%m-%d %H:%M UTC", time.gmtime(d["last_modified"]))
        if d.get("rules"):
            entry["rules"] = d["rules"]
        over.append(entry)
    iocs = [
        {"package": package, "indicator": indicator,
         "aur": f"https://aur.archlinux.org/packages/{package}"}
        for package, indicator in getattr(cycle, "ioc_hits", [])
    ]
    n_alerts = len(cycle.new_alerts)
    parts = []
    if iocs:
        parts.append(f"{len(iocs)} IOC match(es)")
    if cycle.over_threshold:
        parts.append(f"{len(cycle.over_threshold)} package(s) over threshold")
    if n_alerts:
        parts.append(f"{n_alerts} new alert(s)")
    title = "TrustSight: " + ", ".join(parts)
    if day:
        title += f" ({day})"
    payload = {
        "event": "trustsight.alerts",
        "tool": "trustsight",
        "title": title,
        "priority": "urgent" if urgent else "default",
        "cycle": {
            "added": cycle.added,
            "changed": cycle.changed,
            "removed": cycle.removed,
            "processed": cycle.processed,
        },
        "alerts": [
            {"package": package, "rule_id": rule_id}
            for package, rule_id in cycle.new_alerts
        ],
        "over_threshold": over,
        "ioc_matches": iocs,
    }
    if day:
        payload["day"] = day
    return payload


def heartbeat_payload(cycle) -> dict:
    """The low-priority daily "still watching" document.

    Silence on the alert channel is ambiguous between "nothing found" and
    "the watcher is dead"; a beat a day makes the two distinguishable.
    """
    title = "TrustSight: alive"
    day = getattr(cycle, "backfill_day", "") or ""
    if day:
        title += f" (replay at {day})"
    payload = {
        "event": "trustsight.heartbeat",
        "tool": "trustsight",
        "title": title,
        "priority": "low",
        "cycle": {
            "added": cycle.added,
            "changed": cycle.changed,
            "removed": cycle.removed,
            "processed": cycle.processed,
        },
    }
    if day:
        payload["day"] = day
    return payload


_PRIORITY_HEADERS = {
    "urgent": {"Priority": "5", "Tags": "rotating_light"},
    "low": {"Priority": "2", "Tags": "hourglass"},
    "default": {"Tags": "eye"},
}


def post_webhook(url: str, payload: dict, timeout: float = _TIMEOUT_S) -> None:
    """POST *payload* as JSON to *url*.  Raises on any failure.

    The payload's own title and priority become ntfy headers; receivers
    that are not ntfy ignore them.
    """
    headers = {"Content-Type": "application/json",
               "User-Agent": "trustsight/1.0"}
    if payload.get("title"):
        headers["Title"] = payload["title"]
    headers.update(_PRIORITY_HEADERS.get(payload.get("priority", "default"), {}))
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        # Drain the body under a byte cap and the same deadline: an
        # unbounded read here would let a slow-drip receiver stall the
        # watcher past the timeout.
        read_capped_with_deadline(resp, _MAX_RESPONSE_BYTES, url, timeout)


def notify_url(config: dict | None = None) -> str:
    """The configured webhook URL, or "" when none is set."""
    if config is None:
        from .config import load_config

        config = load_config()
    section = config.get(_CONFIG_SECTION) or {}
    return str(section.get(_CONFIG_KEY) or "").strip()


def maybe_notify(cycle, url: str | None = None) -> bool:
    """POST the cycle's alerts to the webhook, if there is anything to say.

    *url* overrides the configured webhook.  Returns True when a
    notification was delivered.  Every failure (no URL, no alerts, a dead
    receiver) is quiet by design: the watcher's job is the next cycle.
    """
    if not cycle.new_alerts and not cycle.over_threshold \
            and not getattr(cycle, "ioc_hits", []):
        return False
    url = url if url is not None else notify_url()
    if not url:
        return False
    try:
        post_webhook(url, alert_payload(cycle))
    except Exception as exc:  # noqa: BLE001 - a notification never kills the loop
        log.warning("alert webhook failed: %s", exc)
        return False
    return True


#: One heartbeat a day.  Silence on the alert channel is ambiguous between
#: "nothing found" and "the watcher is dead"; this makes the two
#: distinguishable without spamming the panel.
HEARTBEAT_SECONDS = 86400


def maybe_heartbeat(cycle, url: str | None = None) -> bool:
    """POST the low-priority alive beat to the webhook.

    The cadence decision belongs to the caller (run_watch), so a day with
    no cycles simply beats on the next one.  Same failure policy as the
    alerts: logged, swallowed, never fatal to the loop.
    """
    url = url if url is not None else notify_url()
    if not url:
        return False
    try:
        post_webhook(url, heartbeat_payload(cycle))
    except Exception as exc:  # noqa: BLE001 - a notification never kills the loop
        log.warning("heartbeat webhook failed: %s", exc)
        return False
    return True
