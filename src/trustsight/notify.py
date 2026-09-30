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
    scored above the alerting bar, and ``priority`` is "urgent" when the
    list is non-empty: those are the packages outside everything the
    benign corpus does.
    """
    urgent = bool(cycle.over_threshold)
    return {
        "event": "trustsight.alerts",
        "tool": "trustsight",
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
        "over_threshold": [
            {"package": package, "score": score}
            for package, score in cycle.over_threshold
        ],
    }


def post_webhook(url: str, payload: dict, timeout: float = _TIMEOUT_S) -> None:
    """POST *payload* as JSON to *url*.  Raises on any failure.

    An urgent payload carries ntfy's ``Priority: max`` header; receivers
    that are not ntfy ignore it.
    """
    headers = {"Content-Type": "application/json",
               "User-Agent": "trustsight/1.0"}
    if payload.get("priority") == "urgent":
        headers["Priority"] = "5"
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
    if not cycle.new_alerts and not cycle.over_threshold:
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
