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

import base64
import copy
import hashlib
import json
import logging
import os
import time
import urllib.request

from .bounded_io import read_capped_with_deadline

log = logging.getLogger(__name__)

#: Total wall-clock budget for one POST.  A hung receiver must not stall
#: the next cycle.
_TIMEOUT_S = 15

#: ntfy.sh stores a message larger than its 4096-byte limit as a *file
#: attachment*: the ``message`` field becomes "You received a file: ..." and
#: the document is only reachable through a separate URL whose file expires
#: in a few hours.  A consumer that reads only ``message`` sees the
#: placeholder and the alert is lost - which is why the feed was taught to
#: fetch and retry the attachment URL rather than discard it.  With that in
#: place the document is sent whole (ntfy attaches it above the limit) so the
#: feed keeps every rule, finding and reason; the budget is only a ceiling
#: against a pathological cycle, set below the feed's own 1 MB attachment cap
#: so a document it can still ingest is what the watcher produces.
_MAX_MESSAGE_BYTES = 4096
_PAYLOAD_BUDGET_BYTES = 900_000
#: Findings kept per package before the payload is trimmed further.
_MAX_FINDINGS_PER_PACKAGE = 12

#: The response body is never read for its content; it is drained only so a
#: slow receiver cannot hold the socket open.  64 KiB is far past any
#: plausible webhook acknowledgement.
_MAX_RESPONSE_BYTES = 64 * 1024

#: Reads `[notify] webhook` and `[notify] feed` from config.toml.
_CONFIG_SECTION = "notify"
_CONFIG_KEY = "webhook"
_CONFIG_FEED_KEY = "feed"

#: The signed feed sink.  ``TRUSTSIGHT_FEED_KEY`` is the Ed25519 private key
#: (base64 PKCS#8); ``TRUSTSIGHT_FEED_KEY_ID`` names it so the receiver can
#: rotate.  Absent either, the feed sink is skipped and only ntfy is notified.
_FEED_URL_ENV = "TRUSTSIGHT_FEED_URL"
_FEED_KEY_ENV = "TRUSTSIGHT_FEED_KEY"
_FEED_KEY_ID_ENV = "TRUSTSIGHT_FEED_KEY_ID"


def _cycle_alert_cap() -> int:
    """``[alerts] max_cycle_alerts``: flagged packages a webhook names before
    it degrades to top-K.  0 disables the cap."""
    try:
        from .config import load_config

        alerts = (load_config().get("alerts", {}) or {})
        return max(0, int(alerts.get("max_cycle_alerts", 0) or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _as_int(value, default: int = 0) -> int:
    """*value* as an int, or *default* when it is absent or nonsensical."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _member_list(finding, key: str) -> list:
    """A finding's ``params[key]`` as a list; tolerant of malformed data."""
    if not isinstance(finding, dict):
        return []
    params = finding.get("params", {})
    if not isinstance(params, dict):
        params = {}
    value = params.get(key)
    if isinstance(value, str):
        return [value]
    try:
        return list(value)
    except TypeError:
        return []


def _headline(cycle, detail, iocs, campaign_cluster, impersonation) -> str:
    """A short, deterministic name for the cycle, naming the top signal.

    Same inputs give the same string: every choice is ordered explicitly
    (score, count, then id), so the title never depends on dict iteration or
    arrival order. It names the most significant thing that happened - an
    impersonation campaign, an IOC match, a campaign cluster, an
    over-threshold package, or a rule firing - instead of only counting
    events, and stays short enough for a phone notification header.
    """
    if impersonation:
        camp = max(impersonation, key=lambda c: (c["count"], c["maintainer"]))
        who = camp["maintainer"] or "one submitter"
        return f"impersonation campaign by {who} ({camp['count']} name-clones)"

    if iocs:
        packages = sorted({entry["package"] for entry in iocs})
        if len(iocs) == 1:
            return f"IOC match on {packages[0]}"
        return f"{len(iocs)} IOC matches ({packages[0]} first)"

    if campaign_cluster:
        top = max(campaign_cluster, key=lambda c: (c["count"], c["rule_id"]))
        return f"campaign across {top['count']} packages ({top['rule_id']})"

    refusals = getattr(cycle, "refusals", None) or []
    if refusals:
        pkgs = sorted(refusals)
        if len(pkgs) == 1:
            return f"analysis could not fully read {pkgs[0]}"
        return (f"{len(pkgs)} packages the analysis could not fully read "
                f"({pkgs[0]} first)")

    if cycle.over_threshold:
        ranked = sorted(
            cycle.over_threshold,
            key=lambda item: (-_as_int(item[1] if len(item) > 1 else 0),
                              str(item[0]) if item else ""),
        )
        package, score = ranked[0]
        d = detail.get(package) or {}
        # Lead with the heaviest finding, not the first rule in the list: the
        # list now carries zero-weight declared practices too, and a headline
        # reading "scored 45 (P001)" would name a declaration, not the risk.
        findings = d.get("findings") or []
        ranked_findings = sorted(
            findings,
            key=lambda f: (-_as_int(f.get("weight")), str(f.get("rule_id", ""))),
        )
        rules = ([ranked_findings[0]["rule_id"]] if ranked_findings
                 else (d.get("rules") or []))
        lead = f" ({rules[0]})" if rules else ""
        extra = len(ranked) - 1
        tail = f" +{extra} more" if extra else ""
        return f"{package} scored {score}{lead}{tail}"

    if cycle.new_alerts:
        counts: dict[str, int] = {}
        for _, rule in cycle.new_alerts:
            counts[rule] = counts.get(rule, 0) + 1
        rule = sorted(counts, key=lambda r: (-counts[r], r))[0]
        packages = sorted({package for package, rid in cycle.new_alerts if rid == rule})
        extra = len(cycle.new_alerts) - 1
        tail = f" +{extra} more" if extra else ""
        return f"{rule} on {packages[0]}{tail}"

    return "watcher cycle"


def _refusal_entry(detail: dict | None, package: str) -> dict:
    """One ``refusals`` entry: the package, and the parser findings that made
    the analysis incomplete (X026/X027), so a reader is told what was not read
    rather than only that something was not.
    """
    entry = {"package": package,
             "aur": f"https://aur.archlinux.org/packages/{package}"}
    findings = [
        f for f in ((detail or {}).get("findings") or [])
        if f.get("rule_id") in ("X026", "X027")
    ]
    if findings:
        entry["findings"] = [
            {"rule_id": f.get("rule_id"), "severity": f.get("severity", ""),
             "file": f.get("file", ""), "line": f.get("line"),
             "reason": f.get("reason", "")}
            for f in findings
        ]
        entry["reason"] = findings[0].get("reason") or findings[0].get("rule_id", "")
    return entry


def alert_payload(cycle) -> dict:
    """The JSON document for one cycle's new alerts.

    Counts travel with the alerts so a receiver can tell "three packages
    changed, one alerted" from "three hundred changed, one alerted"
    without asking again.  ``over_threshold`` carries the packages that
    scored above the alerting bar, each with the context a notification is
    for: the version transition, the AUR change date, the rules that
    fired and a link to the package page.  ``priority`` is always
    "default": the urgent tier (ntfy Priority 5) paged at night, which is
    worse than a quiet panel in the morning.  While backfilling, ``day``
    names the AUR day being replayed.
    """
    detail = getattr(cycle, "detail", {}) or {}
    day = getattr(cycle, "backfill_day", "") or ""
    over = []
    for package, score in cycle.over_threshold:
        entry = {"package": package, "score": _as_int(score),
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
        # The located evidence: rule, file, line, severity and rendered
        # reason.  Lets the feed show what line triggered what rule without
        # a second request, and explains tool-emitted pseudo-rules
        # (NOVELTY, SOURCE_BUCKET) that have no published catalog entry.
        if d.get("findings"):
            entry["findings"] = d["findings"]
        over.append(entry)
    # A single noisy cycle must not become an unbounded notification: past
    # ``[alerts] max_cycle_alerts`` the document keeps the top-K by score
    # and reports how many it grouped.  Nothing is dropped from the stored
    # record; only the webhook is bounded (A4 volume variant).
    cycle_cap = _cycle_alert_cap()
    over_grouped = 0
    if cycle_cap > 0 and len(over) > cycle_cap:
        over.sort(key=lambda entry: entry.get("score", 0), reverse=True)
        over_grouped = len(over) - cycle_cap
        over = over[:cycle_cap]
    iocs = [
        {"package": package, "indicator": indicator,
         "aur": f"https://aur.archlinux.org/packages/{package}"}
        for package, indicator in getattr(cycle, "ioc_hits", [])
    ]
    # the G-series campaign clusters, as member triples.
    # The same document shape as over_threshold, so notify plumbing is reused.
    # Only the correlation family belongs here: the sweep also returns
    # weight-0 context findings (H057/H060/H061), and counting those made a
    # centrality pass read as hundreds of "campaign cluster(s)".
    campaign_cluster = []
    for finding in (getattr(cycle, "cluster_findings", None) or ()):
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id", ""))
        members = _member_list(finding, "members")
        # Only a G-series correlation cluster with at least two members is a
        # campaign.  A one-member "cluster" is a single-package signal, not a
        # coordinated set: the sweep emits H061 dependency hubs one member each,
        # and a bulk sweep of them read as "hundreds of campaign cluster(s)".
        # G006 is bounded neighbourhood context, never a campaign either.
        if not rule_id.startswith("G") or rule_id == "G006" or len(members) < 2:
            continue
        campaign_cluster.append({
            "rule_id": rule_id,
            "members": members,
            "count": len(members),
        })
    # An impersonation campaign (G005) is the one alert a reviewer must not
    # skim past: many typosquats of a popular package under one account.
    # Surfaced on its own, ahead of everything, with the maintainer and the
    # impersonated targets named.
    impersonation = [
        {
            "maintainer": (finding.get("params", {}) or {}).get("maintainer", "")
            if isinstance(finding.get("params", {}), dict) else "",
            "members": _member_list(finding, "members"),
            "targets": _member_list(finding, "targets"),
            "count": _as_int((finding.get("params", {}) or {}).get("count")
                             if isinstance(finding.get("params", {}), dict) else 0),
        }
        for finding in (getattr(cycle, "cluster_findings", None) or ())
        if isinstance(finding, dict) and finding.get("rule_id") == "G005"
    ]
    headline = _headline(cycle, detail, iocs, campaign_cluster, impersonation)
    title = f"TrustSight: {headline}"
    if day:
        title += f" ({day})"
    payload = {
        "event": "trustsight.alerts",
        "tool": "trustsight",
        "title": title,
        "priority": "default",
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
        "over_threshold_grouped": over_grouped,
        "ioc_matches": iocs,
        "campaign_cluster": campaign_cluster,
        "impersonation": impersonation,
        # A refusal names a package the analysis could not fully read.  The
        # name alone does not explain *what* was incomplete, so the refusing
        # X026/X027 findings (rule, file, line, reason) ride along; without
        # them a feed can say "could not fully read X" but not why.
        "refusals": [
            _refusal_entry(detail.get(package), package)
            for package in sorted(getattr(cycle, "refusals", None) or [])
        ],
    }
    if day:
        payload["day"] = day
    return _fit_payload(payload)


def _payload_size(payload: dict) -> int:
    """The UTF-8 byte length of *payload* as it is POSTed."""
    return len(json.dumps(payload).encode("utf-8"))


def _fit_payload(payload: dict) -> dict:
    """Bound a pathological document; a normal one is sent whole.

    The feed fetches the attachment ntfy produces for a document over its
    4096-byte limit (and retries a transient fetch), so detail is no longer
    traded away to stay inline.  This only fires for a cycle far past any
    real one - north of ``_PAYLOAD_BUDGET_BYTES`` - where it sheds the least
    essential detail, in order: the human ``reason`` strings (the rule catalog
    still explains a rule id), then findings beyond a small per-package cap,
    then findings entirely (``rules`` and the counts remain), then the
    lowest-scoring over-threshold entries.  The headline, counts, packages,
    rules, campaigns, IOCs and refusals always survive.
    """
    if _payload_size(payload) <= _PAYLOAD_BUDGET_BYTES:
        return payload
    out = copy.deepcopy(payload)

    for entry in out.get("over_threshold", ()) or ():
        for finding in entry.get("findings", ()) or ():
            finding.pop("reason", None)
    if _payload_size(out) <= _PAYLOAD_BUDGET_BYTES:
        return out

    for entry in out.get("over_threshold", ()) or ():
        findings = entry.get("findings")
        if isinstance(findings, list) and len(findings) > _MAX_FINDINGS_PER_PACKAGE:
            entry["findings_truncated"] = len(findings) - _MAX_FINDINGS_PER_PACKAGE
            entry["findings"] = findings[:_MAX_FINDINGS_PER_PACKAGE]
    if _payload_size(out) <= _PAYLOAD_BUDGET_BYTES:
        return out

    for entry in out.get("over_threshold", ()) or ():
        findings = entry.get("findings")
        if findings:
            entry["findings_truncated"] = len(findings)
            del entry["findings"]
    if _payload_size(out) <= _PAYLOAD_BUDGET_BYTES:
        return out

    # The over_threshold list is worst-first, so drop from the tail.
    over = out.get("over_threshold", [])
    while len(over) > 1 and _payload_size(out) > _PAYLOAD_BUDGET_BYTES:
        over.pop()
        out["over_threshold_grouped"] = int(out.get("over_threshold_grouped", 0)) + 1
    return out


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


# Alerts never carry Priority: the urgent tier (5) pages at night, which
# is worse than a quiet panel in the morning.  The heartbeat alone stays low.
_PRIORITY_HEADERS = {
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


def feed_url(config: dict | None = None) -> str:
    """The feed ingest URL: ``TRUSTSIGHT_FEED_URL``, else ``[notify] feed``.

    The environment wins so a container configures the whole sink from its
    compose environment, without editing ``config.toml``.
    """
    env = os.environ.get(_FEED_URL_ENV, "").strip()
    if env:
        return env
    if config is None:
        from .config import load_config

        config = load_config()
    section = config.get(_CONFIG_SECTION) or {}
    return str(section.get(_CONFIG_FEED_KEY) or "").strip()


def _feed_key() -> tuple[str, str]:
    """``(key_id, base64_pkcs8)`` from the environment, or ``("", "")``."""
    return (os.environ.get(_FEED_KEY_ID_ENV, "").strip(),
            os.environ.get(_FEED_KEY_ENV, "").strip())


def _sign_feed(key_b64: str, key_id: str, body: bytes) -> dict:
    """The signature headers for *body* (material ``id.timestamp.body``).

    The id is deterministic from the body and the timestamp, so a retried POST
    carries the same id and the feed dedupes it rather than double-storing.
    """
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    timestamp = int(time.time())
    webhook_id = hashlib.sha256(f"{timestamp}.".encode() + body).hexdigest()
    key = load_der_private_key(base64.b64decode(key_b64), password=None)
    signature = key.sign(f"{webhook_id}.{timestamp}.".encode() + body)
    return {
        "webhook-id": webhook_id,
        "webhook-timestamp": str(timestamp),
        "webhook-key-id": key_id,
        "webhook-signature": "v1=" + base64.b64encode(signature).decode(),
    }


def post_feed(url: str, payload: dict, key_b64: str, key_id: str,
              timeout: float = _TIMEOUT_S) -> None:
    """POST a signed document to the feed ingest endpoint.  Raises on failure."""
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "trustsight/1.0"}
    headers.update(_sign_feed(key_b64, key_id, body))
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        read_capped_with_deadline(resp, _MAX_RESPONSE_BYTES, url, timeout)


def _deliver(payload: dict, ntfy_url: str | None) -> bool:
    """POST *payload* to every configured sink; True when any took it.

    ntfy and the signed feed are independent: one failing never stops the
    other, and a missing feed URL or key simply skips the feed sink.
    """
    delivered = False
    if ntfy_url:
        try:
            post_webhook(ntfy_url, payload)
            delivered = True
        except Exception as exc:  # noqa: BLE001 - a notification never kills the loop
            log.warning("alert webhook failed: %s", exc)
    feed = feed_url()
    key_id, key = _feed_key()
    if feed and key:
        try:
            post_feed(feed, payload, key, key_id)
            delivered = True
        except Exception as exc:  # noqa: BLE001
            log.warning("feed webhook failed: %s", exc)
    return delivered


def maybe_notify(cycle, url: str | None = None) -> bool:
    """POST the cycle's alerts to every sink, if there is anything to say.

    *url* overrides the configured ntfy webhook.  Returns True when any sink
    delivered.  Every failure (no URL, no alerts, a dead receiver) is quiet by
    design: the watcher's job is the next cycle.
    """
    if not cycle.new_alerts and not cycle.over_threshold \
            and not getattr(cycle, "ioc_hits", []) \
            and not getattr(cycle, "refusals", []):
        return False
    return _deliver(alert_payload(cycle),
                    url if url is not None else notify_url())


def maybe_heartbeat(cycle, url: str | None = None) -> bool:
    """POST the low-priority alive beat to every sink.

    ``full-aur --watch`` sends one for every cycle that raised no alert, so the
    cadence decision belongs to the caller and silence on the channel means the
    watcher is dead rather than quiet.  Same failure policy as the alerts:
    logged, swallowed, never fatal to the loop.
    """
    return _deliver(heartbeat_payload(cycle),
                    url if url is not None else notify_url())
