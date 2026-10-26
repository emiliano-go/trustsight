"""Bootstrap and incremental corpus pipeline."""

import difflib
import hashlib
import json
import logging
import os
import signal as _signal
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

try:
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.console import Console

    _HAS_RICH = True
except ImportError:  # pragma: no cover - rich is a dependency, but degrade gracefully
    _HAS_RICH = False

from ..analysis.base import _ensure_init
from ..config import load_config, load_naming
from ..db import (
    activate_campaign,
    active_campaigns,
    brand_new_packages_since,
    checkpoint_wal,
    clear_correlation_feeds,
    get_connection,
    get_metadata,
    record_alerts,
    get_package_profile,
    get_pkgbuild_snapshot,
    get_previous_pkgbuild_snapshot,
    latest_cycle_time,
    record_cycle_events,
    record_upstream_dep_additions,
    is_reserved_name,
    save_package_profile,
    save_pkgbuild_snapshot,
    set_metadata,
    write_batch,
)
from ..deps import normalize_dependency
from ..safe_text import clean, clean_log
from ..schema import TemporalContext
from ..scoring import risk_level
from ..tokenizer import TokenizerUnavailable
from ..depth import MAX_DEPTH_NODES
from .analyze import analyze_package_text
from .corpus import run_corpus_sweep, source_repos_from_pkgbuild
from .fetch import (
    clear_resume_state,
    fetch_pkgbuild_with_tree,
    load_resume_state,
    save_resume_state,
)
from .metadata import (
    diff_metadata,
    fetch_metadata,
    load_metadata,
    save_metadata,
)

log = logging.getLogger(__name__)

# Score 40 sits in the upper half of the Medium band (scoring.risk_level:
# Low <= 20, Medium 21-50, High 51-80, Critical 81-100); a cycle names the
# packages that reached it rather than leaving them in the database for
# someone to notice later.
_FLAGGED_SCORE = 40

# The benign corpus's measured p95, from published-figures.json
# (`calibration.benign_p95 = 30`): a score strictly past it is outside 95% of
# what the benign corpus does, which is the bar a watcher's alert should use.
# The comparison is `score > _OVER_BENIGN_P95`, so a value of 30 alerts on
# scores of 31+.  `flagged` stays at 40 (the report bar); this is the lower,
# alerting bar.  (The 20-point review threshold and its 7.6% benign rate are a
# separate, stricter review-workload policy, see scoring.FLAG_THRESHOLD.)
_OVER_BENIGN_P95 = 30

# One day of AUR time per backfill cycle (see run_baseline_build's *since*).
_SINCE_DAY_SECONDS = 86400
_SINCE_CURSOR_KEY = "since_cursor"
_SINCE_ORIGIN_KEY = "since_origin"

# How many of them one cycle prints.  A bootstrap analyses the whole AUR,
# and an unbounded list would bury the cluster findings under it.
_FLAGGED_REPORT_LIMIT = 10

# Cluster rules that describe the corpus for prioritisation and must not
# alert: H057 (a transitive orphan), H060 (a live orphan in the closure) and
# H061 (a centrality hub) are weight-0 context, and a sweep emits hundreds of
# H061 hubs at once.  Passing them to record_alerts made a routine sweep read
# as "226 campaign cluster(s) ... 226 new alert(s)".
_NON_ALERTING_CLUSTER_RULES = frozenset({"H057", "H060", "H061", "G006", "G010"})

#: Burst/share clusters that fire on legitimate variant families as readily
#: as on a typosquat campaign.  They score and alert only when one of their
#: members impersonates a far-more-popular package (the corpus H029 check);
#: otherwise they are context.  Without this, a maintainer updating six of
#: their own packages reads as a campaign.
_IMPERSONATION_GATED_RULES = frozenset({"H052", "H055"})

#: G rules that corroborate a campaign.  The report-only members of the
#: family (G006/G007/G009/G010) never prime campaign state.
_CAMPAIGN_RULES = frozenset(
    {"G001", "G002", "G003", "G004", "G005", "G008", "G011",
     "G012", "G013", "G014"})

#: The analysed diff a notification may carry.  The notification already has
#: a total payload budget; this is the per-package bound before the total
#: trimmer drops it.  A large rewrite degrades to the digests, not to a lost
#: alert.
_MAX_NOTIFY_DIFF_BYTES = 32 * 1024


def _recipe_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def _notify_diff(old_text: str, new_text: str) -> dict:
    """A bounded, inert unified diff for the notification document.

    The diff is attacker-controlled text.  ``clean_log`` removes escape
    sequences, C0/C1 controls and bidi overrides while keeping the newlines
    and tabs a diff needs; the feed renders the result as text.  A diff over
    the budget travels as its digest only, never as a silently truncated
    patch a reader could mistake for the whole change.

    ``diff_sha256`` is over the sanitized text a reader sees; the exact byte
    identity of the recipe is ``pkgbuild_sha256`` on the detail entry.  Keeping
    the two separate means stripping a bidi override for display cannot be
    mistaken for changing the analysed evidence.
    """
    if not old_text and not new_text:
        return {}
    if old_text == new_text:
        return {}
    old_lines = old_text.split("\n")
    new_lines = new_text.split("\n")
    if old_lines and old_lines[-1] == "":
        old_lines.pop()
    if new_lines and new_lines[-1] == "":
        new_lines.pop()
    lines = list(difflib.unified_diff(
        old_lines, new_lines,
        fromfile="a/PKGBUILD", tofile="b/PKGBUILD", lineterm=""))
    text = clean_log("\n".join(lines))
    out = {"diff_sha256": _recipe_digest(text)}
    if len(text.encode("utf-8")) <= _MAX_NOTIFY_DIFF_BYTES:
        out["diff"] = text
    else:
        out["diff_truncated"] = True
    return out


def _since_cursor() -> Optional[int]:
    """The active backfill cursor (unix seconds), or None when not replaying."""
    raw = get_metadata(_SINCE_CURSOR_KEY)
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _set_since_cursor(value: Optional[int]) -> None:
    set_metadata(_SINCE_CURSOR_KEY, "" if value is None else str(value))


def _meta_snapshot_path() -> Path:
    """Where this run reads and writes the metadata snapshot.

    Resolved through metadata.default_metadata_path() so the bootstrap, the
    exporter and ``review`` all agree; it used to be relative to the working
    directory here, which meant a snapshot written by one command was
    invisible to the other.
    """
    from .metadata import default_metadata_path

    return default_metadata_path()


def _pkg_or_base(meta: dict) -> str:
    """Return the package base name for metadata lookups.

    Most AUR packages have the same Name and PackageBase.  For split
    packages the PKGBUILD lives under the PackageBase.
    """
    return meta.get("PackageBase") or meta["Name"]


def _record_cycle_feed(
    new_meta: dict,
    old_meta: Optional[dict],
    added: list[str],
    changed: list[str],
    removed: list[str],
) -> None:
    """Record this cycle's introduction events into the Class D adoption feed.

    The feed is the per-cycle diff stream that H073's introduction-rate
    baseline is derived from.  A fresh bootstrap records the whole corpus as
    cycle 1.
    """
    cycle_ts = latest_cycle_time() + 1
    events: list[dict] = []
    for name in added:
        meta = new_meta.get(name) or {}
        events.append(
            {
                "package_name": name,
                "cycle_time": cycle_ts,
                "status": "added",
                "maintainer": meta.get("Maintainer") or "",
                "last_modified": meta.get("LastModified"),
            }
        )
    for name in changed:
        meta = new_meta.get(name) or {}
        events.append(
            {
                "package_name": name,
                "cycle_time": cycle_ts,
                "status": "modified",
                "maintainer": meta.get("Maintainer") or "",
                "last_modified": meta.get("LastModified"),
            }
        )
    for name in removed:
        meta = (old_meta or {}).get(name) or {}
        events.append(
            {
                "package_name": name,
                "cycle_time": cycle_ts,
                "status": "removed",
                "maintainer": meta.get("Maintainer") or "",
                "last_modified": meta.get("LastModified"),
            }
        )
    if events:
        record_cycle_events(events)


def _profile_score(name: str, scores: dict[str, int]) -> int:
    """Current profile score for *name* from the in-memory map or the DB."""
    if name in scores:
        return scores[name]
    with get_connection() as conn:
        row = conn.execute(
            "SELECT last_score FROM package_profiles WHERE package_name = ?",
            (name,),
        ).fetchone()
    return row[0] if row and row[0] is not None else 0


#: Cap on the AUR-popularity candidate list H029 compares against.  The
#: dependency path caps at 5000 too; this list is ordered by votes, so the
#: cap keeps the names worth impersonating.
_H029_POPULARITY_CANDIDATE_LIMIT = 5000


def _popular_candidates(new_meta: dict) -> list[tuple[str, int]]:
    """AUR packages worth impersonating, as ``(name, NumVotes)``.

    The corpus H029 check compares a new package name against this instead
    of the dependency index, which never holds AUR helpers or apps (``yay``,
    ``paru``, a browser) - exactly the typosquat targets.  Built once per
    cycle from the metadata snapshot: names at or above
    ``[naming] h029_popularity_floor`` votes, most-voted first, capped.
    """
    floor = int(
        load_naming().get("naming", {}).get("h029_popularity_floor", 100) or 100
    )
    pairs = [
        (name, int((meta or {}).get("NumVotes", 0) or 0))
        for name, meta in new_meta.items()
    ]
    pairs = [pair for pair in pairs if pair[1] >= floor]
    pairs.sort(key=lambda pair: (-pair[1], pair[0]))
    return pairs[:_H029_POPULARITY_CANDIDATE_LIMIT]


def _impersonates(
    name: str, meta: Optional[dict], candidates: list[tuple[str, int]]
) -> str:
    """The popular package *name* impersonates, or ``""``.

    One helper for the per-package H029 check and the cycle-level campaign
    aggregation, so the two cannot disagree about which member is a clone.
    """
    from ..novelty import package_typosquat_match

    votes = int((meta or {}).get("NumVotes", 0) or 0)
    match = package_typosquat_match(
        name, candidates=candidates, self_popularity=votes
    )
    return match[0] if match else ""


def _campaign_identity(finding: dict) -> tuple[str, dict[str, list[str]]] | None:
    """``(campaign_id, typed_scope)`` for a corroborated cluster, or None.

    Only G-series clusters corroborate a campaign.  The scope is **typed**, so
    a reader knows what a value *is*: a set of package names cannot be
    compared against a set of hosts.  The untyped list this replaced stored
    package members for every rule and then compared them against gained
    hosts, which is why G006 never fired.

    * ``package_names`` - the campaign's members.
    * ``hosts`` - the shared/gained hosts a host campaign joins on.
    * ``dependencies`` - the upstream dependency a G004 campaign joins on.
    * ``signals`` - the payload rule a G012 campaign joins on.
    * ``urls`` - the canonical payload URL a G013 campaign joins on.
    * ``maintainers`` - the accounts a multi-account campaign names.
    * ``targets`` - the legitimate packages a G005 campaign impersonates.
      These are **not** members: a clone is suspicious because it targets
      ``yay``, not because ``yay`` exists.
    """
    if not isinstance(finding, dict):
        return None
    rule_id = str(finding.get("rule_id", ""))
    # Only corroborating G rules prime campaign state.  G006/G007 are
    # report-only context, G009 is the operator's watchlist (a human note,
    # not a detected cluster) and G010 is a first-seen-host census.  Letting
    # any of them activate a campaign would spend a bounded
    # `max_active_campaigns` slot on a weight-0 observation and could refuse
    # a real cluster (A14, campaign state).
    if rule_id not in _CAMPAIGN_RULES:
        return None
    params = finding.get("params", {}) or {}
    if not isinstance(params, dict):
        params = {}

    def _seq(value):
        """A param's member/target list; a bare string is one value."""
        if isinstance(value, str):
            return [value]
        try:
            return list(value)
        except TypeError:
            return []

    members = sorted({str(m) for m in _seq(params.get("members"))})
    if rule_id == "G005":
        key = str(params.get("maintainer", "") or "unknown")
        targets = sorted({str(t) for t in _seq(params.get("targets"))})
        return f"g005:{key}", {"package_names": members, "targets": targets}

    scope: dict[str, list[str]] = {"package_names": members}
    host = str(params.get("host", "") or "")
    if host:
        scope["hosts"] = [host]
    dependency = str(params.get("dependency", "") or "")
    if dependency:
        scope["dependencies"] = [dependency]
    signal = str(params.get("signal", "") or "")
    if signal:
        scope["signals"] = [signal]
    url = str(params.get("url", "") or "")
    if url:
        scope["urls"] = [url]
    accounts = sorted({
        str(m).strip().lower() for m in _seq(params.get("maintainers"))
        if str(m).strip()
    })
    if accounts:
        scope["maintainers"] = accounts
    if rule_id == "G004":
        # G004 joins on the (name, host) pair; keying on the name alone
        # collapsed two different remotes that happen to share a name.
        key = f"{dependency}:{host}"
    elif rule_id == "G012":
        key = signal
    elif rule_id == "G013":
        key = url
    elif rule_id == "G014":
        key = "adoption-window"
    else:
        key = (params.get("host") or params.get("literal")
               or params.get("literal_sha256")
               or params.get("dependency") or params.get("maintainer") or "")
    # The key carries a host or maintainer the input chose.  Bound it and
    # strip control characters before it becomes a database key and a log
    # field; a legitimate value is unchanged (A10, A14).
    key = clean(str(key))[:200]
    return f"{rule_id}:{key}", scope


def _activate_campaigns(findings: list[dict], config: dict, log=None) -> list[str]:
    """Prime campaign state for every corroborated cluster this cycle.

    A campaign is instrument state: it is written only by corroborated
    findings on recorded cycles, never by a package, and it expires on the
    observation clock (A11).  Bounded by ``[alerts] max_active_campaigns``;
    a live TTL is never shortened.

    Returns the campaign ids the cap **refused**.  Campaign mode is temporary
    memory, and silently failing to remember a new campaign would violate the
    transparency the mechanism is built around, so the caller reports each
    refusal rather than dropping it.

    A class that re-arms faster than
    ``[alerts] campaign_min_reactivation_observations`` is still refreshed -
    the window is never shortened - but the churn is surfaced as an M006
    tool-health note rather than passed over in silence.
    """
    alerts = (config or {}).get("alerts", {}) or {}
    try:
        max_active = int(alerts.get("max_active_campaigns", 8) or 0)
    except (TypeError, ValueError, OverflowError):
        max_active = 8
    try:
        ttl = int(alerts.get("campaign_ttl_observations", 40) or 40)
    except (TypeError, ValueError, OverflowError):
        ttl = 40
    refused: list[str] = []
    for finding in findings or ():
        identity = _campaign_identity(finding)
        if identity is None:
            continue
        campaign_id, scope = identity
        activated = activate_campaign(
            campaign_id, scope, str(finding.get("rule_id", "")),
            ttl_obs=ttl, max_active=max_active)
        # The id is public notification data: it is what makes a campaign one
        # durable object across cycles.  Attach it to the finding so the
        # payload does not have to recompute the identity from a scope the
        # feed never sees.  A refused activation is still a detected cluster;
        # mark it inactive rather than hiding the evidence.
        params = finding.setdefault("params", {})
        if isinstance(params, dict):
            params["campaign_id"] = campaign_id
            params["campaign_active"] = bool(activated)
        if not activated:
            refused.append(campaign_id)
    _report_reactivation_pressure(alerts, log)
    return refused


def _report_reactivation_pressure(alerts: dict, log) -> None:
    """M006: surface a campaign class that re-armed faster than the interval.

    Instrument health, not a package finding: a class churning is the tool
    re-priming the same shape over and over, which the spec routes to a
    tool-health signal.  Weight 0 and never attributed to a package.
    """
    if log is None:
        return
    try:
        min_interval = int(
            (alerts or {}).get("campaign_min_reactivation_observations", 5) or 0)
    except (TypeError, ValueError, OverflowError):
        min_interval = 5
    if min_interval <= 0:
        return
    from ..analysis.meta import campaign_reactivation_notes
    from ..db import reactivation_pressure

    for note in campaign_reactivation_notes(
            reactivation_pressure(min_interval)):
        # A campaign id embeds the host or maintainer the cluster joined on,
        # so the note is package-controlled text reaching a terminal (A10).
        log.warning("%s: %s", clean(str(note["rule_id"])),
                    clean(str(note["match"])))


def _report_expired_campaigns(log) -> None:
    """Report each lapsed campaign once, then mark it announced.

    Silence about a campaign that ended is ambiguous between "no campaign"
    and "a campaign lapsed": the lapse is named, the way an expired
    indicator is, and never re-reported.
    """
    from ..db import expired_unannounced, mark_expiry_announced

    for campaign in expired_unannounced():
        log(clean(f"campaign {campaign['campaign_id']} lapsed after "
                  f"{campaign['ttl_obs']} observation(s); no longer priming runs"))
        mark_expiry_announced(campaign["campaign_id"])


def _neighborhood_elevation(records: list[dict]) -> list[dict]:
    """G006: a package stands in an active campaign's neighbourhood (weight 0).

    The cytokine effect: an alerted neighbourhood raises the tissue's
    readiness.  Reported, never scored, and it never forbids a clean verdict.
    The neighbourhood is **typed**, never conflated:

    * **host** - the record *gains* a host in a campaign's ``hosts``.  Only
      gained hosts count, so a package that already had the host is not
      newly elevated.
    * **target** - the record's own ``impersonated_target`` is a package a
      G005 campaign impersonates: this is a *new clone* of that target.  The
      legitimate target itself is not elevated for merely existing.

    A package that is itself a campaign member is excluded: it is the
    campaign, not a neighbour of it.
    """
    campaigns = active_campaigns()
    if not campaigns:
        return []
    host_to_campaign: dict[str, str] = {}
    target_to_campaign: dict[str, str] = {}
    signal_to_campaign: dict[str, str] = {}
    url_to_campaign: dict[str, str] = {}
    maintainer_to_campaign: dict[str, str] = {}
    members_of: dict[str, set[str]] = {}
    for campaign in campaigns:
        scope = campaign.get("scope", {}) or {}
        if not isinstance(scope, dict):
            scope = {}
        campaign_id = campaign["campaign_id"]
        members_of[campaign_id] = {
            str(n) for n in scope.get("package_names", ()) or ()}
        for host in scope.get("hosts", ()) or ():
            host_to_campaign.setdefault(str(host), campaign_id)
        for target in scope.get("targets", ()) or ():
            target_to_campaign.setdefault(str(target), campaign_id)
        for signal in scope.get("signals", ()) or ():
            signal_to_campaign.setdefault(str(signal), campaign_id)
        for url in scope.get("urls", ()) or ():
            url_to_campaign.setdefault(str(url), campaign_id)
        for account in scope.get("maintainers", ()) or ():
            maintainer_to_campaign.setdefault(str(account), campaign_id)

    by_campaign: dict[str, set[str]] = {}
    reasons: dict[str, set[str]] = {}

    def _elevate(campaign_id: str, package: str, reason: str) -> None:
        if campaign_id and package not in members_of.get(campaign_id, ()):
            by_campaign.setdefault(campaign_id, set()).add(package)
            reasons.setdefault(campaign_id, set()).add(reason)

    for record in records or ():
        if not isinstance(record, dict):
            continue
        package = str(record.get("package", ""))
        gained = record.get("hosts_gained") or ()
        if isinstance(gained, str):
            gained = [gained]
        for host in gained:
            _elevate(host_to_campaign.get(str(host)), package,
                     f"gained host {host}")
        target = str(record.get("impersonated_target", "") or "")
        if target:
            _elevate(target_to_campaign.get(target), package,
                     f"a new clone of impersonated {target}")
        rules = record.get("rules")
        if isinstance(rules, str):
            rules = [rules]
        for signal in (rules if isinstance(
                rules, (list, tuple, set, frozenset)) else ()):
            _elevate(signal_to_campaign.get(str(signal)), package,
                     f"fires campaign signal {signal}")
        urls = record.get("payload_urls")
        if isinstance(urls, str):
            urls = [urls]
        for url in (urls if isinstance(
                urls, (list, tuple, set, frozenset)) else ()):
            _elevate(url_to_campaign.get(str(url)), package,
                     f"fetches campaign target {url}")
        maintainer = str(record.get("maintainer", "") or "").strip().lower()
        if maintainer:
            _elevate(maintainer_to_campaign.get(maintainer), package,
                     f"account {maintainer} is in the campaign")
    return [
        {
            "rule_id": "G006",
            "name": "Neighborhood Under Campaign Alert",
            "severity": "INFO", "category": "correlation",
            "match": (f"{len(members)} package(s) in active campaign "
                      f"{campaign_id}: " + "; ".join(sorted(reasons[campaign_id]))),
            "params": {"members": sorted(members), "campaign_id": campaign_id},
        }
        for campaign_id, members in sorted(by_campaign.items())
    ]


def _correlation_records(
    new_meta: dict,
    old_meta: Optional[dict],
    processed: set[str],
    popular: Optional[list[tuple[str, int]]] = None,
    source_repos: Optional[dict[str, set[str]]] = None,
    detail: Optional[dict] = None,
) -> list[dict]:
    """Per-package records the G-series correlates.

    Gained hosts come from the ``source_hosts`` property timeline (the
    corpus already stores every change as JSON old/new values); adoption is
    a maintainer change between two recorded snapshots.  A package absent
    from the previous snapshot is a first observation, not an adoption.
    ``source_repos`` is the per-package source-repository set the sweep
    already computed, so G003 can tell a maintainer co-adopting one variant
    family (one shared repo, H052's shape) from a coordinated takeover of
    unrelated packages.

    ``detail`` is this cycle's per-package analysis detail.  It supplies the
    rule ids G012 joins on and the payload URLs G013 joins on; absent detail
    (a caller that only wants the artifact joins) leaves those feeds empty
    rather than guessing.
    """
    from ..db import (
        correlation_feed,
        record_adoption_event,
        record_property_transition,
        write_batch,
    )

    repo_index = source_repos or {}
    detail_index = detail if isinstance(detail, dict) else {}
    cycle_observed_at = datetime.now(timezone.utc).isoformat()

    # record this cycle's maintainer transitions so the adoption_events view
    # serves G003.  H044 is an ownership transition between two recorded
    # maintainers; H086 is the orphan-to-maintained shape (the prior snapshot
    # held no maintainer).  The per-cycle row is what G003 joins on, so a
    # package re-processed with an unchanged maintainer - or one whose
    # adoption was recorded months ago - cannot re-arm a campaign.  Batched:
    # one transaction for the whole cycle's transitions, not one per package.
    with write_batch():
        for name in processed:
            old_entry = (old_meta or {}).get(name)
            if old_entry is None:
                continue
            current = (new_meta.get(name) or {}).get("Maintainer") or ""
            previous = old_entry.get("Maintainer") or ""
            if current and current != previous:
                record_property_transition(name, "maintainer", previous, current)
                record_adoption_event(
                    name, current, "H044" if previous else "H086",
                    cycle_observed_at)

    feed = correlation_feed(processed)
    records: list[dict] = []
    for name in processed:
        info = feed.get(name, {})
        predicates = list(info.get("adoption_predicates", ()))
        meta = new_meta.get(name) or {}
        package_detail = detail_index.get(name, {})
        if not isinstance(package_detail, dict):
            package_detail = {}
        records.append({
            "package": name,
            # A pkgbase's split outputs are one project, not several
            # unrelated packages meeting at a host/literal/dependency.
            "pkgbase": str(meta.get("PackageBase") or name),
            "hosts_gained": sorted(set(info.get("hosts_gained", ()))),
            # The literal feed G002 joins across packages is the view.
            "added_literals": list(info.get("added_literals", ())),
            # The committed-manifest additions G004 joins on (U-series): the
            # feed is the recorded `upstream_dep_additions` view.
            "upstream_dep_additions": list(
                info.get("upstream_dep_additions", ())),
            "maintainer": meta.get("Maintainer") or info.get("maintainer", ""),
            "adoption": bool(predicates),
            "adoption_predicates": predicates,
            # The package's own source repositories, so G003 can require the
            # members to be unrelated (a shared repo is H052's signal).
            "source_repos": sorted(repo_index.get(name, ()) or ()),
            # The popular package this name clones, when it is one (the
            # corpus H029 check).  G005 groups these into a campaign.
            "impersonated_target": _impersonates(name, meta, popular) if popular else "",
            # G008: AUR LastModified for dormancy check.
            "last_modified": meta.get("LastModified", 0),
            # G008: when the adoption event was observed (ISO timestamp).
            "adoption_observed_at": info.get("adoption_observed_at", ""),
            # G012: this cycle's rule ids for the package (payload signals).
            "rules": list(package_detail.get("rules", ()) or ()),
            # G013: canonical URLs the payload findings reported.
            "payload_urls": list(package_detail.get("payload_urls", ()) or ()),
        })
    return records


def _contacts_enabled(config) -> bool:
    """Whether the Contact Ledger records this cycle (the cold-replay lane)."""
    return bool(((config or {}).get("contacts", {}) or {}).get("enabled", True))


def _record_contacts_and_g010(records: list[dict], config: dict) -> list[dict]:
    """Write this cycle's contact-ledger entries, then run G010.

    The ledger is warm-only state: ``[contacts] enabled = false`` is the cold
    replay lane, where nothing is recorded and G010 stands down.  G010 joins
    the first-seen hosts the ledger wrote across the window, so it is the
    plurality join over strangers, never a per-package finding.
    """
    if not _contacts_enabled(config):
        return []
    from ..config import load_thresholds
    from ..contacts import record_cycle_contacts, shared_first_seen_host
    from ..db import first_seen_hosts_since

    now = int(time.time())
    observed_at = datetime.now(timezone.utc).isoformat()
    record_cycle_contacts(records, now, observed_at)

    g010 = (load_thresholds().get("g010", {}) or {})
    min_packages = int(g010.get("min_packages", 5))
    window_days = int(g010.get("window_days", 7))
    window_start = datetime.fromtimestamp(
        now - window_days * 86400, tz=timezone.utc).isoformat()
    return shared_first_seen_host(
        records, min_packages,
        first_seen_hosts=first_seen_hosts_since(window_start))


def _run_corpus_sweep(
    new_meta: dict,
    old_meta: Optional[dict],
    processed: set[str],
    scores: dict[str, int],
    popular: Optional[list[tuple[str, int]]] = None,
    detail: Optional[dict] = None,
) -> list[dict]:
    """Run the Class D detectors and attach their additive weight.

    With no prior snapshot (first bootstrap) the sweep is skipped entirely;
    the Class D calibration gate is ``fire_rate(no_baseline) == 0``.  Each
    cluster finding adds its severity weight to every member's profile score
    (H045/H052/H055/H073 are additive; only H057/H060/H061 are not).
    """
    if old_meta is None:
        return []

    source_repos: dict[str, set[str]] = {}
    for name in processed:
        snapshot = get_pkgbuild_snapshot(name)
        if not snapshot or not snapshot.get("pkgbuild_text"):
            continue
        repos = source_repos_from_pkgbuild(snapshot["pkgbuild_text"])
        if repos:
            source_repos[name] = repos

    # The shared, once-per-cycle history read: the temporal engine's
    # rate/baseline instances all consume this one snapshot.
    from .temporal_engine import read_cycle_history

    history = read_cycle_history(processed)
    findings = run_corpus_sweep(
        new_meta,
        old_meta,
        source_repos=source_repos,
        prior_history=history["prior_history"],
        maintainer_history=history["maintainer_history"],
        now=int(time.time()),
    )

    # the G-series cross-package correlation, over the
    # cycle's records (collective input, so it runs here and not per package).
    from ..analysis.correlation import (
        correlate,
        first_seen_adoption_burst,
        package_creation_burst,
    )

    records = _correlation_records(new_meta, old_meta, processed, popular,
                                   source_repos, detail)
    config = load_config()
    findings.extend(correlate(records, config))
    # G008 reads the maintainer-event timeline to tell a first-seen account
    # from an established one; it runs before campaign activation so a burst
    # primes campaign state like any other G-series cluster.
    findings.extend(first_seen_adoption_burst(records, config))
    # G011 spans cycles: the observed placeholder burst was spread over
    # several cycles, so this reads the recorded window rather than the
    # current cycle's processed set.
    g011 = (config.get("thresholds", {}) or {}).get("g011", {}) or {}
    try:
        creation_window_days = max(0, int(g011.get("window_days", 7)))
    except (TypeError, ValueError, OverflowError):
        creation_window_days = 7
    creation_since = int(time.time()) - creation_window_days * 86400
    findings.extend(package_creation_burst(
        brand_new_packages_since(creation_since), config))
    # The Contact Ledger records every first-contact this cycle introduced
    # (weight 0, warm-only), then G010 joins the first-seen hosts across the
    # window.  Nothing here scores: contact_ledger is state, not a rule.
    findings.extend(_record_contacts_and_g010(records, config))

    refused = _activate_campaigns(findings, config, log=log)
    if refused:
        # Campaign mode is temporary memory; refusing to remember a campaign
        # because every slot holds a live TTL must be visible, not silent.
        log.warning(
            "campaign cap reached; %d campaign(s) not activated this cycle: %s",
            len(refused), clean(", ".join(sorted(refused))),
        )
    findings.extend(_neighborhood_elevation(records))

    _apply_cluster_weights(findings, new_meta, popular, scores)
    return findings


def _apply_cluster_weights(findings, new_meta, popular, scores) -> None:
    """Add each cluster finding's severity weight to its members' profiles.

    A correlation cluster (**G001**-**G004**) is an alert about a *set*, not
    evidence against each member: the members still get the cluster alert and
    the campaign state, but membership must not inflate a member's own score.
    **G005** (impersonation) is the sharp signal and still scores.

    A shared-repo / attribute-burst cluster (`H052`/`H055`) is not a campaign
    on its own either: a maintainer updating their own variant family trips
    both.  Only when a member impersonates a far-more-popular package does the
    burst read as an attack - then it scores; otherwise it is demoted to
    context (see the alerting filter in the cycle body).
    """
    weights = load_config().get("severity_weights", {})
    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))
        if rule_id.startswith("G") and rule_id != "G005":
            continue
        members = finding.get("params", {}).get("members", [])
        if rule_id in _IMPERSONATION_GATED_RULES:
            impersonated = bool(popular) and any(
                _impersonates(member, new_meta.get(member), popular)
                for member in members
            )
            finding["params"]["impersonated"] = impersonated
            if not impersonated:
                continue
        delta = int(weights.get(finding.get("severity", ""), 0))
        if delta <= 0:
            continue
        with write_batch():
            for member in members:
                if is_reserved_name(member):
                    continue
                new_score = max(0, min(100, _profile_score(member, scores) + delta))
                save_package_profile(member, new_score, risk_level(new_score))


@dataclass
class CycleResult:
    """What one corpus cycle did, for a caller that runs more than one."""

    added: int = 0
    changed: int = 0
    removed: int = 0
    processed: int = 0
    cluster_findings: list[dict] = field(default_factory=list)
    new_alerts: list[tuple[str, str]] = field(default_factory=list)
    flagged: list[tuple[str, int]] = field(default_factory=list)
    over_threshold: list[tuple[str, int]] = field(default_factory=list)
    ioc_hits: list[tuple[str, str]] = field(default_factory=list)
    # Packages whose analysis hit a parser refusal (X026/X027): the change
    # was not fully read, so they are alert-worthy independent of score (the
    # refusal weight is capped so it cannot lift a clean package over the bar
    # by itself).  Reported like IOC hits, outside the score.
    refusals: list[str] = field(default_factory=list)
    backfilling: bool = False
    # The AUR day (YYYY-MM-DD) this cycle replayed, when backfilling.
    backfill_day: str = ""
    # Per-package alert context: score, version transition, LastModified,
    # firing rules - what a webhook document is built from.
    detail: dict[str, dict] = field(default_factory=dict)
    elapsed: float = 0.0
    bootstrap: bool = False
    # True when the cycle deliberately did no work and the caller should
    # report a failure (from-scratch bootstrap refused, empty fetch).
    refused: bool = False
    # True when a stop signal interrupted the cycle; progress is saved.
    stopped: bool = False


def _logger(json_output: bool):
    """The cycle's progress log, rendered inert.

    This is a terminal render path like any other: a cluster finding's
    ``match`` carries the gained host, maintainer or dependency name, all of
    which the input controls.  ``clean`` strips escape sequences, control
    bytes and bidi overrides before the message reaches stderr (A10).  The
    JSON lane is sanitised too, because a consumer may render the string
    later; escaping the document keeps it valid either way.
    """
    if json_output:
        import json as _json

        def _log(msg):
            print(_json.dumps({"msg": clean(msg)}))
    else:
        def _log(msg):
            log.info(clean(msg))
    return _log


def _fetch_workers() -> int:
    """How many PKGBUILD fetches run concurrently.

    The bootstrap's cost is dominated by one network fetch per package;
    fetching a window ahead in parallel is the biggest speedup.  It is bounded
    twice over: this worker count, and a per-host rate cap in the fetcher
    (``fetch._MIN_REQUEST_INTERVAL_BY_HOST``).  The GitHub AUR mirror is a CDN
    with a much smaller cap than the AUR's cgit, so more workers there buy
    throughput rather than idling; the cgit fallback stays capped and simply
    idles the surplus.  Tunable via ``limits.corpus_fetch_workers``.
    """
    try:
        configured = int(load_config().get("limits", {}).get("corpus_fetch_workers", 0))
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 16


def _max_per_cycle() -> int:
    """Cap on packages processed per invocation, so a large delta or a
    bootstrap advances in bounded, resumable chunks instead of one avalanche.

    Default 2000.  Set ``limits.corpus_max_per_cycle`` to another value, or to
    ``0`` to disable the cap and process the whole delta in one run.
    """
    limits = load_config().get("limits", {})
    if "corpus_max_per_cycle" not in limits:
        return 2000
    try:
        n = int(limits["corpus_max_per_cycle"])
    except (TypeError, ValueError):
        return 2000
    return n if n > 0 else 0


#: Direct dependency fields the AUR metadata dump carries.  Same fields as
#: ``depth.DEPTH_FIELDS``, under the RPC's capitalisation.
_META_DEPENDENCY_FIELDS = ("Depends", "MakeDepends", "CheckDepends")

#: How many distinct dependency names the prefill scan may inspect before it
#: gives up.  The cap on *fetches* is ``MAX_DEPTH_NODES``; this one bounds the
#: database lookups a crafted metadata entry could ask for, and leaves room
#: for many already-stored names before the fetches are chosen.
_MAX_PREFILL_CANDIDATES = MAX_DEPTH_NODES * 10


def _needs_dependency_prefill(name: str) -> bool:
    """True when the corpus has no usable stored result for *name*.

    Mirrors :func:`full_aur.analyze._corpus_dependency_fact`: a profile with
    a score or a PKGBUILD snapshot is enough, and anything less leaves the
    dependency walk unable to read it.
    """
    profile = get_package_profile(name)
    if profile and profile.get("last_score") is not None:
        return False
    row = get_pkgbuild_snapshot(name)
    return not (row and row.get("pkgbuild_text"))


#: Cap on the metadata edges the dependency-first ordering will read.  Above
#: it the cycle keeps the delta's natural order; the cap bounds CPU/memory a
#: crafted metadata dump could ask for, and a missed edge only means a
#: same-cycle dependency may still leave a gap for one run.
_MAX_ORDER_CANDIDATES = MAX_DEPTH_NODES * 50


def _dependencies_first(pending: list[str], new_meta: dict[str, dict]) -> list[str]:
    """Order *pending* so a dependency is analysed before its dependents.

    The full-AUR walk reads a stored result.  When a dependency changed in
    the same cycle as a package that needs it, analysing the dependent first
    would report ``deps_not_scanned`` for a package the cycle is about to
    process anyway.  A stable Kahn ordering removes that transient without
    changing the set or hiding a diff.  A cycle or an over-cap metadata edge
    list falls back to the delta's order.
    """
    from heapq import heappop, heappush

    pending_set = set(pending)
    edges: dict[str, set[str]] = {name: set() for name in pending}
    dependents: dict[str, list[str]] = {}
    examined = 0
    for parent in pending:
        entry = new_meta.get(parent) or {}
        for field_name in _META_DEPENDENCY_FIELDS:
            for raw in entry.get(field_name) or ():
                examined += 1
                if examined > _MAX_ORDER_CANDIDATES:
                    return pending
                dep = normalize_dependency(raw)
                if not dep or dep not in pending_set or dep == parent:
                    continue
                if dep not in edges[parent]:
                    edges[parent].add(dep)
                    dependents.setdefault(dep, []).append(parent)
    ready = [name for name in pending if not edges[name]]
    ready.sort()
    ordered: list[str] = []
    emitted: set[str] = set()
    while ready:
        name = heappop(ready)
        if name in emitted:
            continue
        emitted.add(name)
        ordered.append(name)
        for parent in dependents.get(name, ()):
            edges[parent].discard(name)
            if not edges[parent]:
                heappush(ready, parent)
    if len(ordered) != len(pending):
        # A dependency cycle: keep the deterministic remainder rather than
        # dropping packages from the cycle.
        ordered.extend(sorted(name for name in pending if name not in emitted))
    return ordered


def _missing_direct_dependencies(
    new_meta: dict[str, dict],
    pending: list[str],
    to_process: set[str],
    cap: int,
) -> tuple[list[str], bool]:
    """Dependencies to baseline before this cycle's roots are analysed.

    Only packages *not* in this cycle's delta are eligible.  A dependency
    that is itself pending must be analysed as a root so its own diff is
    recorded; saving its snapshot here first would turn that change into an
    unchanged first observation.  The cap bounds the extra fetch work the
    same way ``MAX_DEPTH_NODES`` bounds one walk, and the scan stops as soon
    as the cap is reached so a hostile metadata entry cannot make this pass
    query the database for an unbounded dependency list.

    Returns ``(missing, capped)``.
    """
    seen: set[str] = set()
    missing: list[str] = []
    for parent in pending:
        entry = new_meta.get(parent) or {}
        for field_name in _META_DEPENDENCY_FIELDS:
            for raw in entry.get(field_name) or ():
                dep = normalize_dependency(raw)
                if not dep or dep in seen:
                    continue
                seen.add(dep)
                if len(seen) > _MAX_PREFILL_CANDIDATES:
                    return missing, True
                if dep not in new_meta or dep in to_process:
                    continue
                if not _needs_dependency_prefill(dep):
                    continue
                if len(missing) >= cap:
                    return missing, True
                missing.append(dep)
    return missing, False


def _iter_prefetched(names, fetch_fn, workers: int):
    """Yield ``(name, fetch_result)`` in *names* order, fetching ahead.

    Analysis stays serial and ordered (novelty reads the observations earlier
    packages recorded), so only the fetch is parallelised: a bounded window of
    fetches is kept in flight and consumed in order.  A fetch that raises
    yields ``(None, None, None, False, None, None, None, True)`` - the same shape ``_fetch_one``
    returns for a vanished package - rather than aborting the run.
    """
    names = list(names)
    window = max(workers * 3, 24)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        inflight: deque = deque()
        idx = 0
        while idx < len(names) and len(inflight) < window:
            inflight.append((names[idx], pool.submit(fetch_fn, names[idx])))
            idx += 1
        while inflight:
            name, future = inflight.popleft()
            try:
                result = future.result()
            except Exception:
                result = (None, None, None, False, None, None, None, True)
            yield name, result
            if idx < len(names):
                inflight.append((names[idx], pool.submit(fetch_fn, names[idx])))
                idx += 1


def _corpus_progress(total: int, json_output: bool):
    """A rich progress bar for the analysis loop, or None when not interactive.

    Renders on stderr so it does not corrupt the artifact or a piped ``--json``
    stream; falls back to periodic log lines when there is no TTY.
    """
    if not (_HAS_RICH and not json_output and sys.stderr.isatty()):
        return None
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("elapsed"),
        TimeElapsedColumn(),
        TextColumn("eta"),
        TimeRemainingColumn(),
        console=Console(stderr=True),
    )
    progress.start()
    task = progress.add_task("Analysing packages", total=total)
    return progress, task


def run_baseline_build(
    resume: bool = False,
    export_path: Optional[str] = None,
    sign_key: Optional[str] = None,
    json_output: bool = False,
    bootstrap: bool = False,
    depth: Optional[int] = None,
    over_threshold: Optional[int] = None,
    since: Optional[int] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> CycleResult:
    """Bootstrap or update the full-AUR corpus.

    Fetches the metadata snapshot, diffs against the stored copy, downloads
    the changed PKGBUILDs, analyses each package, stores results, and
    optionally exports a signed baseline artifact.

    *over_threshold* is the alerting bar: packages scoring above it land in
    ``CycleResult.over_threshold``.  ``None`` uses the benign corpus's p95
    (published-figures.json), the point past which a score is outside
    everything the benign corpus does.

    *since* (a unix timestamp) starts a backfill: instead of diffing the
    newest metadata against the stored snapshot, the cycle replays change
    history by AUR ``LastModified``, one day per cycle, analysing every
    package that changed in that day's window.  The cursor persists in the
    database, so a backfill resumes after an interruption and joins the
    live delta when it catches up.  The sweep and the adoption feed stay
    out of backfill cycles: they model the live stream, and replaying two
    years into them would only distort the baselines they compute.

    A from-scratch bootstrap (no prior snapshot) fetches every PKGBUILD in the
    AUR, which is heavy on a shared community mirror.  It is not done by
    accident: *bootstrap* must be True to start one.  Every cycle, bootstrap
    or delta, is bounded by :func:`_max_per_cycle` and resumes automatically,
    so a large amount of work advances in gentle chunks across invocations
    rather than one avalanche.

    Returns what the cycle did so ``run_watch`` can report on it; the
    single-shot CLI path ignores the value.
    """
    try:
        return _run_baseline_build(
            resume=resume, export_path=export_path, sign_key=sign_key,
            json_output=json_output, bootstrap=bootstrap, depth=depth,
            over_threshold=over_threshold, since=since,
            should_stop=should_stop,
        )
    finally:
        # A cycle can write thousands of rows; leave the WAL small
        # instead of waiting for the next manual vacuum.
        checkpoint_wal()


def _run_baseline_build(
    resume: bool = False,
    export_path: Optional[str] = None,
    sign_key: Optional[str] = None,
    json_output: bool = False,
    bootstrap: bool = False,
    depth: Optional[int] = None,
    over_threshold: Optional[int] = None,
    since: Optional[int] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> CycleResult:
    """The cycle body; the public wrapper checkpoints the WAL."""
    if over_threshold is None:
        over_threshold = _OVER_BENIGN_P95
    _ensure_init()
    # Every G-series feed is one cycle's transitions, not an append-only log:
    # clear them before any package is processed so a prior cycle's host,
    # literal, adoption or upstream pair cannot meet this cycle's and re-fire
    # the join (or keep a lapsed campaign primed).
    clear_correlation_feeds()
    result = CycleResult()
    _log = _logger(json_output)

    _log("Fetching AUR metadata snapshot …")
    try:
        new_meta = fetch_metadata()
    except Exception as exc:
        raise RuntimeError(f"failed to fetch the AUR metadata snapshot: {exc}") from exc
    meta_count = len(new_meta)
    _log(f"Fetched {meta_count} package entries")
    if not new_meta:
        # An empty reply would clobber the stored snapshot on the
        # "Nothing to process" path below; keep the last good one.
        _log("The AUR metadata fetch returned nothing; keeping the previous snapshot")
        result.refused = True
        return result

    old_meta = load_metadata(_meta_snapshot_path())

    # Resume state is loaded unconditionally: a capped or interrupted cycle
    # continues where it left off.  ``--resume`` stays accepted but is implied.
    resume_state = load_resume_state()
    in_progress = bool(resume_state and resume_state.get("processed"))

    backfill_day_end = 0
    if since is not None:
        # The flag names the replay's origin; the cursor tracks progress.
        # A service re-passes the flag on every restart, so resetting on
        # the flag alone would replay from the start forever: only a
        # *different* origin starts a new replay.
        if get_metadata(_SINCE_ORIGIN_KEY) != str(since):
            # A fresh replay starts over: any resume set from another flow
            # (a bootstrap in progress) must not subtract names from the bucket.
            clear_resume_state()
            resume_state = None
            in_progress = False
            _set_since_cursor(since)
            set_metadata(_SINCE_ORIGIN_KEY, str(since))
    cursor = _since_cursor()
    if cursor is not None:
        # Backfill: one day of AUR time per cycle.  Days with no changes are
        # skipped inside the cycle, so an empty stretch costs nothing.
        now = int(time.time())
        while True:
            backfill_day_end = cursor + _SINCE_DAY_SECONDS
            bucket = sorted(
                name for name, m in new_meta.items()
                if cursor <= (m.get("LastModified") or 0) < backfill_day_end
            )
            if bucket or backfill_day_end >= now:
                break
            cursor = backfill_day_end
        _set_since_cursor(cursor)
        to_process = bucket
        added, removed = [], []
        changed = list(to_process)
        result.backfilling = True
        result.backfill_day = time.strftime("%Y-%m-%d", time.gmtime(cursor))
        _log(
            f"Backfill since {time.strftime('%Y-%m-%d', time.gmtime(cursor))}: "
            f"{len(to_process)} package(s) changed that day"
        )
    elif old_meta is None:
        # Refuse to start a whole-AUR bootstrap unless it was asked for.  A
        # continuation of one already under way (resume state present, snapshot
        # not yet advanced) is allowed to proceed without re-passing the flag.
        if not bootstrap and not in_progress:
            _log(
                f"Refusing a from-scratch corpus bootstrap of {meta_count} "
                "packages: it fetches the whole AUR and leans on a shared "
                "mirror. Pass --bootstrap to start one (it is capped per cycle "
                "and resumes automatically), or run 'trustsight review' first "
                "so an incremental snapshot already exists to diff against."
            )
            result.refused = True
            return result
        added = sorted(new_meta)
        changed: list[str] = []
        removed: list[str] = []
        result.bootstrap = True
        _log("Bootstrap: processing the whole AUR in capped, resumable cycles")
    else:
        changes = diff_metadata(old_meta, new_meta)
        added = sorted(n for n, s in changes.items() if s == "added")
        changed = sorted(n for n, s in changes.items() if s == "modified")
        removed = sorted(n for n, s in changes.items() if s == "removed")
        _log(f"Delta: {len(added)} added, {len(changed)} changed, {len(removed)} removed")

    result.added, result.changed, result.removed = len(added), len(changed), len(removed)
    to_process = added + changed

    if not to_process:
        if result.backfilling:
            # The bucket was empty at the head of history: the replay has
            # caught up with the AUR.  Join the live delta path.  The origin
            # sentinel is kept, not cleared: --since is re-passed on every
            # cycle, so clearing it would make the next cycle look like a
            # different replay and restart the whole backfill.
            save_metadata(new_meta, _meta_snapshot_path())
            _set_since_cursor(None)
            clear_resume_state()
            result.backfilling = False
            _log("Backfill caught up; joining the live delta stream")
            return result
        _log("Nothing to process")
        # A removals-only delta takes this path, and the adoption feed still
        # needs it: H073's introduction-rate and H058's maintainer-activity
        # baselines count removals.  Recording here rather than only after the
        # analysis loop keeps the feed complete for every delta shape; the
        # sweep never runs on this path, so its read-the-feed-first ordering
        # is untouched.
        _record_cycle_feed(new_meta, old_meta, added, changed, removed)
        save_metadata(new_meta, _meta_snapshot_path())
        clear_resume_state()
        return result

    processed: set[str] = set(resume_state.get("processed", [])) if resume_state else set()
    scores: dict[str, int] = {}
    # Per-package context for the alert payloads: version transition, the
    # AUR change date and the rules that fired, so a notification can say
    # what happened, not only that it did.
    detail: dict[str, dict] = {}
    ioc_hits: dict[str, list[str]] = {}
    refusals: set[str] = set()

    # Cap the work per invocation so even a bootstrap advances in bounded,
    # resumable chunks.  The remainder is picked up on the next run.
    cap = _max_per_cycle()
    pending_all = [n for n in to_process if n not in processed]
    pending = pending_all[:cap] if cap else pending_all
    partial = bool(cap) and len(pending_all) > cap
    process_order = _dependencies_first(pending, new_meta)
    _log(
        f"Processing {len(pending)} package(s) this cycle "
        f"({len(processed)} already done, {len(pending_all)} pending)"
    )
    batch_start = time.time()

    # The AUR-popularity candidate list H029 compares against, built once
    # for the whole cycle.  Without it the corpus typosquat check would see
    # only dependency names and miss every helper/app clone (yay/paru/...).
    popular = _popular_candidates(new_meta)

    def _fetch_one(name):
        meta = new_meta.get(name)
        if meta is None:
            return (None, None, None, False, None, None, None, True)
        return fetch_pkgbuild_with_tree(_pkg_or_base(meta))

    def _analyse_and_store(name, fetched, analyse_depth):
        """Analyse one fetched package and persist its result.

        Returns ``(status, fact)``.  This is the shared half of the root
        path and the dependency prefill: it owns the tokenizer refusal, the
        snapshot/profile write and G004's baseline handling, but emits no
        alert.  A prefill must persist the dependency without entering the
        cycle's score/detail maps.
        """
        meta = new_meta.get(name)
        if meta is None:
            log.warning("metadata for %s vanished; skipping", name)
            return "vanished", None
        if is_reserved_name(name):
            log.warning("skipping reserved package name %r", name)
            return "reserved", None
        (new_pkgbuild, tree_manifest, trailer_finding, snapshot_refused,
         install_text, install_name, manifest_texts,
         manifest_complete) = fetched
        if new_pkgbuild is None:
            log.debug("could not fetch PKGBUILD for %s (base: %s)", name, _pkg_or_base(meta))
            return "fetch_failed", None

        old_snapshot = get_pkgbuild_snapshot(name)
        old_pkgbuild = old_snapshot["pkgbuild_text"] if old_snapshot else None
        prev_last_modified: Optional[int] = (
            old_snapshot["last_modified"] if old_snapshot else None
        )
        # G004 state: this cycle's committed remote dependencies, and the
        # set the last recorded cycle saw.  No prior set (first observation,
        # a baseline import, or a pre-migration row) is a baseline, not an
        # empty history: every dependency would look "added" otherwise.
        manifest_pairs: set[tuple[str, str]] = set()
        manifest_deps_json: Optional[str] = None
        manifest_incomplete = False
        prior_deps: Optional[set[tuple[str, str]]] = None
        if manifest_texts is not None:
            from ..analysis.manifests import tree_remote_dependency_pairs
            manifest_pairs, incomplete = tree_remote_dependency_pairs(
                manifest_texts)
            manifest_incomplete = incomplete or not manifest_complete
            if not manifest_incomplete:
                manifest_deps_json = json.dumps(
                    sorted([list(pair) for pair in manifest_pairs]))
        raw_prior = old_snapshot.get("manifest_deps") if old_snapshot else None
        if raw_prior:
            try:
                decoded = json.loads(raw_prior)
                if isinstance(decoded, list):
                    prior_deps = {
                        (str(pair[0]), str(pair[1]))
                        for pair in decoded
                        if isinstance(pair, (list, tuple)) and len(pair) == 2
                    }
            except (ValueError, TypeError):
                prior_deps = None
        manifest_state_json = None
        manifest_deltas = ()
        workflow_deltas = ()
        if manifest_texts is not None and not manifest_incomplete:
            from ..analysis.manifest_state import (
                build_manifest_state,
                manifest_state_delta,
            )

            manifest_state_json = build_manifest_state(
                manifest_texts, tree_manifest)
            if manifest_state_json and old_snapshot:
                manifest_deltas, workflow_deltas = manifest_state_delta(
                    old_snapshot.get("manifest_state"), manifest_state_json)
        try:
            with write_batch():
                fact = analyze_package_text(
                    pkg_name=name,
                    old_pkgbuild=old_pkgbuild,
                    new_pkgbuild=new_pkgbuild,
                    maintainer=meta.get("Maintainer") or "",
                    temporal=TemporalContext(
                        last_modified=meta.get("LastModified"),
                        first_seen=meta.get("FirstSubmitted"),
                        previous_modified=prev_last_modified,
                        source="aur_metadata",
                    ),
                    tree_manifest=tree_manifest,
                    archive_trailer_finding=trailer_finding,
                    snapshot_refused=snapshot_refused,
                    depth=analyse_depth,
                    # The corpus builder is a writer by definition: it exists to
                    # accumulate the observations the read-only default consumes.
                    record=True,
                    popular_candidates=popular,
                    package_popularity=int((new_meta.get(name) or {}).get("NumVotes", 0) or 0),
                    install_text=install_text,
                    install_name=install_name,
                    old_install_text=(old_snapshot.get("install_text")
                                      if old_snapshot else None),
                    upstream_manifest_incomplete=manifest_incomplete,
                    manifest_deltas=manifest_deltas,
                    workflow_deltas=workflow_deltas,
                )
                save_pkgbuild_snapshot(
                    package_name=name,
                    pkgbuild_text=new_pkgbuild,
                    version=fact.new_version or meta.get("Version", ""),
                    last_modified=meta.get("LastModified", 0),
                    install_text=install_text,
                    manifest_deps=manifest_deps_json,
                    manifest_state=manifest_state_json,
                )
                if manifest_deps_json is not None and prior_deps is not None:
                    record_upstream_dep_additions(
                        name, sorted(manifest_pairs - prior_deps))
                save_package_profile(
                    package_name=name,
                    last_score=fact.final_score,
                    # score_breakdown is a list of ScoreEntry, not a dict: asking it
                    # for "risk_label" raised AttributeError on the first package of
                    # every bootstrap.  The label is derived from the score.
                    last_risk=risk_level(fact.final_score),
                )
        except TokenizerUnavailable as exc:
            # The sandboxed tokenizer could not answer (A6).  The package is
            # not analysed and nothing is persisted, so it cannot enter the
            # corpus as if it had been vetted; the cycle continues.
            log.warning("tokenizer unavailable for %s: %s; not vetted", name, exc)
            return "not_vetted", None
        return "ok", fact

    def _store(name, fetched) -> str:
        """Analyse and persist one fetched package.  Returns a status string:
        ``ok``, ``vanished``, ``reserved`` or ``fetch_failed``."""
        status, fact = _analyse_and_store(name, fetched, depth)
        if status != "ok":
            return status
        meta = new_meta.get(name) or {}
        old_snapshot = get_pkgbuild_snapshot(name)
        scores[name] = fact.final_score
        if fact.ioc_matches:
            # A known-bad match pages at maximum priority whatever the score:
            # the IOC tier is reported outside the heuristic score, so a clean-
            # looking package on the list would never cross the alerting bar.
            for m in fact.ioc_matches:
                ioc_hits[name].append(f"{m.type}:{m.value}")
        # Federated upstream indicators use the same maximum-priority lane.
        for entry in fact.score_breakdown:
            if entry.rule_id in ("U007", "U008"):
                repo = (entry.params or {}).get("upstream_repo", "")
                ioc_hits[name].append(f"upstream_repo:{repo}")
        # What a notification needs to say *where* a finding fired, not only
        # that a rule did.  Each entry names the rule, the file and line of
        # the evidence, its severity/weight and the rendered reason, so a
        # reader can point at the exact line in the PKGBUILD.  A rule with no
        # location (corpus, novelty, provenance) carries file="" and line=None
        # rather than a guessed one.
        #
        # Every entry rides, weight or not: a zero-weight finding is still a
        # finding (a declared practice, a coverage gap, a boundary warning),
        # and dropping it here is how the feed ended up unable to explain the
        # signals the score deliberately excludes.
        from ..registry import uid_of

        findings = [
            {
                "rule_id": e.rule_id,
                # The permanent identity behind the display id, so a feed
                # reader can join an alert back to its rule however the
                # display id is later renamed.
                "rule_uid": uid_of(e.rule_id),
                "severity": e.severity,
                "weight": e.weight,
                "file": e.file or "",
                "line": e.line,
                "reason": e.reason,
            }
            for e in fact.score_breakdown
        ]
        # A parser refusal means part of the change was not read.  It is
        # alert-worthy regardless of score (the weight is capped so it cannot
        # cross the bar alone), so it is tracked as its own tier.
        if any(f["rule_id"] in ("X026", "X027") for f in findings):
            refusals.add(name)
        from ..analysis.payload_signals import payload_urls

        try:
            payload_targets = payload_urls(fact.score_breakdown)
        except Exception:
            # URL extraction is an auxiliary join feed; a malformed finding
            # must not abort the cycle or the package's stored result.
            payload_targets = []

        new_pkgbuild = fetched[0] or ""
        previous_snapshot = get_previous_pkgbuild_snapshot(name) or {}
        old_pkgbuild = previous_snapshot.get("pkgbuild_text") or ""
        detail[name] = {
            "score": fact.final_score,
            "old_version": old_snapshot["version"] if old_snapshot else "",
            "new_version": fact.new_version or meta.get("Version", ""),
            "last_modified": meta.get("LastModified"),
            # Who owns the package now, and who owned it in the previous
            # snapshot.  The alert document needs both sides for an ownership
            # rule, and a campaign needs them per member; keeping them out of
            # `detail` meant every consumer had to re-fetch the AUR metadata.
            "maintainer": meta.get("Maintainer") or "",
            "previous_maintainer": (
                ((old_meta or {}).get(name) or {}).get("Maintainer") or ""),
            # The exact bytes the analysis read.  The feed otherwise has to
            # serve the current AUR file, which may be several commits past
            # the analysed change.  The diff is bounded and inert; when it is
            # too large the digest still names the analysed revision.
            "pkgbuild_sha256": _recipe_digest(new_pkgbuild),
            "previous_pkgbuild_sha256": _recipe_digest(old_pkgbuild or ""),
            "rules": [f["rule_id"] for f in findings],
            "payload_urls": payload_targets,
            "findings": findings,
            **_notify_diff(old_pkgbuild or "", new_pkgbuild),
        }
        return "ok"

    # A direct AUR dependency missing from the corpus makes the root's walk
    # fail closed as deps_not_scanned.  The watcher analyses only changed
    # packages, so an unchanged dependency that predates the corpus would
    # otherwise stay unread indefinitely.  Baseline those dependencies here,
    # before the roots, with depth 0 so this cannot recurse.  Anything in the
    # current delta is excluded: its own turn as a root must record the diff.
    missing_deps, prefill_capped = _missing_direct_dependencies(
        new_meta, pending, set(to_process), MAX_DEPTH_NODES)
    if missing_deps:
        _log(
            f"Prefilling {len(missing_deps)} missing AUR "
            f"dependenc{'y' if len(missing_deps) == 1 else 'ies'} "
            "so this cycle's walks can read them"
        )
        prefetched = 0
        for dep_name, fetched in _iter_prefetched(
                missing_deps, _fetch_one, _fetch_workers()):
            status, _fact = _analyse_and_store(dep_name, fetched, 0)
            if status == "ok":
                prefetched += 1
            else:
                log.warning(
                    "dependency prefill for %s did not complete (%s); the "
                    "dependent may report deps_not_scanned", dep_name, status)
        _log(f"Prefilled {prefetched}/{len(missing_deps)} dependencies")
    if prefill_capped:
        _log(
            f"Dependency prefill stopped at its bound "
            f"({MAX_DEPTH_NODES} fetches / {_MAX_PREFILL_CANDIDATES} "
            "candidates); more may remain for a later cycle"
        )

    fetch_failures = 0
    not_vetted = 0
    stopped = False
    progress = _corpus_progress(len(pending), json_output)
    try:
        done = 0
        for name, fetched in _iter_prefetched(process_order, _fetch_one, _fetch_workers()):
            if should_stop is not None and should_stop():
                stopped = True
                break
            status = _store(name, fetched)
            if status == "fetch_failed":
                fetch_failures += 1
            elif status == "not_vetted":
                not_vetted += 1
            # A fetch failure is marked done too, so a resume does not retry a
            # package the mirror has no snapshot for on every pass.  A
            # not-vetted package is the opposite case: nothing was stored and
            # the tokenizer may answer on a later pass, so it is left out of
            # the resume set and retried.
            if status != "not_vetted":
                processed.add(name)
            done += 1

            if progress is not None:
                progress[0].update(
                    progress[1], advance=1, description=f"Analysing {name[:36]}"
                )
            elif done % 1000 == 0:
                elapsed = time.time() - batch_start
                rate = done / elapsed if elapsed > 0 else 0
                _log(f"Processed {done}/{len(pending)} packages ({rate:.1f}/s)")

            if done % 1000 == 0:
                save_resume_state({"processed": sorted(processed)})
    finally:
        if progress is not None:
            progress[0].stop()

    if fetch_failures:
        _log(f"{fetch_failures} package(s) had no fetchable PKGBUILD this cycle")

    if not_vetted:
        _log(
            f"{not_vetted} package(s) were NOT vetted this cycle: the "
            "sandboxed tokenizer could not answer and nothing was recorded "
            "for them"
        )

    save_resume_state({"processed": sorted(processed)})
    if stopped:
        partial = True
        result.stopped = True
        _log("Stop requested; progress saved for the next cycle")

    # Per-cycle scores become the cycle's report and its alerts on EVERY
    # path: a capped chunk used to return without them, which dropped the
    # over_threshold list for every chunk but the last - the worst findings
    # of a multi-cycle bootstrap never notified.
    result.flagged = sorted(
        ((name, score) for name, score in scores.items() if score >= _FLAGGED_SCORE),
        key=lambda item: (-item[1], item[0]),
    )
    result.over_threshold = sorted(
        ((name, score) for name, score in scores.items() if score > over_threshold),
        key=lambda item: (-item[1], item[0]),
    )
    result.ioc_hits = sorted(
        (name, indicator)
        for name, indicators in ioc_hits.items() for indicator in indicators
    )
    result.refusals = sorted(refusals)
    result.detail = detail

    if partial:
        # More of this transition remains.  Do not advance the snapshot, run
        # the corpus sweep, or export a half-built corpus: the next invocation
        # continues from the saved resume state.
        remaining = len(pending_all) - len(pending)
        _log(
            f"Cycle capped at {len(pending)} package(s); {remaining} still "
            "pending. Run 'trustsight full-aur' again to continue."
        )
        result.processed = len(processed)
        return result

    if result.backfilling:
        # The day is drained.  Advance one day of AUR time; when the next day
        # reaches into the future, the replay has caught up and the snapshot
        # joins the live delta path.  ``now`` is the reading taken when this
        # cycle began, not a second reading here: re-reading the clock let a
        # second boundary falling mid-cycle decide the outcome, so a backfill
        # that had genuinely caught up could advance one more day.  The resume
        # set belongs to the day just finished, so it is cleared either way.
        clear_resume_state()
        if backfill_day_end >= now:
            # Caught up: join the live delta path.  The origin sentinel is
            # kept, not cleared, so the --since re-passed next cycle is not
            # mistaken for a new replay (see the guard above the day walk).
            save_metadata(new_meta, _meta_snapshot_path())
            _set_since_cursor(None)
            result.backfilling = False
            _log("Backfill caught up; joining the live delta stream")
        else:
            _set_since_cursor(backfill_day_end)
        result.processed = len(processed)
        return result

    # The sweep reads the adoption feed as its baseline, so it must run
    # before this cycle's events are recorded.  The feed is recorded before
    # the snapshot advances, as in the removals-only path: a crash between
    # the two used to leave the snapshot at the new state with the cycle's
    # events unrecorded, and the next run diffed the loss away.
    cluster_findings = _run_corpus_sweep(
        new_meta, old_meta, processed, scores, popular, detail)
    _report_expired_campaigns(_log)
    _record_cycle_feed(new_meta, old_meta, added, changed, removed)
    save_metadata(new_meta, _meta_snapshot_path())
    clear_resume_state()
    result.cluster_findings = cluster_findings
    result.processed = len(processed)
    # A context rule describes the corpus for prioritisation and must not
    # alert.  H057/H060/H061 are weight 0; feeding them to record_alerts
    # turned a routine sweep into hundreds of "new alert(s)" - 226 H061
    # centrality hubs in one cycle.  What this cycle analysed, worst first:
    # the individual packages a watcher would otherwise have to go looking
    # for in `trustsight list`.  Both lists were computed above the
    # partial-cycle return, so this path only reads them.
    alerting = [
        finding for finding in cluster_findings
        if finding["rule_id"] not in _NON_ALERTING_CLUSTER_RULES
        and not (finding["rule_id"] in _IMPERSONATION_GATED_RULES
                 and not finding.get("params", {}).get("impersonated"))
    ]
    result.new_alerts = record_alerts([
        (member, finding["rule_id"])
        for finding in alerting
        for member in finding["params"]["members"]
    ])
    if cluster_findings:
        _log(f"Corpus sweep: {len(cluster_findings)} cluster finding(s), "
             f"{len(alerting)} alerting")
        for finding in alerting:
            _log(
                f"  {finding['rule_id']} ({finding['severity']}) "
                f"{finding['name']}: {finding['match']}"
            )

    total_elapsed = time.time() - batch_start
    result.elapsed = total_elapsed
    _log(
        f"Baseline build complete: {len(processed)} packages processed "
        f"in {total_elapsed:.0f}s"
    )

    if result.flagged:
        shown = result.flagged[:_FLAGGED_REPORT_LIMIT]
        _log(
            f"{len(result.flagged)} package(s) scored {_FLAGGED_SCORE}+ this cycle"
            + (f" (showing {len(shown)})" if len(shown) < len(result.flagged) else "")
        )
        for name, score in shown:
            _log(f"  {score:3d}  {name}")

    if export_path:
        from .export import build_artifact
        build_artifact(
            export_path=export_path,
            private_key_path=sign_key,
        )
    return result


def watch_interval_seconds(requested: Optional[int] = None) -> int:
    """Seconds between watch cycles, clamped to the configured floor.

    The AUR regenerates its metadata dump every few minutes, so a shorter
    interval only re-downloads the same snapshot and re-walks the same
    diff; the floor keeps a mistyped ``--interval 1`` from turning into a
    request loop against someone else's mirror.
    """
    limits = load_config().get("limits", {})
    try:
        default = int(limits.get("watch_interval", 3600))
    except (TypeError, ValueError):
        default = 3600
    try:
        floor = int(limits.get("watch_min_interval", 60))
    except (TypeError, ValueError):
        floor = 60
    if requested is not None:
        try:
            requested = int(requested)
        except (TypeError, ValueError):
            requested = None
    return max(floor, int(requested) if requested is not None else default)


def run_watch(
    interval: Optional[int] = None,
    cycles: int = 0,
    json_output: bool = False,
    sleep: Callable[[float], None] = time.sleep,
    depth: Optional[int] = None,
    notify_url: Optional[str] = None,
    over_threshold: Optional[int] = None,
    since: Optional[int] = None,
    auto_pull_baselines: bool = False,
    auto_pull_iocs: bool = False,
    auto_pull_watchlists: bool = False,
) -> list[CycleResult]:
    """Run corpus cycles on an interval until interrupted.

    Each cycle is exactly what ``run_baseline_build`` does once: refresh
    the metadata snapshot, analyse what changed, run the Class D sweep and
    record the adoption feed.  What ``--watch`` adds is repetition and
    memory - a cluster is announced the first time it is seen and then
    counted, not re-announced, so the second cycle of a quiet night prints
    nothing rather than the same forty-package adoption again.

    ``SIGTERM``/``SIGINT`` set a stop event.  The current package finishes,
    the resume file and WAL are saved, and the loop exits without starting
    another cycle.  State is durable at every cycle boundary, so a crash
    loses at most the cycle in flight.
    """
    delay = watch_interval_seconds(interval)
    _log = _logger(json_output)
    results: list[CycleResult] = []
    stop = threading.Event()
    previous_handlers = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (_signal.SIGTERM, _signal.SIGINT):
            try:
                previous_handlers[sig] = _signal.getsignal(sig)
                _signal.signal(sig, lambda *_: stop.set())
            except (OSError, ValueError):
                pass

    from .. import __version__
    from ..db import get_db_path
    from . import watch_state

    _log(
        f"trustsight {__version__} watching the AUR: one cycle every {delay}s"
        + (f", {cycles} cycle(s)" if cycles else ", until interrupted")
    )
    try:
        _log(f"  database: {get_db_path()}")
    except Exception:  # noqa: BLE001 - the banner must never fail the watch
        pass
    try:
        from ..notify import notify_url as _configured_notify_url

        _effective = notify_url or _configured_notify_url()
        _log(f"  alert webhook: {'configured' if _effective else 'none'}")
    except Exception:  # noqa: BLE001
        pass
    # Retry anything a previous run could not deliver before spending the
    # next interval asleep.
    try:
        from ..notify import flush_outbox

        flush_outbox(notify_url)
    except Exception as exc:  # noqa: BLE001 - delivery is best effort
        _log(f"  pending alerts not flushed: {exc}")
    if not os.environ.get("TRUSTSIGHT_NO_SYNC_RULES", "").strip():
        try:
            from ..config import drifted_shipped_rules, sync_rules

            added, updated = sync_rules(update_outdated=True)
            if added or updated:
                _log(f"  ruleset synced: {len(added)} added, {len(updated)} updated")
            remaining = drifted_shipped_rules()
            if remaining:
                _log(f"  ruleset still drifted (user edits kept): {remaining}")
        except Exception as exc:  # noqa: BLE001 - never fail the watch over this
            _log(f"  ruleset sync skipped: {exc}")
    try:
        watch_state.record_start(delay)
    except Exception:
        pass

    def _sleep(seconds: float) -> None:
        if stop.is_set():
            return
        if sleep is time.sleep:
            stop.wait(seconds)
        else:
            sleep(seconds)

    attempts = 0
    try:
        while not stop.is_set():
            try:
                result = run_baseline_build(
                    json_output=json_output, depth=depth,
                    over_threshold=over_threshold, since=since,
                    should_stop=stop.is_set,
                )
                try:
                    watch_state.record_success()
                except Exception:
                    pass
            except Exception as exc:
                attempts += 1
                try:
                    failures = watch_state.record_failure(str(exc))
                except Exception:
                    failures = 0
                _log(f"Cycle failed ({exc}); retrying in {delay}s")
                if watch_state.should_notify_failure(failures):
                    try:
                        from ..notify import notify_watch_failure

                        if notify_watch_failure(
                            {"consecutive_failures": failures,
                             "last_error": str(exc)}, notify_url
                        ):
                            _log("  failure heartbeat delivered")
                    except Exception as notify_exc:  # noqa: BLE001
                        _log(f"  failure heartbeat skipped: {notify_exc}")
                if cycles and attempts >= cycles:
                    break
                _sleep(delay)
                continue
            attempts = 0
            if result.refused:
                from .metadata import load_metadata

                if load_metadata() is None and _since_cursor() is None:
                    try:
                        watch_state.record_failure("no corpus snapshot")
                    except Exception:
                        pass
                    _log(
                        "No corpus snapshot yet; the watch has nothing to "
                        "diff against. Run 'trustsight full-aur --bootstrap' "
                        "first so an initial snapshot exists."
                    )
                    results.append(result)
                    break
                try:
                    watch_state.record_failure("cycle did no work")
                except Exception:
                    pass
                _log(f"Cycle did no work; retrying in {delay}s")
                _sleep(delay)
                continue
            results.append(result)
            if result.new_alerts:
                _log(f"{len(result.new_alerts)} new alert(s) this cycle")
                for package, rule_id in result.new_alerts:
                    _log(f"  {rule_id}  {package}")
            elif result.cluster_findings:
                _log("No new alerts; every cluster this cycle was already reported")
            from ..notify import maybe_heartbeat, maybe_notify

            if maybe_notify(result, notify_url):
                _log("  alert webhook delivered")
            elif maybe_heartbeat(result, notify_url):
                _log("  heartbeat delivered")
            if auto_pull_baselines or auto_pull_iocs or auto_pull_watchlists:
                from ..channels import auto_pull

                for note in auto_pull(
                    baselines=auto_pull_baselines, iocs=auto_pull_iocs,
                    watchlists=auto_pull_watchlists,
                ):
                    _log(f"  {note}")
            if stop.is_set():
                break
            if cycles and len(results) >= cycles:
                break
            _sleep(2 if result.backfilling else delay)
    except KeyboardInterrupt:
        stop.set()
    finally:
        for sig, handler in previous_handlers.items():
            try:
                _signal.signal(sig, handler)
            except (OSError, ValueError):
                pass
    _log(f"Watch stopped after {len(results)} cycle(s)")
    return results
