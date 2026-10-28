"""Bootstrap and incremental corpus pipeline."""

import difflib
import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import rich  # noqa: F401
    _HAS_RICH = True
except ImportError:  # pragma: no cover - rich is a dependency, but degrade gracefully
    _HAS_RICH = False

from ..config import load_config, load_naming
from ..db import (
    activate_campaign,
    active_campaigns,
    get_connection,
    get_metadata,
    latest_cycle_time,
    record_cycle_events,
    is_reserved_name,
    save_package_profile,
    set_metadata,
    write_batch,
)
from ..safe_text import clean, clean_log
from ..scoring import risk_level

log = logging.getLogger("trustsight.full_aur.pipeline")

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


_ROUTINE_SCALAR_RE = re.compile(
    r"^\s*(?:pkgver|pkgrel|epoch)\s*=[^\n]*$", re.IGNORECASE)
_ROUTINE_SUMS_LINE_RE = re.compile(
    r"^\s*(?:sha(?:1|224|256|384|512)sums|b2sums|md5sums|ck)"
    r"(?:_[A-Za-z0-9_]+)?\s*=\s*\(\s*['\"]?[0-9a-fA-F]{32,128}['\"]?\s*\)?\s*$")
_ROUTINE_SUM_ENTRY_RE = re.compile(
    r"^\s*['\"]?[0-9a-fA-F]{32,128}['\"]?\s*\)?\s*$")


def _is_routine_bump(old_text: str, new_text: str) -> bool:
    """True when the recipe changed only version scalars and checksums.

    H058 measures a maintainer's activity volume.  A batch of routine
    version bumps is maintenance, not the xz-style surge the rule exists for,
    so the batch can stand down when every member is routine.  The test is
    deliberately fail-closed: any source, dependency, install, function or
    URL change, any removed checksum, and any change that cannot be classed
    keeps the finding.

    Only PKGBUILD bytes are compared.  A checksum *replacement* is routine;
    an entry that disappears is not, so the added and removed checksum-entry
    counts must balance.
    """
    if not old_text or not new_text or old_text == new_text:
        return False
    old_lines = old_text.split("\n")
    new_lines = new_text.split("\n")
    if old_lines and old_lines[-1] == "":
        old_lines.pop()
    if new_lines and new_lines[-1] == "":
        new_lines.pop()
    entry_added = entry_removed = 0
    changed = False
    for line in difflib.unified_diff(old_lines, new_lines, n=0, lineterm=""):
        if line.startswith(("---", "+++", "@@")):
            continue
        marker, body = line[:1], line[1:]
        if marker not in "+-":
            continue
        if not body.strip():
            continue
        changed = True
        if _ROUTINE_SCALAR_RE.match(body) or _ROUTINE_SUMS_LINE_RE.match(body):
            continue
        if _ROUTINE_SUM_ENTRY_RE.match(body):
            if marker == "+":
                entry_added += 1
            else:
                entry_removed += 1
            continue
        return False
    return changed and entry_added == entry_removed


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
    record_events=record_cycle_events,
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
        record_events(events)


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


def _activate_campaigns(findings: list[dict], config: dict, log=None,
                       activate=activate_campaign,
                       active=active_campaigns) -> list[str]:
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
        activated = activate(
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
