"""G-series: cross-package correlation.

The only family whose input is the *set* of recent analyses, not one
package.  Mechanistically distinct from D (single-package graph walk) and T
(single-package history): G's input is collective, so it runs at cycle end
in the full-AUR sweep, never on a single ``review``.

Runs over a list of per-package correlation records (the corpus builder
supplies them), so the join logic is testable without a live corpus:

* **G001 Shared Gained Host** (HIGH): the same gained canonical host appears
  in at least N packages in the window.  A "new CDN" is plausible once,
  damning five times.
* **G002 Shared Added Literal** (HIGH): an identical added literal above a
  length floor appears in at least two unrelated packages.
* **G003 Coordinated Adoption** (MEDIUM, HIGH for a first-seen account
  adopting dormant targets): the same maintainer key adopted at least M
  packages in the window.
* **G008 First-Seen Account Adoption Burst** (HIGH): an account with no
  prior maintainer history adopts many dormant packages at once.  It reads
  the maintainer-event timeline, so it is a DB-backed rule invoked from the
  sweep beside G006, not from :func:`correlate`.
* **G011 Maintainer Package Creation Burst** (MEDIUM, HIGH with a
  placeholder majority): a first-seen account creates many unrelated
  brand-new packages in the recorded window.  It reads the cycle-event
  window, so it is a DB-backed rule invoked from the sweep beside G008.
* **G009 Watchlisted Subject** (INFO, weight 0): a package named directly on
  the operator's hand-curated watchlist, or one whose maintainer is.  It is the
  sanctioned home for profile-page facts the RPC metadata does not carry, and
  for an operator's package-level attention.  Report-only.
* **G012 Shared Payload Signal** (HIGH): the same specific payload rule fired
  in unrelated packages from more than one maintainer in the cycle.
* **G013 Shared Fetch Target** (HIGH): payload findings in unrelated packages
  name the same canonical URL.
* **G014 Shared Adoption Window** (HIGH): unrelated dormant packages were
  adopted by more than one maintainer in the cycle.

Members are named in the finding; the roundup is one alert, not N.

Every join here runs over the cycle records the full-AUR sweep supplies.
G008 reads the maintainer-event timeline, so it is invoked beside
:func:`correlate` from the sweep rather than inside it.  See the correlation
rule reference.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict

__all__ = ["correlate", "shared_gained_host", "shared_added_literal",
           "coordinated_adoption", "shared_upstream_dependency",
           "first_seen_adoption_burst", "package_creation_burst",
           "watchlisted_maintainer",
           "shared_payload_signal", "shared_fetch_target",
           "shared_adoption_window"]

#: Above this many members, the pairwise naming-relatedness pass in G003 is
#: skipped.  The pass is O(n^2) and the member set is attacker-influenced; a
#: cap keeps one maintainer with a thousand adopted names from deciding how
#: much CPU the sweep spends (A14).  Skipping means the group is not proven
#: to be one family, so it stays a finding - fail-open to the alert.
MAX_RELATEDNESS_MEMBERS = 64


def _safe_int(value, default: int) -> int:
    """*value* as an int, or *default*: a bad threshold never aborts a sweep."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _maintainer_key(value) -> str:
    """One grouping key for a maintainer identity.

    The seed and every runtime lookup normalise ``strip().lower()`` at one
    chokepoint (:func:`trustsight.db._hash_maintainer_value`); the G rules
    must group on the same key, or a case/whitespace variant splits one
    account into two clusters (or evades one rule while tripping another).
    """
    return str(value or "").strip().lower()


def _seq(value) -> list[str]:
    """A record field as a bounded list of strings.

    A hand-built or decoded record may carry a bare string where the corpus
    writer supplies a list; iterating that string would turn ``R001`` into
    four single-character rule ids.  An unexpected shape is empty rather
    than guessed at.
    """
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(item) for item in value if item is not None]
    return []


def _thresholds(config) -> dict:
    """The thresholds table, or {} when a hand-edited value is not a table."""
    value = (config or {}).get("thresholds", {})
    return value if isinstance(value, dict) else {}


def _section(value) -> dict:
    """One threshold section, or {} when a hand-edited value is not a table."""
    return value if isinstance(value, dict) else {}


def _maintainer_first_seen_ts(maintainer: str):
    """Earliest recorded maintainer-event timestamp, or ``None``.

    A database read shared by the adoption rules.  Any read failure is
    ``None`` (``unknown``), never an established account, so a cold or
    unreadable database cannot manufacture novelty.
    """
    from ..db import maintainer_first_seen
    from ..db._history import _parse_ts

    try:
        first_seen = maintainer_first_seen(maintainer)
    except Exception:
        return None
    if not first_seen:
        return None
    try:
        return _parse_ts(first_seen).timestamp()
    except (ValueError, TypeError):
        return None


#: Buckets whose hosts are ubiquitous and carry no campaign signal: five
#: unrelated packages gaining `github.com` is not a shared-CDN campaign, it is
#: how the AUR works.
_UBIQUITOUS_BUCKETS = frozenset({"trusted_forge", "official"})


def _one_name_family(members) -> bool:
    """True when every member shares a long dash-terminated name prefix.

    A maintainer refreshing a translation family (``firefox-nightly-i18n-*``)
    is one batch, not several packages meeting at a host.  The prefix must be
    long enough to be a family and end in ``-``; ``a``/``b``/``c`` are not a
    family, so a same-maintainer set of genuinely unrelated names still joins.
    """
    names = sorted(str(name) for name in members)
    if len(names) < 2:
        return False
    prefix = names[0]
    for name in names[1:]:
        while prefix and not name.startswith(prefix):
            prefix = prefix[:-1]
    return len(prefix) >= 8 and prefix.endswith("-")


def shared_gained_host(records, min_packages: int = 5,
                       min_maintainers: int = 2) -> list[dict]:
    """G001: a gained host shared by *min_packages* distinct packages.

    A host that is itself a trusted forge or official channel is skipped: the
    join only means something for a *new* host a set of packages did not all
    already reach through the ordinary sources.  A batch belonging to one
    maintainer is skipped too: one account refreshing a family (the
    firefox-nightly-i18n packages) is a maintenance batch, not a set of
    packages meeting at a host.  Single-account sweeps are covered by H026/
    H058/G003; the cross-account join is what G001 adds.
    """
    from ..buckets import canonical_host, classify_url

    by_host: dict[str, dict[str, dict]] = defaultdict(dict)
    for record in records:
        for host in record.get("hosts_gained", ()) or ():
            normalised = canonical_host(str(host)) if host else ""
            if normalised:
                by_host[normalised][str(record.get("package", ""))] = record
    out = []
    for host, members in sorted(by_host.items()):
        if len(members) < min_packages:
            continue
        if _one_project(members.values()):
            continue
        maintainers = {
            str(record.get("maintainer") or "").strip().lower()
            for record in members.values()
        }
        maintainers.discard("")
        if (maintainers and len(maintainers) < min_maintainers
                and _one_name_family(members)):
            continue
        try:
            bucket, _domain = classify_url(f"https://{host}")
        except Exception:
            # A host the classifier cannot read is an unknown host, not a
            # reason to abandon the cycle's other clusters.
            bucket = "unknown"
        if bucket in _UBIQUITOUS_BUCKETS:
            continue
        out.append({
            "rule_id": "G001",
            "name": "Shared Gained Host",
            "severity": "HIGH", "category": "correlation",
            "match": (f"gained host {host} appears in {len(members)} "
                      "packages in the window"),
            "params": {"members": sorted(members), "host": host},
        })
    return out


def _literal_token(entry) -> tuple[str, int] | None:
    """``(join_token, length)`` for one recorded added literal.

    The corpus feed supplies ``(digest, length)`` because the join must use
    the *full* literal's digest: the stored text is truncated for
    diagnostics, and joining on that copy let two distinct long literals
    sharing a prefix meet.  A hand-built record may still carry the text
    itself, which the unit tests and callers do.
    """
    if isinstance(entry, (list, tuple)) and len(entry) == 2:
        try:
            token, length = str(entry[0]), int(entry[1])
        except (TypeError, ValueError):
            return None
        return (token, length) if token and length >= 0 else None
    text = str(entry)
    return (text, len(text)) if text else None


def shared_added_literal(records, min_packages: int = 2,
                         min_length: int = 256) -> list[dict]:
    """G002: an identical added literal in *min_packages* packages."""
    by_literal: dict[str, dict[str, dict]] = defaultdict(dict)
    lengths: dict[str, int] = {}
    for record in records:
        for entry in record.get("added_literals", ()) or ():
            parsed = _literal_token(entry)
            if parsed is None:
                continue
            token, length = parsed
            if length >= min_length:
                by_literal[token][str(record.get("package", ""))] = record
                lengths[token] = max(lengths.get(token, 0), length)
    out = []
    for literal, members in by_literal.items():
        if len(members) >= min_packages and not _one_project(members.values()):
            out.append({
                "rule_id": "G002",
                "name": "Shared Added Literal",
                # Never print the literal's content: name its class only.
                "severity": "HIGH", "category": "correlation",
                "match": (f"an added literal of {lengths[literal]} chars "
                          f"appears in {len(members)} packages in the window"),
                "params": {"members": sorted(members),
                           "literal_length": lengths[literal],
                           "literal_sha256": literal},
            })
    return out


def _one_project(member_records) -> bool:
    """True when every member names the same pkgbase.

    A pkgbase's split outputs (``foo``/``foo-bin``/``foo-docs``) are one
    project's release, not several packages meeting at a host, literal or
    dependency.  Missing pkgbase data cannot prove a relationship, so it
    keeps the finding (the same fail-open posture G003 uses).
    """
    records = list(member_records)
    if not records:
        return False
    bases = {str(r.get("pkgbase") or "") for r in records}
    bases.discard("")
    return len(bases) == 1 and all(r.get("pkgbase") for r in records)


def _one_related_cluster(members) -> bool:
    """True when every member name belongs to one relatedness cluster.

    Union-find over :func:`~trustsight.deps.is_related_package`: two names
    share an edge when either is a variant/companion/sibling of the other.
    A single cluster covering every member means the group is one project's
    naming family (``appattic``/``appattic-bin``/``appattic-qt``), which is
    H052's shape regardless of whether repo data exists yet.
    """
    from ..deps import is_related_package

    names = sorted(members)
    if len(names) > MAX_RELATEDNESS_MEMBERS:
        # Not proven to be one family.  Keep the finding rather than spend
        # O(n^2) on an attacker-chosen member set.
        return False
    parent = {name: name for name in names}

    def find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if is_related_package(a, b):
                parent[find(a)] = find(b)
    return len({find(name) for name in names}) == 1


def coordinated_adoption(records, min_members: int = 3,
                         config=None) -> list[dict]:
    """G003: one maintainer key adopting *min_members* unrelated packages.

    Joins on the temporal adoption predicates (H044 ownership transition,
    H086 orphan-to-maintained) recorded per package, so the group is an
    adoption event the temporal engine would also fire - not a bare
    maintainer-change.

    The members must be **unrelated**: a maintainer adopting several packages
    that all source from one repository is a variant family (H052's shape),
    not a coordinated takeover.  When every member has repo data and they
    share a common repo, G003 stands down; any member without repo data keeps
    the group firing, because an unproven relationship is not evidence of one.

    New packages land in the window with no repo data yet, which used to make
    the repo test vacuous for exactly the case it exists for: a maintainer
    releasing ``appattic``, ``appattic-bin`` and ``appattic-qt`` in one cycle
    is the same variant family by name even where the corpus has not learned
    the repos.  A naming-relatedness pass (``is_related_package``) therefore
    stands the group down the same way: one cluster of related names is one
    project, not a campaign.

    Novelty/dormancy weighting (``[g003]``): a *globally novel* maintainer
    (its earliest recorded maintainer-event falls within ``novel_days``)
    adopting dormant targets (``last_modified`` older than ``dormant_days``)
    is the fennekuiper shape G008 exists for.  When it holds for at least
    ``min_dormant`` members the finding is escalated to HIGH; the bare
    N-adoption shape stays MEDIUM, so established maintainers keep the old
    posture.  The escalation changes the alert severity and evidence, not
    member scores - correlation clusters do not score their members
    (``_apply_cluster_weights`` skips every G finding but G005).
    """
    thresholds = _thresholds(config)
    g003 = thresholds.get("g003", {})
    novel_days = max(0, _safe_int(g003.get("novel_days", 30), 30))
    min_dormant = max(0, _safe_int(g003.get("min_dormant", 2), 2))
    dormant_days = max(0, _safe_int(g003.get("dormant_days", 180), 180))
    now = time.time()
    novel_cutoff = now - novel_days * 86400
    dormant_cutoff = now - dormant_days * 86400

    by_maintainer: dict[str, set[str]] = defaultdict(set)
    predicates: dict[str, set[str]] = defaultdict(set)
    repos: dict[str, list[set[str]]] = defaultdict(list)
    last_modified: dict[str, list[float]] = defaultdict(list)
    for record in records:
        maintainer = _maintainer_key(record.get("maintainer"))
        if maintainer and record.get("adoption"):
            by_maintainer[maintainer].add(str(record.get("package", "")))
            predicates[maintainer] |= set(
                record.get("adoption_predicates") or ())
            repos[maintainer].append(set(record.get("source_repos") or ()))
            last_mod = record.get("last_modified")
            if isinstance(last_mod, (int, float)) and last_mod:
                last_modified[maintainer].append(last_mod)
    out = []
    for maintainer, members in sorted(by_maintainer.items()):
        if len(members) < min_members:
            continue
        member_repos = repos[maintainer]
        if all(member_repos):
            common = set.intersection(*member_repos)
            if common:
                # Every member sources from the same repo: H052's family, not
                # a coordinated adoption.
                continue
        if _one_related_cluster(members):
            # Every member is a naming variant of one project (the
            # appattic/appattic-bin/appattic-qt release shape): H052's
            # family by name, not a coordinated adoption.
            continue
        dormant_count = sum(
            1 for lm in last_modified[maintainer] if lm < dormant_cutoff)
        first_seen_ts = _maintainer_first_seen_ts(maintainer)
        novel = first_seen_ts is not None and first_seen_ts >= novel_cutoff
        escalated = novel and dormant_count >= min_dormant
        which = sorted(predicates[maintainer])
        all_repos = sorted({r for rs in member_repos for r in rs})
        match = (f"maintainer adopted {len(members)} unrelated packages "
                 "in the window")
        if escalated:
            match += (f" (first-seen account, {dormant_count} dormant "
                      "targets)")
        out.append({
            "rule_id": "G003",
            "name": "Coordinated Adoption",
            "severity": "HIGH" if escalated else "MEDIUM",
            "category": "correlation",
            "match": match,
            "params": {"members": sorted(members), "predicates": which,
                       "repos": all_repos, "novel": novel,
                       "dormant_count": dormant_count},
        })
    return out


def shared_upstream_dependency(records, min_packages: int = 2) -> list[dict]:
    """G004: the same upstream dependency added across packages in the window.

    A name and its host added to committed manifests (the U-series change
    view) in at least *min_packages* distinct packages: the same-new-
    upstream-dependency campaign shape, one alert naming the members.
    """
    by_dep: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)
    for record in records:
        for entry in record.get("upstream_dep_additions", ()) or ():
            if isinstance(entry, (list, tuple)):
                name = str(entry[0]) if entry else ""
                host = str(entry[1]) if len(entry) > 1 else ""
            else:
                name, host = str(entry), ""
            if name:
                by_dep[(name, host)][str(record.get("package", ""))] = record
    out = []
    for (name, host), members in sorted(by_dep.items()):
        if len(members) >= min_packages and not _one_project(members.values()):
            where = f" from {host}" if host else ""
            out.append({
                "rule_id": "G004",
                "name": "Shared Upstream Dependency",
                "severity": "HIGH", "category": "correlation",
                "match": (f"upstream dependency {name}{where} appears in "
                          f"{len(members)} packages in the window"),
                "params": {"members": sorted(members), "dependency": name,
                           "host": host},
            })
    return out


def impersonation_campaign(records, min_members: int = 3) -> list[dict]:
    """G005: many name-clones of popular packages under one maintainer.

    Each record carries ``impersonated_target`` when its package name
    resembles a *far* more popular AUR package (the corpus H029 check over
    AUR vote counts).  A single maintainer publishing several such clones in
    one window is the registry-impersonation campaign that the per-package
    H029 only whispers about - 242 near-identical typosquats read as one
    campaign, not 242 findings.  This is the alert that names the campaign,
    its maintainer and its targets.

    Grouping is by maintainer key only.  Packages with **no** maintainer are
    not pooled into a synthetic "one submitter": an empty maintainer field is
    not evidence that unrelated ownerless packages share an operator.  Those
    clones stay individual H029 findings until something independently links
    them.
    """
    by_maintainer: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for record in records:
        target = str(record.get("impersonated_target", "") or "")
        if not target:
            continue
        member = str(record.get("package", ""))
        maintainer = _maintainer_key(record.get("maintainer"))
        if maintainer:
            by_maintainer[maintainer].append((member, target))
    out: list[dict] = []
    for maintainer, pairs in sorted(by_maintainer.items()):
        members = sorted({member for member, _ in pairs})
        if len(members) < min_members:
            continue
        targets = sorted({target for _, target in pairs})
        out.append({
            "rule_id": "G005",
            "name": "Impersonation Campaign",
            "severity": "HIGH", "category": "correlation",
            "match": (f"maintainer {maintainer} published {len(members)} "
                      f"name-clones of popular packages "
                      f"({', '.join(targets[:5])})"),
            "params": {"members": members, "maintainer": maintainer,
                       "targets": targets, "count": len(members)},
        })
    return out


def first_seen_adoption_burst(records, config=None) -> list[dict]:
    """G008: a first-seen account adopting many dormant packages at once.

    An account is *first-seen* when its earliest maintainer-event in the
    local property timeline falls within the current cycle window -- it has
    no prior maintainer history in the database.  Registration date is not
    in the RPC metadata and chasing profile pages would be a new fetch, so
    first-seen is the deterministic, self-contained approximation.  A
    throwaway account has, by definition, no prior maintainer events.

    The dormant-target clause is the false-positive killer: a legitimate new
    maintainer adopts a package or two they care about; nobody's first act is
    sweeping up orphans.  The conjunction of first-seen, many targets, and
    dormant targets is near-zero FP.  All parameters are config-driven and
    fingerprint-covered.
    """
    from ..db._history import _parse_ts

    thresholds = _thresholds(config)
    g008 = thresholds.get("g008", {})
    min_packages = max(1, _safe_int(g008.get("min_packages", 5), 5))
    window_days = max(0, _safe_int(g008.get("window_days", 7), 7))
    min_dormant = max(0, _safe_int(g008.get("min_dormant", 3), 3))
    dormant_days = max(0, _safe_int(g008.get("dormant_days", 180), 180))

    now = time.time()
    window_start = now - window_days * 86400
    dormant_cutoff = now - dormant_days * 86400

    by_maintainer: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        if not record.get("adoption"):
            continue
        maintainer = _maintainer_key(record.get("maintainer"))
        if maintainer:
            by_maintainer[maintainer].append(record)

    out: list[dict] = []
    for maintainer, events in sorted(by_maintainer.items()):
        # A DB read failure is "unknown", never "established": the guarded
        # helper returns None instead of aborting the cycle.
        first_seen_ts = _maintainer_first_seen_ts(maintainer)
        if first_seen_ts is None or first_seen_ts < window_start:
            continue

        # One package contributes once, however many transitions it has.
        packages: dict[str, float] = {}
        for event in events:
            observed_at = event.get("adoption_observed_at", "")
            if not observed_at:
                continue
            try:
                observed_ts = _parse_ts(observed_at).timestamp()
            except (ValueError, TypeError):
                continue
            if observed_ts < window_start:
                continue
            pkg = str(event.get("package", ""))
            if not pkg:
                continue
            last_mod = event.get("last_modified", 0)
            if isinstance(last_mod, (int, float)):
                packages[pkg] = float(last_mod or 0)
            else:
                packages.setdefault(pkg, 0.0)
        packages_in_window = sorted(packages)
        dormant_count = sum(
            1 for last_mod in packages.values()
            if last_mod and last_mod < dormant_cutoff)

        if len(packages_in_window) >= min_packages and dormant_count >= min_dormant:
            out.append({
                "rule_id": "G008",
                "name": "First-Seen Account Adoption Burst",
                "severity": "HIGH", "category": "correlation",
                "match": (f"first-seen account {maintainer} adopted "
                          f"{len(packages_in_window)} packages "
                          f"({dormant_count} dormant) within {window_days} days"),
                "params": {
                    "maintainer": maintainer,
                    "members": sorted(packages_in_window),
                    "dormant_count": dormant_count,
                    "window_days": window_days,
                },
            })
    return out


def watchlisted_maintainer(records, config=None) -> list[dict]:
    """G009: a package or maintainer on the operator watchlist.

    Report-only (INFO, weight 0).  A package entry is the operator asking for
    that package to be named; a maintainer entry carries a human's judgement
    about an account, where registration date, "Inactive since" and suspension
    state are profile-page facts the pipeline never fetches.

    Maintainer entries are matched by salted hash, never a plaintext identity.
    Package entries are stored as written because package names are already
    public.  The watchlist is absent on a clean install, so this is silent
    until an operator curates one.
    """
    g009 = _thresholds(config).get("g009", {})
    if not g009.get("enabled", True):
        return []
    from ..watchlist import (
        load_packages,
        load_watchlist,
        local_hash_many,
    )

    raw_path = g009.get("path")
    path = raw_path if isinstance(raw_path, str) and raw_path else None
    entries = load_watchlist(path)
    packages = load_packages(path)
    if not entries and not packages:
        return []

    # One salt read and one hash loop for the sweep, rather than a database
    # connection per package.  Only the maintainer entries need hashing.
    hashes = local_hash_many(
        {_maintainer_key(r.get("maintainer")) for r in records}
    ) if entries else {}

    out: list[dict] = []
    seen: set[str] = set()
    for record in records:
        package = str(record.get("package", ""))
        if package in seen:
            continue
        if package in packages:
            label = packages[package]
            subject = "package"
        else:
            maintainer = _maintainer_key(record.get("maintainer"))
            if not maintainer:
                continue
            name_hash = hashes.get(maintainer)
            if not name_hash or name_hash not in entries:
                continue
            label = entries[name_hash]
            subject = "maintainer"
        seen.add(package)
        out.append({
            "rule_id": "G009",
            "name": "Watchlisted Subject",
            "severity": "INFO", "category": "correlation",
            "match": (f"{subject} is on the operator watchlist"
                      + (f" ({label})" if label else "")),
            "params": {"members": [package], "label": label,
                       "subject": subject},
        })
    return out


def shared_payload_signal(records, min_packages: int = 3,
                          min_maintainers: int = 2) -> list[dict]:
    """G012: the same specific payload rule across unrelated maintainers.

    A single ``R001`` is a package-level finding.  The same rule firing in
    several unrelated packages from different accounts in one cycle is the
    multi-maintainer shape the per-package rules cannot name.  Only the
    curated :data:`~trustsight.analysis.payload_signals.SHARED_PAYLOAD_RULES`
    set counts; a broad practice rule would turn ordinary ecosystem churn into
    a campaign.
    """
    from .payload_signals import SHARED_PAYLOAD_RULES

    min_packages = max(1, _safe_int(min_packages, 3))
    min_maintainers = max(1, _safe_int(min_maintainers, 2))
    by_rule: dict[str, dict[str, dict]] = defaultdict(dict)
    maintainers: dict[str, set[str]] = defaultdict(set)
    for record in records or ():
        if not isinstance(record, dict):
            continue
        package = str(record.get("package", "") or "")
        if not package:
            continue
        maintainer = _maintainer_key(record.get("maintainer"))
        for rule_id in _seq(record.get("rules")):
            signal = str(rule_id)
            if signal not in SHARED_PAYLOAD_RULES:
                continue
            by_rule[signal][package] = record
            if maintainer:
                maintainers[signal].add(maintainer)
    out: list[dict] = []
    for signal, members in sorted(by_rule.items()):
        if len(members) < min_packages:
            continue
        accounts = sorted(maintainers[signal])
        if len(accounts) < min_maintainers:
            continue
        if _one_project(members.values()) or _one_related_cluster(members):
            continue
        out.append({
            "rule_id": "G012",
            "name": "Shared Payload Signal",
            "severity": "HIGH", "category": "correlation",
            "match": (f"{len(members)} packages from {len(accounts)} "
                      f"maintainer(s) all fired {signal} in the window"),
            "params": {"members": sorted(members), "signal": signal,
                       "maintainers": accounts,
                       "maintainer_count": len(accounts)},
        })
    return out


def shared_fetch_target(records, min_packages: int = 2,
                        min_maintainers: int = 2) -> list[dict]:
    """G013: the same canonical payload URL across unrelated maintainers.

    ``G012`` joins on the rule; this joins on the URL the rule reported, so
    two different payload rules that fetch the same endpoint meet.  URLs are
    extracted from already-bounded finding text by
    :mod:`trustsight.analysis.payload_signals`; a URL that cannot be parsed
    is dropped, never guessed at.
    """
    from .payload_signals import canonical_payload_url

    min_packages = max(1, _safe_int(min_packages, 2))
    min_maintainers = max(1, _safe_int(min_maintainers, 2))
    by_url: dict[str, dict[str, dict]] = defaultdict(dict)
    maintainers: dict[str, set[str]] = defaultdict(set)
    for record in records or ():
        if not isinstance(record, dict):
            continue
        package = str(record.get("package", "") or "")
        if not package:
            continue
        maintainer = _maintainer_key(record.get("maintainer"))
        for url in _seq(record.get("payload_urls")):
            target = canonical_payload_url(str(url))
            if not target:
                continue
            by_url[target][package] = record
            if maintainer:
                maintainers[target].add(maintainer)
    out: list[dict] = []
    for url, members in sorted(by_url.items()):
        if len(members) < min_packages:
            continue
        accounts = sorted(maintainers[url])
        if len(accounts) < min_maintainers:
            continue
        if _one_project(members.values()) or _one_related_cluster(members):
            continue
        out.append({
            "rule_id": "G013",
            "name": "Shared Fetch Target",
            "severity": "HIGH", "category": "correlation",
            "match": (f"{len(members)} packages from {len(accounts)} "
                      f"maintainer(s) fetch {url}"),
            "params": {"members": sorted(members), "url": url,
                       "maintainers": accounts,
                       "maintainer_count": len(accounts)},
        })
    return out


def shared_adoption_window(records, min_packages: int = 3,
                           min_maintainers: int = 2, min_dormant: int = 2,
                           dormant_days: int = 180) -> list[dict]:
    """G014: unrelated dormant packages adopted by several maintainers.

    ``G003`` groups adoptions under one maintainer and ``G008`` watches a
    single first-seen account.  This is the multi-account adoption window
    H052's old wording described: different maintainers taking unrelated
    dormant packages in the same cycle.  The dormant-target clause keeps the
    ordinary "new maintainer adopts an active package" case out.
    """
    min_packages = max(1, _safe_int(min_packages, 3))
    min_maintainers = max(1, _safe_int(min_maintainers, 2))
    min_dormant = max(0, _safe_int(min_dormant, 2))
    dormant_days = max(0, _safe_int(dormant_days, 180))
    now = time.time()
    dormant_cutoff = now - dormant_days * 86400
    members: dict[str, dict] = {}
    maintainers: set[str] = set()
    dormant_count = 0
    for record in records or ():
        if not isinstance(record, dict) or not record.get("adoption"):
            continue
        package = str(record.get("package", "") or "")
        if not package or package in members:
            continue
        members[package] = record
        maintainer = _maintainer_key(record.get("maintainer"))
        if maintainer:
            maintainers.add(maintainer)
        last_modified = record.get("last_modified")
        if (isinstance(last_modified, (int, float)) and last_modified
                and last_modified < dormant_cutoff):
            dormant_count += 1
    if len(members) < min_packages:
        return []
    accounts = sorted(maintainers)
    if len(accounts) < min_maintainers:
        return []
    if dormant_count < min_dormant:
        return []
    if _one_project(members.values()) or _one_related_cluster(members):
        return []
    return [{
        "rule_id": "G014",
        "name": "Shared Adoption Window",
        "severity": "HIGH", "category": "correlation",
        "match": (f"{len(members)} unrelated packages adopted by "
                  f"{len(accounts)} maintainer(s) "
                  f"({dormant_count} dormant) in the window"),
        "params": {"members": sorted(members), "maintainers": accounts,
                   "maintainer_count": len(accounts),
                   "dormant_count": dormant_count},
    }]


def package_creation_burst(records, config=None) -> list[dict]:
    """G011: a first-seen maintainer creates many packages in one window.

    A brand-new package is not adoption: nobody loses a package, and a
    maintainer launching a family is ordinary.  The signal is the collective
    shape: a first-seen account creating several unrelated packages quickly.
    A majority of H104 placeholders escalates it, because reserving names in
    bulk is the name-squatting shape H104 exists to surface; a bare burst
    stays MEDIUM.  Established accounts are ignored, which is what keeps a
    long-standing maintainer's multi-package launch out.

    The records come from :func:`trustsight.db.brand_new_packages_since`:
    the window spans cycles, not just the current one.  Alert-only, like the
    other adoption/window joins: the campaign state is the escalation, not a
    member score.
    """
    thresholds = _thresholds(config)
    g011 = _section(thresholds.get("g011"))
    min_packages = max(1, _safe_int(g011.get("min_packages", 5), 5))
    try:
        placeholder_share = float(g011.get("placeholder_share", 0.5))
    except (TypeError, ValueError, OverflowError):
        placeholder_share = 0.5
    if not math.isfinite(placeholder_share):
        placeholder_share = 0.5
    placeholder_share = min(1.0, max(0.0, placeholder_share))
    escalation = bool(g011.get("placeholder_escalation", True))

    by_maintainer: dict[str, dict[str, bool]] = defaultdict(dict)
    for record in records or ():
        if not isinstance(record, dict) or not record.get("brand_new"):
            continue
        maintainer = _maintainer_key(record.get("maintainer"))
        package = str(record.get("package", "") or "")
        if not maintainer or not package:
            continue
        if record.get("maintainer_established"):
            continue
        by_maintainer[maintainer][package] = bool(record.get("placeholder"))

    out: list[dict] = []
    for maintainer, packages in sorted(by_maintainer.items()):
        members = sorted(packages)
        if len(members) < min_packages:
            continue
        if _one_related_cluster(members):
            continue
        placeholder_count = sum(packages.values())
        share = placeholder_count / len(members)
        severity = ("HIGH" if escalation and share >= placeholder_share
                    else "MEDIUM")
        out.append({
            "rule_id": "G011",
            "name": "Maintainer Package Creation Burst",
            "severity": severity,
            "category": "correlation",
            "match": (f"first-seen maintainer {maintainer} created "
                      f"{len(members)} packages in the window "
                      f"({placeholder_count} placeholder)"),
            "params": {
                "maintainer": maintainer,
                "maintainers": [maintainer],
                "members": members,
                "placeholder_count": placeholder_count,
            },
        })
    return out


def correlate(records, config=None) -> list[dict]:
    """All G-series findings for one cycle's records."""
    thresholds = _thresholds(config)
    host_n = max(1, _safe_int(
        _section(thresholds.get("g_host")).get("min_packages", 5), 5))
    blob_n = max(1, _safe_int(
        _section(thresholds.get("g_blob")).get("min_packages", 2), 2))
    blob_len = max(0, _safe_int(
        _section(thresholds.get("g_blob")).get("min_length", 256), 256))
    adopt_m = max(1, _safe_int(
        _section(thresholds.get("g_adopt")).get("min_members", 3), 3))
    dep_n = max(1, _safe_int(
        _section(thresholds.get("g_dep")).get("min_packages", 2), 2))
    imp_m = max(1, _safe_int(
        _section(thresholds.get("g_impersonation")).get("min_members", 3), 3))
    g012 = _section(thresholds.get("g012"))
    payload_n = max(1, _safe_int(g012.get("min_packages", 3), 3))
    payload_m = max(1, _safe_int(g012.get("min_maintainers", 2), 2))
    g013 = _section(thresholds.get("g013"))
    url_n = max(1, _safe_int(g013.get("min_packages", 2), 2))
    url_m = max(1, _safe_int(g013.get("min_maintainers", 2), 2))
    g014 = _section(thresholds.get("g014"))
    adopt_window_n = max(1, _safe_int(g014.get("min_packages", 3), 3))
    adopt_window_m = max(1, _safe_int(g014.get("min_maintainers", 2), 2))
    adopt_window_dormant = max(0, _safe_int(g014.get("min_dormant", 2), 2))
    adopt_window_days = max(0, _safe_int(g014.get("dormant_days", 180), 180))
    out: list[dict] = []
    out.extend(shared_gained_host(records, host_n))
    out.extend(shared_added_literal(records, blob_n, blob_len))
    out.extend(coordinated_adoption(records, adopt_m, config))
    out.extend(shared_upstream_dependency(records, dep_n))
    out.extend(impersonation_campaign(records, imp_m))
    out.extend(shared_payload_signal(records, payload_n, payload_m))
    out.extend(shared_fetch_target(records, url_n, url_m))
    out.extend(shared_adoption_window(
        records, adopt_window_n, adopt_window_m,
        adopt_window_dormant, adopt_window_days))
    out.extend(watchlisted_maintainer(records, config))
    return out
