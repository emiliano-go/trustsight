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
* **G003 Coordinated Adoption** (MEDIUM): the same maintainer key adopted
  at least M packages in the window.

Members are named in the finding; the roundup is one alert, not N.

Live coverage caveat: only G001, G003 and G005 have a connected corpus feed
today.  G002 (added literals) and G004 (upstream dependencies) ship and are
unit-tested, but the views that would supply them are pending, so they cannot
fire on a real ``full-aur`` cycle yet.  See the correlation rule reference.
"""

from __future__ import annotations

from collections import defaultdict

__all__ = ["correlate", "shared_gained_host", "shared_added_literal",
           "coordinated_adoption", "shared_upstream_dependency"]


def _thresholds(config) -> dict:
    return (config or {}).get("thresholds", {})


#: Buckets whose hosts are ubiquitous and carry no campaign signal: five
#: unrelated packages gaining `github.com` is not a shared-CDN campaign, it is
#: how the AUR works.
_UBIQUITOUS_BUCKETS = frozenset({"trusted_forge", "official"})


def shared_gained_host(records, min_packages: int = 5) -> list[dict]:
    """G001: a gained host shared by *min_packages* distinct packages.

    A host that is itself a trusted forge or official channel is skipped: the
    join only means something for a *new* host a set of packages did not all
    already reach through the ordinary sources.
    """
    from ..buckets import classify_url

    by_host: dict[str, set[str]] = defaultdict(set)
    for record in records:
        for host in record.get("hosts_gained", ()) or ():
            if host:
                by_host[host].add(str(record.get("package", "")))
    out = []
    for host, members in sorted(by_host.items()):
        if len(members) < min_packages:
            continue
        bucket, _domain = classify_url(f"https://{host}")
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


def shared_added_literal(records, min_packages: int = 2,
                         min_length: int = 256) -> list[dict]:
    """G002: an identical added literal in *min_packages* packages."""
    by_literal: dict[str, set[str]] = defaultdict(set)
    for record in records:
        for literal in record.get("added_literals", ()) or ():
            text = str(literal)
            if len(text) >= min_length:
                by_literal[text].add(str(record.get("package", "")))
    out = []
    for literal, members in by_literal.items():
        if len(members) >= min_packages:
            out.append({
                "rule_id": "G002",
                "name": "Shared Added Literal",
                # Never print the literal's content: name its class only.
                "severity": "HIGH", "category": "correlation",
                "match": (f"an added literal of {len(literal)} chars appears "
                          f"in {len(members)} packages in the window"),
                "params": {"members": sorted(members),
                           "literal_length": len(literal)},
            })
    return out


def coordinated_adoption(records, min_members: int = 3) -> list[dict]:
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
    """
    by_maintainer: dict[str, set[str]] = defaultdict(set)
    predicates: dict[str, set[str]] = defaultdict(set)
    repos: dict[str, list[set[str]]] = defaultdict(list)
    for record in records:
        maintainer = str(record.get("maintainer", "") or "").strip().lower()
        if maintainer and record.get("adoption"):
            by_maintainer[maintainer].add(str(record.get("package", "")))
            predicates[maintainer] |= set(
                record.get("adoption_predicates") or ())
            repos[maintainer].append(set(record.get("source_repos") or ()))
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
        which = sorted(predicates[maintainer])
        all_repos = sorted({r for rs in member_repos for r in rs})
        out.append({
            "rule_id": "G003",
            "name": "Coordinated Adoption",
            "severity": "MEDIUM", "category": "correlation",
            "match": (f"maintainer adopted {len(members)} unrelated packages "
                      "in the window"),
            "params": {"members": sorted(members), "predicates": which,
                       "repos": all_repos},
        })
    return out


def shared_upstream_dependency(records, min_packages: int = 2) -> list[dict]:
    """G004: the same upstream dependency added across packages in the window.

    A name and its host added to committed manifests (the U-series change
    view) in at least *min_packages* distinct packages: the same-new-
    upstream-dependency campaign shape, one alert naming the members.
    """
    by_dep: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in records:
        for entry in record.get("upstream_dep_additions", ()) or ():
            if isinstance(entry, (list, tuple)):
                name = str(entry[0]) if entry else ""
                host = str(entry[1]) if len(entry) > 1 else ""
            else:
                name, host = str(entry), ""
            if name:
                by_dep[(name, host)].add(str(record.get("package", "")))
    out = []
    for (name, host), members in sorted(by_dep.items()):
        if len(members) >= min_packages:
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
        maintainer = str(record.get("maintainer", "") or "")
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


def correlate(records, config=None) -> list[dict]:
    """All G-series findings for one cycle's records."""
    thresholds = _thresholds(config)
    host_n = int(thresholds.get("g_host", {}).get("min_packages", 5))
    blob_n = int(thresholds.get("g_blob", {}).get("min_packages", 2))
    blob_len = int(thresholds.get("g_blob", {}).get("min_length", 256))
    adopt_m = int(thresholds.get("g_adopt", {}).get("min_members", 3))
    dep_n = int(thresholds.get("g_dep", {}).get("min_packages", 2))
    imp_m = int(thresholds.get("g_impersonation", {}).get("min_members", 3))
    out: list[dict] = []
    out.extend(shared_gained_host(records, host_n))
    out.extend(shared_added_literal(records, blob_n, blob_len))
    out.extend(coordinated_adoption(records, adopt_m))
    out.extend(shared_upstream_dependency(records, dep_n))
    out.extend(impersonation_campaign(records, imp_m))
    return out
