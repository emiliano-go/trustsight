"""Adoption, repository-cluster and activity-rate temporal emitters."""

from __future__ import annotations

import re
import statistics
from typing import TYPE_CHECKING

from ..deps import _package_stem
from ._temporal_common import (
    _cluster,
    _last_modified,
    _maintainer,
    _package_base,
    _repo_owner,
    _threshold,
)

if TYPE_CHECKING:
    from .temporal_engine import HistorySnapshot


def _mass_adoption(snapshot: HistorySnapshot) -> list[dict]:
    """H045: one maintainer files N packages within a short window."""
    new_meta, changes = snapshot.new_meta, snapshot.changes
    min_packages = _threshold("h045", "min_packages", 10)
    window_s = _threshold("h045", "window_days", 7) * 86400
    by_maintainer: dict[str, list[tuple[str, int]]] = {}
    for name, status in changes.items():
        if status != "added":
            continue
        maintainer = _maintainer(new_meta.get(name))
        if not maintainer:
            continue
        by_maintainer.setdefault(maintainer, []).append(
            (name, _last_modified(new_meta.get(name)) or 0)
        )
    findings: list[dict] = []
    for maintainer, pkgs in by_maintainer.items():
        # A split package files one PKGBUILD that produces several names.
        # Counting those names as separate adoptions made one new font,
        # kernel or database-tool base read as a mass adoption.  The base is
        # the unit a maintainer adopts; the member list still carries every
        # name so each output is scored.
        bases = {_package_base(new_meta.get(name)) or name for name, _ in pkgs}
        if len(bases) < min_packages:
            continue
        timestamps = [ts for _, ts in pkgs]
        if max(timestamps) - min(timestamps) > window_s:
            continue
        members = sorted(pkg for pkg, _ in pkgs)
        findings.append(
            _cluster(
                "H045",
                "Mass Adoption",
                f"maintainer {maintainer} submitted {len(bases)} package "
                f"base(s) ({len(members)} packages) within "
                f"{_threshold('h045', 'window_days', 7)} days",
                members,
                maintainer=maintainer,
            )
        )
    return findings


def _attribute_burst(snapshot: HistorySnapshot) -> list[dict]:
    """H055: N packages sharing an attribute modified in a short window."""
    new_meta, changes = snapshot.new_meta, snapshot.changes
    min_packages = _threshold("h055", "min_packages", 5)
    window_s = _threshold("h055", "window_hours", 24) * 3600
    by_maintainer: dict[str, list[tuple[str, int]]] = {}
    for name, status in changes.items():
        if status != "modified":
            continue
        lm = _last_modified(new_meta.get(name))
        if lm is None:
            continue
        maintainer = _maintainer(new_meta.get(name))
        if not maintainer:
            continue
        by_maintainer.setdefault(maintainer, []).append((name, lm))
    findings: list[dict] = []
    for maintainer, pkgs in by_maintainer.items():
        # A split package touches every output in one cycle.  That is one
        # logical update, not a burst across packages; judge the bases.
        bases = sorted({
            _package_base(new_meta.get(name)) or name
            for name, _ in pkgs
        })
        if len(bases) < min_packages:
            continue
        # A split family (foo, foo-bin, foo-git) is one logical update.
        if len({_package_stem(base) for base in bases}) == 1:
            continue
        timestamps = sorted(ts for _, ts in pkgs)
        if timestamps[-1] - timestamps[0] > window_s:
            continue
        members = sorted(pkg for pkg, _ in pkgs)
        findings.append(
            _cluster(
                "H055",
                "Attribute Burst",
                f"{len(members)} packages by maintainer {maintainer} modified within {_threshold('h055', 'window_hours', 24)}h",
                members,
                maintainer=maintainer,
            )
        )
    return findings


def _shared_repo_cluster(snapshot: HistorySnapshot) -> list[dict]:
    """H052: >= min_packages unrelated packages share a source repo."""
    new_meta, changes = snapshot.new_meta, snapshot.changes
    source_repos = snapshot.source_repos
    min_packages = _threshold("h052", "min_packages", 3)
    by_repo: dict[str, set[str]] = {}
    for name in changes:
        repos = source_repos.get(name) or set()
        for repo in repos:
            key = repo[:-4] if repo.endswith(".git") else repo
            by_repo.setdefault(key, set()).add(name)
    findings: list[dict] = []
    for repo, members in by_repo.items():
        if len(members) < min_packages:
            continue
        members_sorted = sorted(members)
        bases = {_package_base(new_meta.get(name)) for name in members_sorted}
        if len(bases) < min_packages:
            continue
        findings.append(
            _cluster(
                "H052",
                "Shared Source Repo Cluster",
                f"{len(members_sorted)} unrelated packages share source {repo}",
                members_sorted,
                repo=repo,
            )
        )
    return findings


def _introduction_deviation(snapshot: HistorySnapshot) -> list[dict]:
    """H073: this cycle's introduction rate deviates from the baseline."""
    changes = snapshot.changes
    prior_history = snapshot.prior_history
    min_cycles = _threshold("h073", "min_history_cycles", 3)
    z_score = float(_threshold("h073", "z_score", 3.0))
    min_introduced = _threshold("h073", "min_introduced", 3)
    if len(prior_history) < min_cycles:
        return []
    introduced = sum(1 for status in changes.values() if status == "added")
    if introduced < min_introduced:
        return []
    prior = [int(row["introduced"]) for row in prior_history]
    mean = statistics.mean(prior)
    if len(prior) >= 2 and statistics.stdev(prior) > 0:
        z = (introduced - mean) / statistics.stdev(prior)
    else:
        z = (introduced - mean) / max(mean, 1.0)
    if z < z_score:
        return []
    members = sorted(name for name, status in changes.items() if status == "added")
    return [
        _cluster(
            "H073",
            "Introduction-Rate Deviation",
            f"introduction rate {introduced} vs prior mean {mean:.0f} (z={z:.1f})",
            members,
            introduced=introduced,
            mean=round(mean),
            z_score=round(z, 2),
        )
    ]


#: Names whose version is taken from upstream automatically, so a rebuild
#: gives them a new ``pkgver`` without the recipe changing.
_AUTO_TRACKING_SUFFIX_RE = re.compile(
    r"-(?:git|hg|svn|bzr|cvs|darcs|fossil|latest|nightly)$"
)
_AUTO_TRACKING_URL_RE = re.compile(r"\.git(?:[#?]|$)", re.IGNORECASE)


def _is_auto_tracking(name: str, snapshot: HistorySnapshot) -> bool:
    """True when *name*'s version tracks upstream instead of being declared.

    ``-git``/``-latest`` names and ``.git`` sources take a new ``pkgver`` on
    every upstream commit, so one sweep touches many unrelated upstreams by
    construction.  That is a periodic refresh, not a surge.
    """
    if _AUTO_TRACKING_SUFFIX_RE.search(name):
        return True
    return any(
        _AUTO_TRACKING_URL_RE.search(url)
        for url in (snapshot.source_repos.get(name) or ())
    )


def _maintainer_deviation_findings(snapshot: HistorySnapshot) -> list[dict]:
    """H058 - a maintainer's activity deviates from their own baseline."""
    changes, new_meta = snapshot.changes, snapshot.new_meta
    maintainer_history = snapshot.maintainer_history
    min_cycles = int(_threshold("h058", "min_history_cycles", 3))
    z_score = float(_threshold("h058", "z_score", 2.0))
    min_activity = int(_threshold("h058", "min_activity", 3))
    prior_by_maintainer: dict[str, list[int]] = {}
    for row in maintainer_history:
        m = row.get("maintainer") or ""
        if m:
            prior_by_maintainer.setdefault(m, []).append(int(row.get("activity") or 0))
    activity_now: dict[str, list[str]] = {}
    for name, status in changes.items():
        if status == "removed":
            continue
        m = _maintainer(new_meta.get(name))
        if m:
            activity_now.setdefault(m, []).append(name)
    out: list[dict] = []
    for maintainer, members in activity_now.items():
        if len(members) < min_activity:
            continue
        prior = prior_by_maintainer.get(maintainer, [])
        if len(prior) < min_cycles:
            continue
        # A batch no larger than one this maintainer has already shipped is
        # within their demonstrated range, not a deviation from it: a
        # packager who has bumped six packages in one cycle before is not
        # surging when they bump five again.  The xz shape is a quiet
        # account *exceeding* its own history, so require a new high-water
        # mark before the z test can fire.
        if len(members) <= max(prior):
            continue
        mean = statistics.mean(prior)
        if len(prior) >= 2 and statistics.stdev(prior) > 0:
            z = (len(members) - mean) / statistics.stdev(prior)
        else:
            z = (len(members) - mean) / max(mean, 1.0)
        if z < z_score:
            continue
        # A periodic refresh of every auto-tracking recipe touches many
        # unrelated upstreams at once: that is routine packager maintenance,
        # not the xz-style surge onto packages the account did not already
        # maintain.  A batch with any declared-version package keeps its
        # signal.
        if all(_is_auto_tracking(name, snapshot) for name in members):
            continue
        # A bulk packager bumping their own sibling packages in lockstep
        # (linux-lts510, -docs, -headers, ...) is one logical update spread
        # over a naming family, not a deviation from the maintainer's
        # baseline - the same shape G003 already stands down for.  The same
        # holds for one upstream org's differently named packages: they share
        # a source owner, not a name stem.  Only a surge spanning unrelated
        # packages is the xz-style signal.
        if len(members) > 1:
            owner_sets = []
            for name in members:
                owners = {_repo_owner(url)
                          for url in (snapshot.source_repos.get(name) or ())}
                owners.discard(None)
                owner_sets.append(owners)
            if all(owner_sets) and set.intersection(*owner_sets):
                continue
            # The unit a maintainer updates is the package base: one split
            # PKGBUILD (a font bundle, sqldef plus its -bin twin) produces
            # many package names from one logical release.  Judge the bases,
            # not the names, so a split family does not read as a surge.
            bases = sorted({
                _package_base(new_meta.get(name)) or name
                for name in members
            })
            from ..analysis.correlation import _one_related_cluster
            if _one_related_cluster(members):
                continue
            if len({_package_stem(base) for base in bases}) == 1:
                continue
        # A batch of routine version/checksum bumps is maintenance, not a
        # surge.  Every member must be routine: an unknown or non-routine
        # package keeps the finding (fail closed).
        if members and all(name in snapshot.routine_only for name in members):
            continue
        out.append(_cluster(
            "H058",
            "Maintainer Baseline Deviation",
            f"maintainer {maintainer} active on {len(members)} packages "
            f"vs prior mean {mean:.0f} (z={z:.1f})",
            sorted(members),
            severity="MEDIUM",
            maintainer=maintainer,
            activity=len(members),
            mean=round(mean),
            z_score=round(z, 2),
        ))
    return out
