"""Phase 6 - Class D corpus sweep (plan §8).

The adoption/momentum rules describe the *corpus* rather than a single
diff: clusters of packages sharing a maintainer, a burst window, a source
repo, an anomalous introduction rate, an ownership transition, a
dependency edge, or a name/host consensus break.  They cannot fire
per-package, so :func:`run_corpus_sweep` runs once per metadata cycle,
after the per-package analysis loop, and returns one finding per cluster
(the cluster members live in ``params.members``).

Rules: H045/H052/H055/H073 (adoption/momentum), H044/H074 (commit
identity / adopt-then-modify), H053/H058/H059 (consensus), and the graph
rules H046/H057/H060/H061 (see :mod:`~trustsight.full_aur.graph`).

All detectors are silent when there is no prior snapshot (``old_meta is
None``): the Class D calibration gate is ``fire_rate(no_baseline) == 0``.
"""

import statistics

from ..config import load_thresholds
from ..findings import stamp
from ..novelty import normalize_url
from .graph import run_graph_sweep
from .metadata import diff_metadata

_SEVERITY = {
    "H045": "HIGH", "H052": "HIGH", "H055": "MEDIUM", "H073": "MEDIUM",
    "H044": "MEDIUM", "H074": "MEDIUM", "H026": "HIGH",
    "H053": "MEDIUM", "H058": "MEDIUM", "H059": "MEDIUM",
}

# Hosts where an ecosystem package would be expected to live; a divergence
# from every one of these for a prefixed package is H053's signal.
_FORGE_HOSTS = frozenset({
    "github.com", "gitlab.com", "codeberg.org", "bitbucket.org",
    "sourceforge.net", "gitea.com", "gitea.io", "git.sr.ht",
})

_ECOSYSTEM_HOSTS = {
    "python": {"pypi.org", "pypi.io", "files.pythonhosted.org"},
    "python2": {"pypi.org", "pypi.io", "files.pythonhosted.org"},
    "python3": {"pypi.org", "pypi.io", "files.pythonhosted.org"},
    "perl": {"cpan.org", "metacpan.org"},
    "ruby": {"rubygems.org"},
    "nodejs": {"npmjs.com", "registry.npmjs.org"},
    "node": {"npmjs.com", "registry.npmjs.org"},
    "php": {"packagist.org"},
    "lua": {"luarocks.org"},
    "rust": {"crates.io", "static.crates.io"},
    "haskell": {"hackage.haskell.org"},
    "ocaml": {"opam.ocaml.org"},
    "texlive": {"ctan.org"},
    "r": {"cran.r-project.org", "cloud.r-project.org"},
}


def _threshold(rule: str, key: str, default):
    return load_thresholds().get(rule, {}).get(key, default)


def _maintainer(entry: dict | None) -> str:
    if not entry:
        return ""
    return (entry.get("Maintainer") or "").strip().lower()


def _last_modified(entry: dict | None) -> int | None:
    if not entry:
        return None
    lm = entry.get("LastModified")
    return int(lm) if isinstance(lm, (int, float)) and lm else None


def _package_base(entry: dict | None) -> str:
    if not entry:
        return ""
    return (entry.get("PackageBase") or entry.get("Name") or "").strip()


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("?")[0].split("#")[0].lower()


def _repo_path_tokens(url: str) -> set[str]:
    """Meaningful tokens from a source URL's path, minus version noise.

    Handles ``owner/repo/archive/v1.2.3.tar.gz``, ``releases/download``,
    raw and codeload layouts by scanning every path segment, stripping
    archive suffixes and trailing version digits.
    """
    rest = url.split("://", 1)[-1]
    path = rest.split("/", 1)[1] if "/" in rest else ""
    tokens: set[str] = set()
    for part in path.split("/"):
        for piece in part.replace(".tar.gz", "").replace(".tgz", "").replace(
            ".tar", "").replace(".zip", "").replace(".git", "").split("."):
            piece = piece.rstrip("0123456789")
            if len(piece) >= 3:
                tokens.add(piece)
    return tokens


def _ownership_transitions(old_meta: dict, new_meta: dict) -> dict[str, tuple[str, str]]:
    """``{name: (old_maintainer, new_maintainer)}`` for maintainer changes.

    Only packages that already existed in the previous snapshot count; a
    brand-new package has no previous owner, so its maintainer is not a
    transition.
    """
    out: dict[str, tuple[str, str]] = {}
    for name, entry in new_meta.items():
        old = old_meta.get(name)
        if old is None:
            continue
        old_m = (old.get("Maintainer") or "").strip().lower()
        new_m = (entry.get("Maintainer") or "").strip().lower()
        if old_m != new_m:
            out[name] = (old_m, new_m)
    return out


def _cluster(rule: str, name: str, match: str, members: list[str],
             severity: str | None = None, category: str = "adoption",
             **extra) -> dict:
    finding = {
        "rule_id": rule,
        "name": name,
        "severity": severity or _SEVERITY.get(rule, "MEDIUM"),
        "category": category,
        "match": match,
        "params": {"members": members, "member_count": len(members), **extra},
    }
    return stamp(finding)


def _mass_adoption(new_meta: dict, changes: dict) -> list[dict]:
    """H045: one maintainer files N packages within a short window.

    Only *added* packages count (an adoption is a new submission), and the
    cluster is attributed to the metadata Maintainer of record.
    """
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
        if len(pkgs) < min_packages:
            continue
        timestamps = [ts for _, ts in pkgs]
        if max(timestamps) - min(timestamps) > window_s:
            continue
        members = sorted(pkg for pkg, _ in pkgs)
        findings.append(
            _cluster(
                "H045",
                "Mass Adoption",
                f"maintainer {maintainer} submitted {len(members)} packages within {_threshold('h045', 'window_days', 7)} days",
                members,
                maintainer=maintainer,
            )
        )
    return findings


def _attribute_burst(new_meta: dict, changes: dict) -> list[dict]:
    """H055: N packages sharing an attribute modified in a short window.

    Only *modified* packages count; H045 already claims the added-package
    adoption clusters, so counting adds again here would double-report the
    same maintainer.  The shared attribute is the maintainer of record.
    """
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
        if len(pkgs) < min_packages:
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


def _shared_repo_cluster(
    new_meta: dict, changes: dict, source_repos: dict[str, set[str]]
) -> list[dict]:
    """H052: >= min_packages unrelated packages share a source repo.

    ``source_repos`` maps package name to the set of normalized upstream
    URLs its PKGBUILD declares.  "Unrelated" is enforced by requiring the
    cluster to span distinct package bases, so split packages of one base
    cannot trip the rule.
    """
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


def _introduction_deviation(new_meta: dict, changes: dict, prior_history: list[dict]) -> list[dict]:
    """H073: this cycle's introduction rate deviates from the baseline.

    Maturity-gated: a fresh corpus (fewer than *min_history_cycles* prior
    cycles) has no baseline, so the rule stays silent.  Only over-achievement
    is suspicious; a quiet cycle is not.
    """
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


def _known_maintainers(old_meta: dict) -> set[str]:
    """Every maintainer the previous snapshot knew of.

    The corpus sweep's own answer to "has this account been seen before":
    the per-package H026 asks the observation database, which on the corpus
    path has only what earlier cycles happened to analyse, while the
    snapshot names the maintainer of every package in the AUR.
    """
    known: set[str] = set()
    for entry in old_meta.values():
        maintainer = (entry.get("Maintainer") or "").strip().lower()
        if maintainer:
            known.add(maintainer)
    return known


def _ownership_transition_findings(
    new_meta: dict, old_meta: dict, transitions: dict
) -> list[dict]:
    """H044 - a package changed maintainer this cycle, and H026 with it.

    Transitions to a non-empty maintainer are the takeover half of H044
    (the commit-identity half needs git metadata the snapshot sweep does
    not carry).  A move to an empty maintainer is abandonment, handled by
    H046/H060 as orphan state rather than a takeover.

    H026 ships with H044 (plan §8): when the incoming account maintained
    nothing at all in the previous snapshot, the transition is not just a
    handover between known packagers, and that is a different claim from
    H044's.  The two are separate findings on separate evidence, so a
    handover between established maintainers carries H044 alone.
    """
    out: list[dict] = []
    known = _known_maintainers(old_meta)
    for name, (old_m, new_m) in sorted(transitions.items()):
        if not new_m:
            continue
        out.append(_cluster(
            "H044",
            "Ownership Transition",
            f"maintainer of {name} changed from '{old_m or 'orphan'}' to '{new_m}'",
            [name],
            severity="MEDIUM",
            category="maintainer",
            old=old_m,
            new=new_m,
        ))
        if new_m not in known:
            out.append(_cluster(
                "H026",
                "Untrusted Maintainer Takeover",
                f"maintainer of {name} changed to '{new_m}', who maintained "
                f"no package in the previous snapshot",
                [name],
                severity="HIGH",
                category="maintainer",
                previous_maintainer=old_m,
                current_maintainer=new_m,
            ))
    return out


def _adopt_then_modify_findings(
    new_meta: dict,
    old_meta: dict,
    transitions: dict,
    now: int,
) -> list[dict]:
    """H074 - adopt-then-immediately-modify (fires on the first package).

    A package adopted (maintainer transition to a non-empty maintainer)
    whose version also changed in the same cycle was touched by the new
    owner immediately.  Clusters by the adopting maintainer; the window
    bounds how recent the touch must be.
    """
    window_s = _threshold("h074", "window_days", 14) * 86400
    by_maintainer: dict[str, list[str]] = {}
    for name, (old_m, new_m) in transitions.items():
        if not new_m:
            continue
        old_v = (old_meta.get(name) or {}).get("Version")
        new_v = (new_meta.get(name) or {}).get("Version")
        if old_v == new_v:
            continue
        lm = _last_modified(new_meta.get(name))
        if lm is not None and now and (now - lm) > window_s:
            continue
        by_maintainer.setdefault(new_m, []).append(name)
    out: list[dict] = []
    for maintainer, members in by_maintainer.items():
        out.append(_cluster(
            "H074",
            "Adopt-then-Modify",
            f"maintainer {maintainer} adopted and immediately modified "
            f"{len(members)} package(s)",
            sorted(members),
            severity="MEDIUM",
            category="maintainer",
            maintainer=maintainer,
        ))
    return out


def _ecosystem_prefix_of(name: str) -> str | None:
    """Ecosystem prefix (with a known canonical host) for *name*, or None."""
    lower = name.lower()
    for prefix in sorted(_ECOSYSTEM_HOSTS, key=len, reverse=True):
        if lower.startswith(prefix + "-"):
            return prefix
    return None


def _name_host_divergence_findings(
    changes: dict, source_repos: dict[str, set[str]]
) -> list[dict]:
    """H053 - name-token <-> host consensus divergence.

    An ecosystem-prefixed package (``python-*``, ``nodejs-*``, ...) added
    this cycle whose sources live on a host that is neither the ecosystem's
    canonical host nor a known forge: the name implies an ecosystem the
    hosting contradicts.
    """
    out: list[dict] = []
    for name, status in changes.items():
        if status != "added":
            continue
        prefix = _ecosystem_prefix_of(name)
        if not prefix:
            continue
        repos = source_repos.get(name) or set()
        if not repos:
            continue
        hosts = {_host_of(r) for r in repos}
        canonical = _ECOSYSTEM_HOSTS[prefix]
        if hosts & canonical:
            continue
        if hosts & _FORGE_HOSTS:
            continue
        out.append(_cluster(
            "H053",
            "Ecosystem/Host Divergence",
            f"{name} claims the {prefix} ecosystem but sources from "
            f"{', '.join(sorted(hosts)[:3])}",
            [name],
            severity="MEDIUM",
            category="naming",
            prefix=prefix,
            hosts=sorted(hosts),
        ))
    return out


def _name_repo_divergence_findings(
    changes: dict, source_repos: dict[str, set[str]]
) -> list[dict]:
    """H059 - package name and source repo share no token.

    A multi-token package name whose upstream repo path shares none of its
    tokens is a name/repo mismatch; on a newly added package that is the
    typosquat-shaped signal.
    """
    from ..deps import _package_stem

    out: list[dict] = []
    for name, status in changes.items():
        if status != "added":
            continue
        repos = source_repos.get(name) or set()
        if not repos:
            continue
        tokens = {t for t in _package_stem(name).split("-") if len(t) >= 3}
        if len(tokens) < 2:
            continue
        repo_tokens = set()
        for repo in repos:
            repo_tokens |= _repo_path_tokens(repo)
        if not repo_tokens:
            continue
        overlapping = any(
            t in rt or rt in t for t in tokens for rt in repo_tokens
        )
        if not overlapping:
            out.append(_cluster(
                "H059",
                "Name/Repo Divergence",
                f"{name} sources from {', '.join(sorted(repos)[:3])}, "
                "sharing no token with its name",
                [name],
                severity="MEDIUM",
                category="naming",
                repos=sorted(repos)[:3],
            ))
    return out


def _maintainer_deviation_findings(
    changes: dict,
    new_meta: dict,
    maintainer_history: list[dict],
) -> list[dict]:
    """H058 - a maintainer's activity deviates from their own baseline.

    Compares this cycle's package count per maintainer against that
    maintainer's prior per-cycle activity (from the adoption feed).
    Maturity-gated like H073: no prior baseline, no finding.
    """
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
        mean = statistics.mean(prior)
        if len(prior) >= 2 and statistics.stdev(prior) > 0:
            z = (len(members) - mean) / statistics.stdev(prior)
        else:
            z = (len(members) - mean) / max(mean, 1.0)
        if z < z_score:
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


def source_repos_from_pkgbuild(pkgbuild_text: str | None) -> set[str]:
    """Normalized upstream URLs declared by a full PKGBUILD text.

    The existing source-array extractor consumes diff text, so each line is
    wrapped as a context line; only the ``source=()`` (and ``source_arch=()``)
    declarations are scanned.
    """
    from ..differ import extract_source_array_urls

    if not pkgbuild_text:
        return set()
    wrapped = "\n".join(" " + line for line in pkgbuild_text.splitlines())
    return {normalize_url(url) for url in extract_source_array_urls(wrapped, side="after")}


def run_corpus_sweep(
    new_meta: dict,
    old_meta: dict | None,
    *,
    source_repos: dict[str, set[str]] | None = None,
    prior_history: list[dict] | None = None,
    maintainer_history: list[dict] | None = None,
    edges: dict[str, set[str]] | None = None,
    now: int = 0,
) -> list[dict]:
    """Run the Phase 6 Class D detectors over one metadata cycle.

    Returns cluster findings (one per cluster; members in ``params``).
    With no prior snapshot (first bootstrap) nothing can be a deviation, a
    transition, or a burst, so every detector is silent.
    """
    if old_meta is None:
        return []
    changes = diff_metadata(old_meta, new_meta)
    transitions = _ownership_transitions(old_meta, new_meta)
    repos = source_repos or {}
    findings: list[dict] = []
    findings += _mass_adoption(new_meta, changes)
    findings += _attribute_burst(new_meta, changes)
    findings += _shared_repo_cluster(new_meta, changes, repos)
    findings += _introduction_deviation(new_meta, changes, prior_history or [])
    findings += _ownership_transition_findings(new_meta, old_meta, transitions)
    findings += _adopt_then_modify_findings(new_meta, old_meta, transitions, now)
    findings += _name_host_divergence_findings(changes, repos)
    findings += _name_repo_divergence_findings(changes, repos)
    findings += _maintainer_deviation_findings(changes, new_meta, maintainer_history or [])
    findings += run_graph_sweep(new_meta, old_meta, changes, transitions, edges=edges)
    return findings
