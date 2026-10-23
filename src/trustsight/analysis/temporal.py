import time

from ..coverage import note_stage_failure
from ..db import get_package
from ..findings import stamp
from ..sandbox.git_client import GitOpError, GitSandboxUnavailable


def _t_thresholds(config, name: str, key: str, default: int) -> int:
    return int(((config or {}).get("thresholds", {}).get(name, {}) or {})
               .get(key, default))


def t_key_findings(change: dict, config) -> list[dict]:
    """T001 - signing-key novelty.

    A ``validpgpkeys`` entry added in this diff whose fingerprint has never
    been observed in the ecosystem index.  Distinct from package novelty:
    the xz lesson is a *key* story.  Cold index (fewer than
    ``[thresholds] t_key.min_observations`` keys, default 1) declines to
    avoid firing on every key a fresh install sees.
    """
    from ..db import key_observed_before, observed_key_count

    gained = list((change or {}).get("pgp_keys", {}).get("gained", ()) or ())
    if not gained:
        return []
    if observed_key_count() < _t_thresholds(config, "t_key", "min_observations", 1):
        return []
    out = []
    for key in gained:
        if key and not key_observed_before(key):
            out.append(stamp({
                "rule_id": "T001",
                "name": "Signing-Key Novelty",
                "severity": "HIGH", "category": "temporal",
                "match": ("validpgpkeys adds a signing key never observed in "
                          f"the ecosystem: {key[:20]}..."),
                "params": {"key": key[:64]},
            }))
    return out


def t_key_rotation(change: dict) -> list[dict]:
    """T003 - signing-key rotation.

    A ``validpgpkeys`` key removed *and* a different one added in the same
    diff.  The xz backdoor's shape: the trusted signer is swapped, not merely
    widened or narrowed.  Distinct from H078 (which reports the change) and
    from T001 (a brand-new key): the rotation of trust in one commit is its
    own fact and does not need ecosystem history.
    """
    gained = list((change or {}).get("pgp_keys", {}).get("gained", ()) or ())
    lost = list((change or {}).get("pgp_keys", {}).get("lost", ()) or ())
    if not (gained and lost):
        return []
    return [stamp({
        "rule_id": "T003",
        "name": "Signing Key Rotated",
        "severity": "HIGH", "category": "temporal",
        "match": ("validpgpkeys removed "
                  f"{len(lost)} key(s) and added {len(gained)} in one diff; "
                  "the trusted signer changed"),
        "params": {"removed": len(lost), "added": len(gained)},
    })]


def t_domain_findings(maintainer: str, config) -> list[dict]:
    """T002 - maintainer domain novelty.

    A maintainer email whose domain first appeared in the ecosystem within
    the observation window: a domain never seen before first appears now, and
    one first seen this week is as novel as brand new.  Cold index declines
    (see T001).
    """
    from ..db import domain_first_seen, domain_seen_within, observed_domain_count
    from ..maintainer_email import maintainer_domain

    domain = maintainer_domain(maintainer)
    if not domain:
        return []
    if observed_domain_count() < _t_thresholds(
            config, "t_dom", "min_observations", 1):
        return []
    window = int(_t_thresholds(config, "t_dom", "window_days", 30))
    first_seen = domain_first_seen(domain)
    if first_seen is None or domain_seen_within(domain, window):
        reason = ("has never been observed in the ecosystem" if first_seen is None
                  else f"first appeared within the last {window} days")
        return [stamp({
            "rule_id": "T002",
            "name": "Maintainer Domain Novelty",
            "severity": "MEDIUM", "category": "temporal",
            "match": f"maintainer domain '{domain}' {reason}",
            "params": {"domain": domain, "window_days": window},
        })]
    return []


def t_metadata_git_divergence(project, head_commit, last_modified,
                              config) -> list[dict]:
    """T006 - AUR LastModified ahead of the git tip commit date.

    In aurweb, pushes set both the AUR ``LastModified`` timestamp and the git
    commit timestamp, so divergence means commits were pushed and later
    stripped (a history rewrite).  The benign explanations (staff reset,
    maintainer cleanup force-push) are themselves security-relevant, so this
    is MEDIUM, review-queue verdict.  The finding's output is designed to be
    pasted into a report to AUR security, where push logs survive even when
    git history does not.
    """
    if not head_commit or not last_modified:
        return []
    try:
        records = project.commit_meta([head_commit])
        if not records:
            return []
        tip_time = records[0].commit_time
        margin = int(_t_thresholds(
            config, "t006", "min_divergence_hours", 24)) * 3600
        if last_modified > tip_time + margin:
            divergence_hours = int((last_modified - tip_time) / 3600)
            return [stamp({
                "rule_id": "T006",
                "name": "Metadata-Git Divergence",
                "severity": "MEDIUM", "category": "temporal",
                "match": (f"AUR LastModified is {divergence_hours}h ahead "
                          "of git tip commit date"),
                "params": {
                    "last_updated": last_modified,
                    "tip_commit_time": tip_time,
                    "divergence_hours": divergence_hours,
                },
            })]
    except (GitSandboxUnavailable, GitOpError):
        note_stage_failure("temporal")
    return []


def t_packager_not_in_history(project, head_commit, maintainer,
                              config) -> list[dict]:
    """T007 - AUR maintainer not found in git commit messages (weight 0).

    A weight-0 corroboration signal: the AUR says this account packaged the
    project, but no commit in the retained git history mentions them.  Name
    matching is fuzzy (display name vs email vs git config), so this
    corroborates T006 and G008 but never scores alone.  On its own tier it is
    nearly a confession; as a solo scorer it would eventually burn someone
    with an unusual committer setup.
    """
    if not maintainer or not head_commit:
        return []
    try:
        name_lower = maintainer.lower()
        for commit in project.walk(head_commit, 200):
            if name_lower in (commit.message or "").lower():
                return []
        return [stamp({
            "rule_id": "T007",
            "name": "Packager Not In History",
            "severity": "INFO", "category": "temporal",
            "match": (f"AUR maintainer '{maintainer}' not found in any "
                      "commit message in the retained git history"),
            "params": {"maintainer": maintainer},
        })]
    except (GitSandboxUnavailable, GitOpError):
        note_stage_failure("temporal")
    return []


def _recent_update(project, head_commit):
    if not head_commit:
        return None
    try:
        records = project.commit_meta([head_commit])
        if not records:
            return None
        hours_ago = (time.time() - records[0].commit_time) / 3600
        if hours_ago < 72:
            return stamp({
                "rule_id": "H020",
                "name": "Very Recent Update",
                "severity": "INFO",
                "category": "temporal",
                "match": f"updated {int(hours_ago)}h ago (< 72h)",
                "params": {"detail": f"updated {int(hours_ago)}h ago (< 72h)"},
            })
    except (GitSandboxUnavailable, GitOpError):
        note_stage_failure("temporal")
    return None


def _package_is_new(project, head_commit, pkg_name=None):
    if not head_commit:
        return None
    try:
        if pkg_name and get_package(pkg_name):
            return None

        # 100 rather than the default: this only asks whether the *root*
        # commit is recent, and a package with more history than that is
        # not new by any reading.
        root_age = None
        for c in project.walk(head_commit, 100):
            if not c.parents:
                root_age = (time.time() - c.commit_time) / 86400
                break
        if root_age is not None and root_age < 30:
            return stamp({
                "rule_id": "H021",
                "name": "Brand New Package",
                "severity": "INFO",
                "category": "temporal",
                "match": f"first AUR commit {int(root_age)} days ago (< 30)",
                "params": {"detail": f"first AUR commit {int(root_age)} days ago (< 30)"},
            })
    except (GitSandboxUnavailable, GitOpError):
        note_stage_failure("temporal")
    return None


def _stale_revival(project, old_commit, head_commit):
    if not old_commit or not head_commit:
        return None
    try:
        records = {r.id: r for r in project.commit_meta([old_commit, head_commit])}
        old = records.get(old_commit)
        head = records.get(head_commit)
        if old is None or head is None:
            return None
        gap_days = (head.commit_time - old.commit_time) / 86400
        if gap_days > 365:
            return stamp({
                "rule_id": "H022",
                "name": "Stale Package Revived",
                "severity": "MEDIUM",
                "category": "temporal",
                "match": f"dormant {int(gap_days)} days, now has a new update (> 1 year)",
                "params": {"detail": f"dormant {int(gap_days)} days, now has a new update (> 1 year)"},
            })
    except (GitSandboxUnavailable, GitOpError):
        note_stage_failure("temporal")
    return None
