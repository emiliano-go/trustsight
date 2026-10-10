import time

import pygit2

from ..coverage import note_stage_failure
from ..db import get_package
from ..fetcher import walk_bounded
from ..findings import stamp


def _t_thresholds(config, name: str, key: str, default: int) -> int:
    return int(((config or {}).get("thresholds", {}).get(name, {}) or {})
               .get(key, default))


def t_key_findings(change: dict, config) -> list[dict]:
    """T001 - signing-key novelty (Addendum 5 §6.1).

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
    """T003 - signing-key rotation (Addendum 5 §6.1).

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
    """T002 - maintainer domain novelty (Addendum 5 §6.1).

    A maintainer email whose domain has never been observed in the
    ecosystem index.  Cold index declines (see T001).
    """
    from ..db import domain_first_seen, observed_domain_count

    if not maintainer or "@" not in maintainer:
        return []
    domain = maintainer.rsplit("@", 1)[1].strip().lower()
    if not domain:
        return []
    if observed_domain_count() < _t_thresholds(
            config, "t_dom", "min_observations", 1):
        return []
    if domain_first_seen(domain) is None:
        return [stamp({
            "rule_id": "T002",
            "name": "Maintainer Domain Novelty",
            "severity": "MEDIUM", "category": "temporal",
            "match": (f"maintainer domain '{domain}' has never been observed "
                      "in the ecosystem"),
            "params": {"domain": domain},
        })]
    return []


def _recent_update(repo, head_commit):
    if not head_commit:
        return None
    try:
        commit = repo.get(head_commit)
        if commit is None:
            return None
        hours_ago = (time.time() - commit.commit_time) / 3600
        if hours_ago < 72:
            return stamp({
                "rule_id": "H020",
                "name": "Very Recent Update",
                "severity": "INFO",
                "category": "temporal",
                "match": f"updated {int(hours_ago)}h ago (< 72h)",
                "params": {"detail": f"updated {int(hours_ago)}h ago (< 72h)"},
            })
    except (AttributeError, pygit2.GitError):
        note_stage_failure("temporal")
    return None


def _package_is_new(repo, head_commit, pkg_name=None):
    if not head_commit:
        return None
    try:
        if pkg_name and get_package(pkg_name):
            return None

        # 100 rather than the default: this only asks whether the *root*
        # commit is recent, and a package with more history than that is
        # not new by any reading.
        root_age = None
        for c in walk_bounded(repo, head_commit, limit=100):
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
    except (AttributeError, pygit2.GitError):
        note_stage_failure("temporal")
    return None


def _stale_revival(repo, old_commit, head_commit):
    if not old_commit or not head_commit:
        return None
    try:
        old = repo.get(old_commit)
        head = repo.get(head_commit)
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
    except (AttributeError, pygit2.GitError):
        note_stage_failure("temporal")
    return None
