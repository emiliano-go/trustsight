import time

import pygit2

from ..db import get_package
from ..fetcher import walk_bounded
from ..findings import stamp


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
                "rule_id": "R065",
                "name": "Very Recent Update",
                "severity": "INFO",
                "category": "temporal",
                "match": f"updated {int(hours_ago)}h ago (< 72h)",
                "params": {"detail": f"updated {int(hours_ago)}h ago (< 72h)"},
            })
    except (AttributeError, pygit2.GitError):
        pass
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
                "rule_id": "R066",
                "name": "Brand New Package",
                "severity": "INFO",
                "category": "temporal",
                "match": f"first AUR commit {int(root_age)} days ago (< 30)",
                "params": {"detail": f"first AUR commit {int(root_age)} days ago (< 30)"},
            })
    except (AttributeError, pygit2.GitError):
        pass
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
                "rule_id": "R067",
                "name": "Stale Package Revived",
                "severity": "MEDIUM",
                "category": "temporal",
                "match": f"dormant {int(gap_days)} days, now has a new update (> 1 year)",
                "params": {"detail": f"dormant {int(gap_days)} days, now has a new update (> 1 year)"},
            })
    except (AttributeError, pygit2.GitError):
        pass
    return None
