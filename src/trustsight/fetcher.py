import os
import re
from pathlib import Path
from typing import Optional

import pygit2

from .config import CACHE_DIR


def repo_path(pkg_name: str) -> Path:
    return CACHE_DIR / pkg_name


def clone_or_fetch(pkg_name: str) -> pygit2.Repository:
    path = repo_path(pkg_name)
    if not path.exists():
        os.makedirs(path.parent, exist_ok=True)
        url = f"https://aur.archlinux.org/{pkg_name}.git"
        repo = pygit2.clone_repository(url, str(path))
    else:
        repo = pygit2.Repository(str(path))
        repo.remotes["origin"].fetch()
    return repo


def get_commit_for_version(
    repo: pygit2.Repository, version: str
) -> Optional[str]:
    for commit in repo.walk(repo.head.target, pygit2.GIT_SORT_TIME):
        try:
            blob = repo[commit.tree]["PKGBUILD"]
            pkgbuild = blob.data.decode()
            match = re.search(
                r'^pkgver\s*=\s*["\']?([^\s"\']+)', pkgbuild, re.MULTILINE
            )
            if match and match.group(1) == version:
                return str(commit.id)
        except (KeyError, AttributeError):
            pass
    return None


def get_head_commit(repo: pygit2.Repository) -> str:
    return str(repo.head.target)


def get_pkgver_from_head(repo: pygit2.Repository) -> Optional[str]:
    try:
        blob = repo[repo.head.target].tree["PKGBUILD"]
        pkgbuild = blob.data.decode()
        match = re.search(
            r'^pkgver\s*=\s*["\']?([^\s"\']+)', pkgbuild, re.MULTILINE
        )
        if match:
            return match.group(1)
    except (KeyError, AttributeError):
        pass
    return None


def get_maintainer_from_repo(repo: pygit2.Repository) -> Optional[str]:
    try:
        blob = repo[repo.head.target].tree[".SRCINFO"]
        srcinfo = blob.data.decode()
        match = re.search(r"^\s*maintainer\s*=\s*(.+)", srcinfo, re.MULTILINE)
        if match:
            return match.group(1).strip()
    except (KeyError, AttributeError):
        pass
    return None


def get_maintainer_from_commit(repo: pygit2.Repository, commit_oid: str) -> Optional[str]:
    try:
        commit = repo.get(commit_oid)
        blob = commit.tree[".SRCINFO"]
        srcinfo = blob.data.decode()
        match = re.search(r"^\s*maintainer\s*=\s*(.+)", srcinfo, re.MULTILINE)
        if match:
            return match.group(1).strip()
    except (KeyError, AttributeError, TypeError):
        pass
    return None
