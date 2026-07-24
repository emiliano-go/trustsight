import os
import re
import shutil
from pathlib import Path
from typing import Optional

import pygit2

from .config import CACHE_DIR


def _head_commit_id(repo: pygit2.Repository) -> str:
    """Resolve HEAD to a commit OID, handling empty and unborn repos."""
    try:
        return str(repo.head.peel().id)
    except pygit2.GitError:
        pass
    if repo.head_is_unborn or repo.is_empty:
        return ""
    for name in ("main", "master"):
        try:
            return str(repo.branches[name].peel().id)
        except (KeyError, pygit2.GitError):
            pass
    for ref_name in repo.references:
        try:
            ref = repo.references[ref_name]
            return str(ref.peel().id)
        except (TypeError, pygit2.GitError):
            pass
    raise pygit2.GitError("cannot resolve HEAD to a commit")


def repo_path(pkg_name: str) -> Path:
    return CACHE_DIR / pkg_name


def clone_or_fetch(pkg_name: str) -> pygit2.Repository:
    path = repo_path(pkg_name)
    if path.exists():
        try:
            repo = pygit2.Repository(str(path))
            _head_commit_id(repo)
            repo.remotes["origin"].fetch()
            return repo
        except pygit2.GitError:
            shutil.rmtree(path)
    os.makedirs(path.parent, exist_ok=True)
    url = f"https://aur.archlinux.org/{pkg_name}.git"
    return pygit2.clone_repository(url, str(path))


def get_commit_for_version(
    repo: pygit2.Repository, version: str
) -> Optional[str]:
    head = _head_commit_id(repo)
    if not head:
        return None
    for commit in repo.walk(head, pygit2.GIT_SORT_TIME):
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
    return _head_commit_id(repo)


def get_pkgver_from_head(repo: pygit2.Repository) -> Optional[str]:
    try:
        blob = repo[_head_commit_id(repo)].tree["PKGBUILD"]
        pkgbuild = blob.data.decode()
        match = re.search(
            r'^pkgver\s*=\s*["\']?([^\s"\']+)', pkgbuild, re.MULTILINE
        )
        if match:
            return match.group(1)
    except (KeyError, AttributeError, ValueError):
        pass
    return None


# The maintainer is a PKGBUILD comment, not a .SRCINFO field.  makepkg
# does not propagate it: checked against the AUR mirror, 0 of 200
# .SRCINFO files carry a `maintainer =` line, while every PKGBUILD opens
# with `# Maintainer: Name <email>`.  Reading .SRCINFO therefore always
# returned None, which silently disabled maintainer_changed, the
# maintainer novelty weight, and C006.
_MAINTAINER_COMMENT_RE = re.compile(
    r"^#\s*Maintainer\s*:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE
)
_MAINTAINER_SRCINFO_RE = re.compile(
    r"^\s*maintainer\s*=\s*(.+)", re.MULTILINE | re.IGNORECASE
)


def extract_maintainer(pkgbuild: str = "", srcinfo: str = "") -> Optional[str]:
    """Return the maintainer name, preferring the PKGBUILD comment.

    ``.SRCINFO`` is still consulted as a fallback: some tooling does
    write the field, and it costs nothing to accept it.
    """
    match = _MAINTAINER_COMMENT_RE.search(pkgbuild)
    if match:
        return match.group(1).strip()
    match = _MAINTAINER_SRCINFO_RE.search(srcinfo)
    if match:
        return match.group(1).strip()
    return None


def _read_blob(tree, name: str) -> str:
    try:
        return tree[name].data.decode("utf-8", errors="replace")
    except (KeyError, AttributeError, ValueError, TypeError):
        return ""


def get_maintainer_from_repo(repo: pygit2.Repository) -> Optional[str]:
    try:
        tree = repo[_head_commit_id(repo)].tree
    except (KeyError, AttributeError, ValueError, TypeError):
        return None
    return extract_maintainer(_read_blob(tree, "PKGBUILD"), _read_blob(tree, ".SRCINFO"))


def get_maintainer_from_commit(repo: pygit2.Repository, commit_oid: str) -> Optional[str]:
    try:
        commit = repo.get(commit_oid)
        tree = commit.tree
    except (KeyError, AttributeError, TypeError):
        return None
    if tree is None:
        return None
    return extract_maintainer(_read_blob(tree, "PKGBUILD"), _read_blob(tree, ".SRCINFO"))
