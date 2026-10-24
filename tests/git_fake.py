"""An in-process stand-in for ``git_client.GitProject``.

The parent holds a :class:`GitProject` and reads through the isolated worker.
Unit and regression tests do not need a subprocess: this adapter implements
the same read API by calling the same ``git_project`` functions the worker
calls, so the projection logic under test is identical.  Tests that want to
control a projection monkeypatch the ``git_project`` function, and both the
fake and the worker see it.
"""

from __future__ import annotations

import pygit2

from trustsight.sandbox import git_project
from trustsight.sandbox.git_client import _Commit


def _signature(commit, attr):
    sig = getattr(commit, attr)
    return getattr(sig, "name", "") or "", getattr(sig, "email", "") or ""


def _commit_from(commit):
    author_name, author_email = _signature(commit, "author")
    committer_name, committer_email = _signature(commit, "committer")
    return _Commit(
        str(commit.id), int(commit.commit_time),
        [str(p.id) for p in commit.parents], commit.message or "",
        author_name, author_email, committer_name, committer_email,
    )


class FakeGitProject:
    def __init__(self, repo, pkg="pkg", cache_dir=""):
        self._repo = repo
        self.pkg = pkg
        self.cache_dir = cache_dir
        self.closed = False

    def head_commit(self) -> str:
        try:
            return git_project.head_commit_id(self._repo)
        except pygit2.GitError:
            return ""

    def file_at(self, oid, name, max_bytes=None) -> str:
        if not oid:
            return ""
        try:
            commit = self._repo.get(oid)
            if not isinstance(commit, pygit2.Commit):
                return ""
            data = commit.tree[name].data
        except (KeyError, AttributeError, TypeError, ValueError):
            return ""
        if max_bytes is not None and len(data) > max_bytes:
            return ""
        return data.decode("utf-8", errors="replace")

    def walk(self, head, limit=None):
        return [
            _commit_from(c)
            for c in git_project.walk_bounded(self._repo, head, limit=limit)
        ]

    def commit_meta(self, oids):
        out = []
        for oid in oids:
            commit = self._repo.get(oid) if oid else None
            if isinstance(commit, pygit2.Commit):
                out.append(_commit_from(commit))
        return out

    def parent_commit(self, head) -> str:
        return git_project.parent_commit_id(self._repo, head)

    def diff_bounded(self, old, new, context_lines=3, max_bytes=None):
        return git_project.generate_diff_bounded(
            self._repo, old, new, context_lines, max_bytes)

    def tree_files(self, oid):
        return git_project.collect_tree_files(self._repo, oid)

    def companion_hunks(self, oid, max_bytes=None, baseline_oid=""):
        if max_bytes is None:
            return git_project.companion_source_hunks(
                self._repo, oid, baseline_oid=baseline_oid)
        return git_project.companion_source_hunks(
            self._repo, oid, max_bytes=max_bytes, baseline_oid=baseline_oid)

    def companion_hunks_with_present_before(
            self, oid, max_bytes=None, baseline_oid=""):
        present = []
        kwargs = {"baseline_oid": baseline_oid, "present_before": present}
        if max_bytes is None:
            text, truncated = git_project.companion_source_hunks(
                self._repo, oid, **kwargs)
        else:
            text, truncated = git_project.companion_source_hunks(
                self._repo, oid, max_bytes=max_bytes, **kwargs)
        return text, truncated, "\n".join(present)

    def opaque_changed(self, old, new):
        return git_project.changed_opaque_members(self._repo, old, new)

    def binary_meta(self, old, new):
        return git_project.binary_metadata_paths(self._repo, old, new)

    def last_fetch_time(self):
        return git_project.last_fetch_time(self._repo)

    def close(self):
        self.closed = True
