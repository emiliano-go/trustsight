"""The only place libgit2 is operated (A16).

Every function here takes a libgit2 repository/tree/blob and reads committed
objects.  It is imported by ``sandbox/git_worker.py`` (the isolated child) and
by nothing else in the production path: the parent reaches these operations
through the worker, never in-process.  Tests call them directly against a
fixture repository, which is why they are importable at all.

The pure helpers and the caps they honour live in :mod:`trustsight.differ`
(which no longer imports libgit2); this module imports them so there is one
copy of each.
"""

from __future__ import annotations

import difflib
import re
import time
from pathlib import Path

import pygit2
from pygit2 import (
    GIT_DELTA_ADDED,
    GIT_DELTA_DELETED,
    GIT_DELTA_MODIFIED,
    GIT_DELTA_RENAMED,
)

from ..coverage import note_stage_failure
from ..differ import (
    MAX_COMPANION_BYTES,
    MAX_COMPANION_FILES,
    MAX_DIFF_PATCHES,
    MAX_DIFF_SUMMARY_FILES,
    MAX_GENERATED_DIFF_BYTES,
    MAX_HISTORY_COMMITS,
    MAX_PATCH_BYTES,
    MAX_PATCH_SOURCE_BYTES,
    MAX_PKG_BUILD_BYTES,
    MAX_STREAM_BYTES,
    _COMPANION_INCOMPLETE,
    _COMPANION_MAX_BYTES,
    _bounded_path,
    _companion_names,
    _is_metadata_path,
    _top_level_blob,
    _tree_blob,
    truncate_diff,
)
from ..schema import DiffSummary
from ..tokenizer import split_lines
from .git_bounds import GIT_TREE_MAX_ENTRIES

__all__ = [
    "MAX_HISTORY_COMMITS",
    "generate_diff_bounded",
    "generate_diff",
    "changed_opaque_members",
    "binary_metadata_paths",
    "companion_source_hunks",
    "read_blob_head",
    "collect_tree_files",
    "walk_bounded",
    "head_commit_id",
    "parent_commit_id",
    "marker_path",
    "record_fetch",
    "last_fetch_time",
]

#: When the last successful fetch happened, recorded next to the repository.
#: Deliberately not derived from the HEAD commit's timestamp: a commit's date
#: is chosen by whoever authored it, so a maintainer who dates a commit in the
#: future would make the clone look permanently current.
_FETCH_MARKER = "trustsight-last-fetch"

#: Committed files whose *content* is worth more than their magic bytes (see
#: ``collect_tree_files``).
_COMPANION_CONTENT_RE = re.compile(
    r"(?:\.(?:service|socket|timer|path|mount|automount|target|desktop"
    r"|rules|conf|cfg|ini|install|hook|patch|diff|sh|bash|zsh|py|pl|rb)\Z"
    r"|(?:\A|/)(?:\.?[A-Za-z0-9_.-]+\.d/|PKGBUILD\Z|\.SRCINFO\Z))",
    re.IGNORECASE,
)

#: Per-file and whole-tree ceilings on the selective read.
_COMPANION_HEAD_BYTES = 16 * 1024
_COMPANION_TOTAL_BYTES = 512 * 1024

_DELTA_STATUS_MAP = {
    GIT_DELTA_ADDED: "added",
    GIT_DELTA_DELETED: "removed",
    GIT_DELTA_MODIFIED: "modified",
    GIT_DELTA_RENAMED: "renamed",
}

#: Suffixes whose bytes the text rules never read.  A change to one of these
#: produces an empty diff: git emits no content for a binary file, so the
#: *only* observable is the blob's identity.
_OPAQUE_MEMBER_RE = re.compile(
    r"\.(?:bin|so(?:\.\d+)*|a|o|ko|dylib|dll|exe|elf|jar|war|apk|whl|gem"
    r"|tar|tgz|gz|bz2|xz|zst|zip|7z|rar|deb|rpm|pkg|img|iso|db|sqlite3?"
    r"|png|jpg|jpeg|gif|ico|pdf|woff2?|ttf|otf)$",
    re.IGNORECASE,
)

#: Read size when draining a streamed blob.  Only the head is kept.
_DRAIN_CHUNK_BYTES = 256 * 1024


def _delta_side_size(side) -> int:
    """One side's declared size, or 0 when libgit2 does not report it.

    A missing or nonsensical size is treated as 0 rather than as unbounded:
    the byte caps downstream still apply, and refusing to read a patch whose
    size libgit2 declined to state would drop ordinary deltas.
    """
    size = getattr(side, "size", 0)
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return 0
    return size


def generate_diff_bounded(
    repo: pygit2.Repository, old_oid: str, new_oid: str, context_lines: int = 3,
    max_bytes: int | None = None,
) -> tuple[str, DiffSummary, bool]:
    """Generate a unified diff, and say whether anything was dropped.

    The third value is the truncation flag, and it is the reason this helper
    exists rather than the two-value form alone. A caller that re-derives
    truncation by measuring the returned text cannot see a patch this
    function *declined to retain*: the assembled text is then at or under the
    cap, measuring it reports "complete", and content has been skipped with
    no coverage gap recorded. That is the silent-skip B2 forbids, so the flag
    travels rather than being inferred.

    Three bounds apply, and each is on what gets *allocated* rather than on
    what survives:

    * ``MAX_PATCH_BYTES`` - ``patch.text`` materialises a whole patch, so a
      cap applied afterwards bounds only what is kept. A patch over this
      limit contributes its bounded prefix and sets truncation.
    * ``MAX_DIFF_PATCHES`` - the metadata filter accepts every ``.install``
      file, and a repository may contain any number of them.
    * ``MAX_DIFF_SUMMARY_FILES`` - the summary walks every delta regardless
      of the text cap, so a wide repository would otherwise choose the size
      of a stored ``fact_json``.

    Policy omission is not truncation. Dropping a ``.png`` because the filter
    does not read it leaves nothing unexamined; dropping a ``.install``
    because a cap was reached does. Only the second sets the flag.
    """
    old_commit = repo.get(old_oid) if old_oid else None
    new_commit = repo.get(new_oid)
    if (old_oid and old_commit is None) or new_commit is None:
        return "", DiffSummary(), False

    if max_bytes is None:
        max_bytes = MAX_GENERATED_DIFF_BYTES
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    max_bytes = min(max_bytes, MAX_GENERATED_DIFF_BYTES)

    if old_commit is None:
        # No base: the whole recipe, as if every file had just been added.
        diff = new_commit.tree.diff_to_tree(context_lines=context_lines, swap=True)
    else:
        diff = repo.diff(old_commit.tree, new_commit.tree, context_lines=context_lines)

    filtered_patches: list[str] = []
    generated_bytes = 0
    truncated = False

    for patch in diff:
        delta = patch.delta
        if not (_is_metadata_path(delta.new_file.path)
                or _is_metadata_path(delta.old_file.path)):
            continue
        if len(filtered_patches) >= MAX_DIFF_PATCHES:
            truncated = True
            break
        remaining = max_bytes - generated_bytes
        if remaining <= 0:
            truncated = True
            break

        # Before `patch.text`, not after: that attribute materialises the
        # whole patch, so every later cap bounds retention rather than
        # allocation. The delta knows both file sizes already.
        declared = max(_delta_side_size(delta.old_file),
                       _delta_side_size(delta.new_file))
        if declared > MAX_PATCH_SOURCE_BYTES:
            # Skipped rather than fatal: one oversized `.install` must not
            # stop the PKGBUILD beside it being read.
            truncated = True
            continue

        text = patch.text or ""
        # One bound, not two: the per-patch ceiling and what the running
        # total can still accept are both byte limits on the same string, and
        # truncating twice encodes it twice for no additional safety.
        text, cut = truncate_diff(text, min(MAX_PATCH_BYTES, remaining))
        if cut:
            truncated = True
        generated_bytes += len(text.encode("utf-8", errors="replace"))
        filtered_patches.append(text)

    unified = "\n".join(filtered_patches)
    lines_added = diff.stats.insertions
    lines_removed = diff.stats.deletions

    seen: set[str] = set()
    file_changes: list[dict] = []
    summary_full = False
    for delta in diff.deltas:
        if len(seen) >= MAX_DIFF_SUMMARY_FILES:
            summary_full = True
            break
        status = _DELTA_STATUS_MAP.get(delta.status, "modified")
        path = _bounded_path(
            delta.new_file.path if delta.status != GIT_DELTA_DELETED
            else delta.old_file.path
        )
        if path in seen:
            continue
        seen.add(path)
        if path not in (".SRCINFO", ".gitignore"):
            file_changes.append({"path": path, "status": status})

    # A summary cut short hides which files moved, which is content the
    # reader would otherwise have seen.
    if summary_full:
        truncated = True

    file_changes.sort(key=lambda item: (item["path"], item["status"]))
    summary = DiffSummary(
        lines_added=lines_added,
        lines_removed=lines_removed,
        files_changed=sorted(seen),
        file_changes=file_changes,
    )

    return unified, summary, truncated


def generate_diff(
    repo: pygit2.Repository, old_oid: str, new_oid: str, context_lines: int = 3,
    max_bytes: int | None = None,
) -> tuple[str, DiffSummary]:
    """Two-value form, for callers that do not consume the truncation flag."""
    text, summary, _truncated = generate_diff_bounded(
        repo, old_oid, new_oid, context_lines, max_bytes
    )
    return text, summary


def read_blob_head(blob, limit: int, max_stream_bytes: int = MAX_STREAM_BYTES):
    """The first *limit* bytes of *blob*, or None if it could not be read.

    ``blob.data`` materialises the whole blob, so taking a slice of it
    bounds what is *kept*, not what is read.  Above a small size the head is
    streamed instead - and streaming has a trap: ``pygit2.BlobIO`` feeds
    from a worker thread through a ``Queue(maxsize=1)`` and ``close()``
    joins that thread, so reading 64 bytes of a 1 MiB blob and closing
    parks the writer on a full queue forever.  The rest is drained before
    close, which holds memory at one chunk and costs time linear in the
    blob - hence the ceiling above it.
    """
    size = getattr(blob, "size", 0)
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        # An unknown or nonsensical declared size is treated as unread: the
        # head is reported missing rather than the whole blob materialised
        # to discover its length.
        return None
    if size <= max(limit, 512 * 1024):
        try:
            return blob.data[:limit]
        except (KeyError, TypeError, ValueError):
            return None
    if size > max_stream_bytes:
        return None
    try:
        stream = pygit2.BlobIO(blob)
    except Exception:
        return None
    try:
        head = stream.read(limit)
        while stream.read(_DRAIN_CHUNK_BYTES):
            pass
        return head
    except Exception:
        return None
    finally:
        try:
            stream.close()
        except Exception:
            pass


def changed_opaque_members(repo, old_oid: str, new_oid: str) -> list[str]:
    """Committed files whose bytes changed but whose diff is empty.

    A git blob id is a content hash, so comparing the two trees answers
    "did this file change" exactly, without reading either version - which
    matters because these are the members the analysis deliberately does
    not read. H066 claims a committed ELF's *presence*; it reports the same
    thing whether the binary was replaced or left alone, because git emits
    no diff body for it.

    Cheap by construction: the ids are already in the tree objects, so this
    is a walk of two manifests and no blob reads at all.
    """
    def members(oid: str) -> dict[str, str]:
        commit = repo.get(oid) if oid else None
        if commit is None:
            return {}
        found: dict[str, str] = {}
        try:
            for entry in commit.tree:
                if getattr(entry, "type_str", None) != "blob":
                    continue
                if _OPAQUE_MEMBER_RE.search(entry.name):
                    found[entry.name] = str(entry.id)
        except (KeyError, AttributeError, TypeError, ValueError):
            return {}
        return found

    before, after = members(old_oid), members(new_oid)
    return sorted(
        name for name, oid in after.items()
        if name in before and before[name] != oid
    )


def binary_metadata_paths(repo, old_oid: str, new_oid: str) -> list[str]:
    """Metadata files git refused to diff because they are binary.

    ``generate_diff_bounded`` reads ``patch.text``, and for a binary delta
    that is the single line ``Binary files a/PKGBUILD and b/PKGBUILD
    differ``: no added line, no source URL, no rule.  A PKGBUILD with one
    NUL byte therefore analyses as a clean, empty change while ``bash``
    sources it normally, which is exactly the silent skip B2 forbids.

    Detected from the delta flag rather than the text so an added file and a
    replaced one are both caught, and so a ``.gitattributes`` marking a
    metadata file binary is caught without a NUL.
    """
    old_commit = repo.get(old_oid) if old_oid else None
    new_commit = repo.get(new_oid) if new_oid else None
    if old_commit is None or new_commit is None:
        return []
    try:
        diff = repo.diff(old_commit.tree, new_commit.tree, context_lines=0)
    except (KeyError, AttributeError, TypeError, ValueError):
        return []
    found: list[str] = []
    for patch in diff:
        delta = patch.delta
        new_path = delta.new_file.path
        old_path = delta.old_file.path
        if not (_is_metadata_path(new_path) or _is_metadata_path(old_path)):
            continue
        if not delta.is_binary:
            continue
        path = old_path if delta.status == GIT_DELTA_DELETED else new_path
        if path and path not in found:
            found.append(path)
    return found


class _IndentInsensitiveLine(str):
    """A diff line that compares equal when only its indentation moved.

    ``difflib`` is given these objects, so a reindented companion produces
    no hunk while the lines it does emit keep their original spelling.
    """

    __slots__ = ()

    def __eq__(self, other):
        return self.lstrip() == str(other).lstrip()

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.lstrip())


def _companion_diff(old_lines: list[str], new_lines: list[str],
                    name: str) -> list[str]:
    return list(difflib.unified_diff(
        [_IndentInsensitiveLine(line) for line in old_lines],
        [_IndentInsensitiveLine(line) for line in new_lines],
        fromfile=f"a/{name}", tofile=f"b/{name}", lineterm=""))


def _whole_file_hunk(name: str, lines: list[str]) -> list[str]:
    return [
        "--- /dev/null",
        f"+++ b/{name}",
        f"@@ -0,0 +1,{len(lines)} @@",
    ] + ["+" + line for line in lines]


def companion_source_hunks(
    repo: pygit2.Repository, commit_oid: str, max_bytes: int = _COMPANION_MAX_BYTES,
    baseline_oid: str = "", present_before: list[str] | None = None,
) -> tuple[str, bool]:
    """Committed companion files as added-file hunks, and whether any was cut.

    The second element is the honest half.  Every bound in this function
    used to drop content and say nothing, so a payload past the budget
    scored the same as a package with no companions at all.

    Every committed text file the PKGBUILD names (a declared ``source=()``
    entry or one it merely executes/sources/patches by path) is emitted as
    a ``+++ b/<name>`` hunk, so the ordinary line rules, the tokenizer and
    ``map_diff_lines`` see it with correct file attribution.  Binary and ELF
    files are left out: H066-tree already owns embedded binaries, and text
    rules over binary bytes are noise.

    With *baseline_oid*, a companion the baseline PKGBUILD already named is
    diffed instead of replayed in full: unchanged content contributes no
    hunk, and a changed file contributes only its added lines.  Otherwise
    every update scored an install file, a cleanup trap or a Documentation=
    URL that had not moved.  A file the baseline did not name is still
    emitted whole, so a payload committed earlier and merely referenced now
    is read.

    *present_before*, when given, collects the whole content of companions
    the baseline already named and whose bytes did not move.  That content
    is not analysis input; the caller reports it at weight 0 so an unchanged
    trap or Documentation= link is listed rather than silently vanishing.
    """
    max_bytes = max(1, min(max_bytes, MAX_COMPANION_BYTES))
    commit = repo.get(commit_oid)
    if commit is None:
        return "", False
    pkgbuild = _top_level_blob(commit.tree, "PKGBUILD")
    if pkgbuild is None:
        # No PKGBUILD is not a truncation: there is nothing to companion.
        return "", False
    try:
        blob = repo[pkgbuild.id]
        # Size before any read: `blob.data` materialises the whole blob, so a
        # check afterwards bounds what is kept rather than what is read.  The
        # companion names come from this text, so a cut PKGBUILD means
        # companions this scan will never know to look for - which is a
        # truncation, not an absence.
        if getattr(blob, "size", 0) > MAX_PKG_BUILD_BYTES:
            return "", True
        head = read_blob_head(blob, MAX_PKG_BUILD_BYTES)
        if head is None:
            return "", True
        pkgbuild_text = head.decode("utf-8", errors="replace")
    except (KeyError, TypeError, ValueError):
        return "", True

    hunks: list[str] = []
    used = 0
    present_used = 0
    truncated = False
    baseline_tree = None
    baseline_selected: set[str] = set()
    if baseline_oid and baseline_oid != commit_oid:
        base = repo.get(baseline_oid)
        if base is not None:
            base_pkgbuild = _top_level_blob(base.tree, "PKGBUILD")
            if base_pkgbuild is not None:
                try:
                    base_blob = repo[base_pkgbuild.id]
                    if getattr(base_blob, "size", 0) <= MAX_PKG_BUILD_BYTES:
                        base_head = read_blob_head(
                            base_blob, MAX_PKG_BUILD_BYTES)
                        if base_head is not None:
                            baseline_tree = base.tree
                            baseline_selected = set(_companion_names(
                                base.tree,
                                base_head.decode("utf-8", errors="replace")))
                except (KeyError, TypeError, ValueError):
                    # An unreadable baseline falls back to the full scan: it
                    # over-scores rather than silently skipping a companion.
                    baseline_tree = None
    selected = set(_companion_names(commit.tree, pkgbuild_text))
    if _COMPANION_INCOMPLETE in selected:
        # The *selection* was cut, not just the reading: a name past the
        # length cap, or a tree with more entries than the walk inspects.
        selected.discard(_COMPANION_INCOMPLETE)
        truncated = True
    names = sorted(selected)
    if len(names) > MAX_COMPANION_FILES:
        truncated = True
    # An equal share per named file rather than one pool drained in sort
    # order.  A single pool is a starvation primitive: commit a large benign
    # file whose name sorts first, and it consumes the whole budget before
    # the payload file is reached - the attacker picks both names, so they
    # pick the order.  Sharing spends no more bytes in total, it only stops
    # one file deciding how much the others get.
    selected = names[:MAX_COMPANION_FILES]
    share = max(4096, max_bytes // max(1, len(selected)))
    for name in selected:
        entry = _tree_blob(commit.tree, name)
        if entry is None:
            continue
        old_entry = (
            _tree_blob(baseline_tree, name)
            if baseline_tree is not None and name in baseline_selected
            else None
        )
        if old_entry is not None and old_entry.id == entry.id:
            # Already present at the baseline and still referenced: it was
            # scored when it arrived, and replaying it as added lines made
            # every later update start at the same baseline noise.  Its
            # content is still collected for the weight-0 "present before"
            # report when the caller asked for it.
            if present_before is not None and present_used < max_bytes:
                try:
                    blob = repo[entry.id]
                    remaining = min(share, max_bytes - present_used)
                    data = read_blob_head(blob, remaining)
                except (KeyError, TypeError, ValueError):
                    data = None
                if (data is not None and b"\x00" not in data[:8192]
                        and data[:4] != b"\x7fELF"):
                    lines = split_lines(
                        data.decode("utf-8", errors="replace"))
                    if lines:
                        chunk = _whole_file_hunk(name, lines)
                        if present_used + sum(len(line) + 1 for line in chunk) <= max_bytes:
                            present_before.append("\n".join(chunk))
                            present_used += sum(len(line) + 1 for line in chunk)
            continue
        remaining = min(share, max_bytes - used)
        if remaining <= 0:
            truncated = True
            break
        try:
            blob = repo[entry.id]
        except (KeyError, TypeError, ValueError):
            truncated = True
            continue
        # An oversized companion used to `break` here, unread and unrecorded.
        # Both halves of that were wrong.  `break` meant one padded benign
        # file - which sorts wherever the attacker names it - ended the loop
        # for every companion after it, so a small payload file placed later
        # was never read either.  And nothing said so: the promise in
        # `analyze_package` that a companion's "committed content is scanned
        # with the same rules" silently stopped holding, while the verdict
        # still read Low.  The head is now read within the remaining budget,
        # the loop continues to the next file, and what was cut is reported.
        oversized = getattr(blob, "size", 0) > remaining
        data = read_blob_head(blob, remaining)
        if data is None:
            truncated = True
            continue
        if oversized:
            truncated = True
        # NUL in the head marks a binary; ELF is H066's job, not the text
        # rules'.  Deliberately *not* recorded as a truncation: H066-tree
        # reads the manifest and owns committed binaries, so this surface is
        # examined by another rule rather than left unexamined - and a gap
        # here would fire on every package that commits an icon.
        if b"\x00" in data[:8192] or data[:4] == b"\x7fELF":
            continue
        text = data.decode("utf-8", errors="replace")
        new_lines = split_lines(text)
        if not new_lines:
            continue

        if old_entry is None:
            chunk = _whole_file_hunk(name, new_lines)
        else:
            # A companion the baseline already named: only the lines this
            # update adds are new evidence.  Context lines stay visible to
            # the reader but are not scored as additions.
            try:
                old_blob = repo[old_entry.id]
            except (KeyError, TypeError, ValueError):
                truncated = True
                old_blob = None
            old_lines = None
            if old_blob is not None:
                if getattr(old_blob, "size", 0) > remaining:
                    truncated = True
                old_data = read_blob_head(old_blob, remaining)
                if old_data is not None and b"\x00" not in old_data[:8192]:
                    old_lines = split_lines(
                        old_data.decode("utf-8", errors="replace"))
            if old_lines is None:
                # The prior text is unavailable; keep the conservative
                # whole-file scan rather than call an unread change clean.
                chunk = _whole_file_hunk(name, new_lines)
            else:
                chunk = _companion_diff(old_lines, new_lines, name)
        lines: list[str] = []
        for ln in chunk:
            if used + len(ln) + 1 > max_bytes:
                truncated = True
                break
            lines.append(ln)
            used += len(ln) + 1
        if not lines:
            continue
        hunks.append("\n".join(lines))
    return "\n".join(hunks), truncated


def head_commit_id(repo) -> str:
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
            return str(repo.references[ref_name].peel().id)
        except (TypeError, pygit2.GitError):
            pass
    raise pygit2.GitError("cannot resolve HEAD to a commit")


def parent_commit_id(repo, head_commit: str) -> str:
    """The first parent of *head_commit*, or ``""`` when there is none."""
    if not head_commit:
        return ""
    try:
        commit = repo[head_commit]
        parents = commit.parents
    except (KeyError, IndexError, AttributeError, pygit2.GitError, TypeError):
        return ""
    return str(parents[0].id) if parents else ""


def walk_bounded(repo, head, *, sort=None, limit=None):
    """Yield at most *limit* commits from *head*, newest first.

    One implementation rather than a counter at each call site: the review
    notes name "a control applied at one of several equivalent call sites" as
    the recurring failure here, and unbounded walks were spread across three
    modules.
    """
    cap = MAX_HISTORY_COMMITS if limit is None else limit
    walker = repo.walk(head) if sort is None else repo.walk(head, sort)
    for seen, commit in enumerate(walker, start=1):
        yield commit
        if seen >= cap:
            return


def collect_tree_files(
    repo,
    commit_oid: str,
    max_file_bytes: int = 512 * 1024,
    head_bytes: int = 64,
    max_stream_bytes: int = 64 * 1024 * 1024,
    max_entries: int | None = GIT_TREE_MAX_ENTRIES,
) -> tuple[list[tuple[str, bytes]], bool]:
    """Walk a commit tree, returning ``([(path, first_bytes)], complete)``.

    ``complete`` is False when any member could not be read, so the caller can
    say the tree was not fully examined instead of implying it was.  A blob
    larger than *max_file_bytes* is streamed for its head rather than skipped
    (a committed payload is far more likely to be large than small), and an
    incomplete read reports as incomplete ([B2](../../docs/security.md)).

    *max_entries* is enforced **during** the walk, not after it: a repository
    is free to commit millions of tiny blobs, so a cap applied to the finished
    list bounds what is returned while the list itself has already grown
    without limit.  Reaching the cap stops the walk and reports incomplete.
    """
    files: list[tuple[str, bytes]] = []
    complete = True
    budget = _COMPANION_TOTAL_BYTES
    inspected = 0

    def head_of(blob, want: int) -> bytes | None:
        """The first *want* bytes of *blob*, or None if it was not read."""
        if blob.size <= max_file_bytes:
            try:
                return blob.data[:want]
            except (KeyError, TypeError, ValueError):
                note_stage_failure("tree-blob-read")
                return None
        if blob.size > max_stream_bytes:
            return None
        try:
            stream = pygit2.BlobIO(blob)
        except Exception:
            note_stage_failure("tree-blob-read")
            return None
        try:
            head = stream.read(want)
            # Drain, or close() blocks on the writer thread.
            while stream.read(_DRAIN_CHUNK_BYTES):
                pass
            return head
        except Exception:
            note_stage_failure("tree-blob-read")
            return None
        finally:
            try:
                stream.close()
            except Exception:
                pass

    # Iterative walk on an explicit stack: the tree's depth is the attacker's
    # choice, and a recursive walk raised RecursionError past the interpreter
    # limit - escaping analysis entirely instead of degrading to the gap.
    def walk(tree, prefix: str) -> None:
        nonlocal complete, budget, inspected
        stack = [(tree, prefix)]
        while stack:
            cur_tree, cur_prefix = stack.pop()
            for entry in cur_tree:
                # Checked here, before the entry is processed or its subtree
                # is pushed, so neither the file list nor the pending stack
                # can grow past the cap.
                if max_entries is not None and inspected >= max_entries:
                    complete = False
                    return
                inspected += 1
                if entry.type_str == "tree":
                    try:
                        stack.append((repo[entry.id], cur_prefix + entry.name + "/"))
                    except (KeyError, TypeError, ValueError):
                        complete = False
                elif entry.type_str == "blob":
                    try:
                        blob = repo[entry.id]
                    except (KeyError, TypeError, ValueError):
                        complete = False
                        continue
                    path = cur_prefix + entry.name
                    want = head_bytes
                    if budget > 0 and _COMPANION_CONTENT_RE.search(path):
                        want = max(head_bytes, min(_COMPANION_HEAD_BYTES, budget))
                    data = head_of(blob, want)
                    if data is None:
                        complete = False
                        continue
                    if want > head_bytes:
                        budget -= len(data)
                        if blob.size > len(data):
                            complete = False
                    files.append((path, data))

    try:
        commit = repo.get(commit_oid)
        if commit is not None:
            walk(commit.tree, "")
        else:
            complete = False
    except (KeyError, AttributeError, TypeError, ValueError):
        complete = False
    return files, complete


def marker_path(repo) -> Path:
    """Location of the last-fetch marker for *repo*."""
    return Path(repo.path) / _FETCH_MARKER


def record_fetch(repo):
    """Note that *repo* has just been brought up to date."""
    stamp = int(time.time())
    try:
        marker_path(repo).write_text(str(stamp))
    except OSError:
        return None
    return stamp


def last_fetch_time(repo):
    """When this clone was last fetched, or None if that is unknown."""
    try:
        return int(marker_path(repo).read_text().strip())
    except (OSError, ValueError):
        return None


def _is_current(repo, upstream_mtime) -> bool:
    """True when this clone was fetched after the upstream last changed.

    A clone with no fetch marker falls back to the local HEAD commit time, so
    an unchanged clone avoids an unnecessary network fetch.
    """
    fetched = last_fetch_time(repo)
    if fetched is not None:
        try:
            return fetched >= int(upstream_mtime)
        except (TypeError, ValueError):
            return False
    try:
        commit = repo.head.peel()
        return int(commit.commit_time) >= int(upstream_mtime)
    except (AttributeError, pygit2.GitError, KeyError, TypeError, ValueError):
        return False
