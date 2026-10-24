"""Extracted from differ.py: _companions."""

import fnmatch
import re
from ._bounds import MAX_COMPANION_BYTES, MAX_COMPANION_NAME_BYTES, MAX_COMPANION_TREE_ENTRIES, MAX_STREAM_BYTES
from ._common import _is_metadata_path
from ._sources import local_source_names

__all__ = ['_BINARY_DIFF_MARKER_RE', '_COMPANION_INCOMPLETE', '_COMPANION_MAX_BYTES', '_COMPANION_SKIP', '_DRAIN_CHUNK_BYTES', '_PATTERN_REF_RE', '_TOOL_CONTRACT_FILES', '_companion_names', '_is_safe_companion_name', '_referenced_by_pattern', '_top_level_blob', 'binary_metadata_in_text', 'binary_metadata_paths', 'changed_opaque_members', 'companion_source_hunks', 'read_blob_head']

_COMPANION_MAX_BYTES = MAX_COMPANION_BYTES

def _top_level_blob(tree, name: str):
    """The blob named *name* at the tree root, or None."""
    try:
        entry = tree[name]
    except (KeyError, TypeError):
        return None
    if getattr(entry, "type_str", None) != "blob":
        return None
    return entry

_COMPANION_SKIP = frozenset({"PKGBUILD", ".SRCINFO", ".gitignore"})

_COMPANION_INCOMPLETE = "\x00incomplete"

_TOOL_CONTRACT_FILES = (
    (re.compile(r"\b(?:npm|pnpm|yarn|bun)\b"), "package.json"),
    (re.compile(r"\bcargo\b"), "Cargo.toml"),
    (re.compile(r"\bcargo\b"), "build.rs"),
    (re.compile(r"\bcmake\b"), "CMakeLists.txt"),
    (re.compile(r"\bmeson\b"), "meson.build"),
    (re.compile(r"\bninja\b"), "build.ninja"),
    (re.compile(r"\b(?:gradle|gradlew)\b"), "build.gradle"),
    (re.compile(r"\bmvn\b|\bmaven\b"), "pom.xml"),
    (re.compile(r"\bgo\b\s+(?:build|install|run|generate)"), "go.mod"),
    # `go build` compiles every .go file in the module, and an `init()` runs
    # before `main`.  Loading go.mod alone read the manifest and none of the
    # code it names.
    (re.compile(r"\bgo\b\s+(?:build|install|run|generate)"), "main.go"),
    (re.compile(r"\bgo\b\s+(?:build|install|run|generate)"), "init.go"),
    (re.compile(r"\bdotnet\b"), "Program.cs"),
    (re.compile(r"\bpip[23]?\b|\bpython[23]?\s+-m\s+(?:pip|build)"), "setup.py"),
    (re.compile(r"\bpip[23]?\b|\bpython[23]?\s+-m\s+(?:pip|build)"), "pyproject.toml"),
    (re.compile(r"\bpip[23]?\b"), "requirements.txt"),
    (re.compile(r"\bbundle\b|\bgem\b"), "Gemfile"),
    (re.compile(r"\bcomposer\b"), "composer.json"),
    (re.compile(r"\bg?make\b"), "Makefile"),
    (re.compile(r"\bg?make\b"), "GNUmakefile"),
)

_PATTERN_REF_RE = re.compile(
    r"\A[\w./-]*(?:\$\{?\w+\}?|\*|\?|\[[^\]]+\])[\w./-]*\.[A-Za-z0-9_]+\Z"
)

def _referenced_by_pattern(name: str, pkgbuild_text: str) -> bool:
    """True when *name* matches a glob or variable reference in the recipe."""
    tokens = {
        token.strip("\"'();,")
        for token in pkgbuild_text.split()
        if ("$" in token or "*" in token or "?" in token or "[" in token)
        and "." in token
    }
    for token in tokens:
        if not _PATTERN_REF_RE.match(token):
            continue
        # A variable stands for an unknown run of characters, exactly as a
        # `*` does; both become one wildcard so the same matcher answers.
        pattern = re.sub(r"\$\{?\w+\}?", "*", token)
        if pattern in ("*", "*.*"):
            # A reference that matches everything names nothing: `$f` alone
            # would pull in every committed file.
            continue
        if fnmatch.fnmatchcase(name, pattern):
            return True
    return False

def _companion_names(tree, pkgbuild_text: str) -> list[str]:
    """Committed top-level files whose content the recipe pulls in.

    A file is included when it is a declared ``source=()`` entry *or* its name
    appears anywhere in the PKGBUILD: ``bash "${startdir}/helper.sh"`` names a
    committed file that makepkg never copies through ``source=()`` yet the
    build still executes, so declaring the source was never required to run
    it.  Tying the scan to files the recipe *names* keeps an unrelated
    committed blob out of it while leaving no referenced file unread.
    """
    unsafe_names = False
    declared = local_source_names(pkgbuild_text)
    # A build tool names its own input by contract, not by spelling it in the
    # recipe.  `npm install` reads package.json, `cargo build` reads
    # Cargo.toml and compiles build.rs, `cmake` reads CMakeLists.txt - each
    # of those files is committed code that runs at build time, and none of
    # them appears in the PKGBUILD text, so the name test above excluded
    # exactly the records whose contents matter most.
    implied = {
        name
        for pattern, name in _TOOL_CONTRACT_FILES
        if pattern.search(pkgbuild_text)
    }
    names: list[str] = []
    inspected = 0
    for entry in tree:
        # The walk is bounded, not just the selection: a tree is free to hold
        # any number of entries, and the per-file cap applies to what was
        # already chosen.
        if inspected >= MAX_COMPANION_TREE_ENTRIES:
            break
        inspected += 1
        if getattr(entry, "type_str", None) != "blob":
            continue
        name = entry.name
        if not _is_safe_companion_name(name):
            # A name past the length cap, or one that fails the safety
            # check, is a referenced file left unread.  Silence here was a
            # place to put a payload: 25 with a generic committed-exec
            # claim and no sign that anything had been skipped.
            unsafe_names = True
            continue
        if name in _COMPANION_SKIP:
            continue
        # `.install` used to be skipped here.  A scriptlet runs as root at
        # install time, and its body is the single most consequential text in
        # an AUR package; skipping it meant that a hook committed in an
        # earlier commit was never read at all, so a `post_install()` holding
        # `curl ... | bash` scored 15 for the attribute change and nothing
        # for the payload.  H017 reads hook lines from the diff; this makes
        # the committed body one of those lines.
        if (name in declared or name in implied or name in pkgbuild_text
                or _referenced_by_pattern(name, pkgbuild_text)):
            names.append(name)
    if inspected >= MAX_COMPANION_TREE_ENTRIES or unsafe_names:
        names.append(_COMPANION_INCOMPLETE)
    return names

def _is_safe_companion_name(name: str) -> bool:
    """Whether *name* is a plain, bounded, top-level filename.

    The scanner reads top-level blobs, so anything carrying path structure is
    not a name it can have produced honestly. Rejecting these here keeps an
    absolute path or a traversal component out of a rendered hunk header,
    where it would name a file the reader does not have.
    """
    if not name or len(name.encode("utf-8", errors="replace")) > MAX_COMPANION_NAME_BYTES:
        return False
    if name in (".", ".."):
        return False
    if name.startswith("/") or "/" in name or "\\" in name:
        return False
    return "\x00" not in name

_DRAIN_CHUNK_BYTES = 256 * 1024

def read_blob_head(blob, limit: int, max_stream_bytes: int = MAX_STREAM_BYTES):
    """The first *limit* bytes of *blob* (streaming work in git_project)."""
    from ..sandbox.git_project import read_blob_head as _core

    return _core(blob, limit, max_stream_bytes)

def changed_opaque_members(repo, old_oid: str, new_oid: str) -> list[str]:
    """Committed files whose bytes changed but whose diff is empty."""
    from ..sandbox.git_project import changed_opaque_members as _core

    return _core(repo, old_oid, new_oid)

_BINARY_DIFF_MARKER_RE = re.compile(
    r"^Binary files .*?(\S+?) and (\S+?) differ$", re.MULTILINE
)

def binary_metadata_paths(repo, old_oid: str, new_oid: str) -> list[str]:
    """Metadata files git refused to diff as binary (work in git_project)."""
    from ..sandbox.git_project import binary_metadata_paths as _core

    return _core(repo, old_oid, new_oid)

def binary_metadata_in_text(diff_text: str) -> list[str]:
    """Metadata paths a git-generated text diff marked binary.

    The text path (``scan_diff``, the corpus adapter) has no repository to
    ask, so it reads the marker git wrote instead.  Same skip, different
    source of the fact.
    """
    found: list[str] = []
    for match in _BINARY_DIFF_MARKER_RE.finditer(diff_text):
        for raw in (match.group(1), match.group(2)):
            path = raw[2:] if raw.startswith(("a/", "b/")) else raw
            if _is_metadata_path(path) and path not in found:
                found.append(path)
    return found

def companion_source_hunks(
    repo, commit_oid: str, max_bytes: int = _COMPANION_MAX_BYTES,
    baseline_oid: str = "", present_before: list[str] | None = None,
) -> tuple[str, bool]:
    """Committed companion files as added-file hunks (git work in git_project)."""
    from ..sandbox.git_project import companion_source_hunks as _core

    return _core(repo, commit_oid, max_bytes, baseline_oid, present_before)
