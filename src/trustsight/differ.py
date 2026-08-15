import re

import pygit2
from pygit2 import GIT_DELTA_ADDED, GIT_DELTA_DELETED, GIT_DELTA_MODIFIED, GIT_DELTA_RENAMED

from .schema import DiffSummary, SourceChanges

_HUNK_HEADER_RE = re.compile(
    r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@"
)

# These are parser-side safety rails; the pipeline's configured diff cap still
# owns the final coverage decision for an analysis.
MAX_GENERATED_DIFF_BYTES = 5 * 1024 * 1024
MAX_COMPANION_BYTES = 65536
MAX_COMPANION_FILES = 256
MAX_DIFF_PATH_BYTES = 4096

#: Filtered patches whose text is retained.  The byte cap bounds how much
#: text is kept; this bounds how many patches are *visited*, because a
#: repository is free to contain a hundred thousand ``.install`` files and
#: the filter accepts every one of them.
MAX_DIFF_PATCHES = 256

#: File paths retained in a summary.  ``files_changed`` and ``file_changes``
#: walk every delta regardless of the text cap, so without this a wide
#: repository sets the size of a stored ``fact_json``.
MAX_DIFF_SUMMARY_FILES = 4096

#: One patch's text, read before it is joined.  ``patch.text`` materialises
#: the whole patch, so a bound applied after that call is a bound on what is
#: *kept* rather than on what is *allocated* - the same distinction A4 draws
#: for a tar member's declared size.
MAX_PATCH_BYTES = 1024 * 1024

#: The largest side of a delta whose patch text will be requested at all.
#:
#: ``MAX_PATCH_BYTES`` bounds what is *kept* from ``patch.text``, but that
#: attribute has already allocated the whole patch by the time it returns, so
#: on its own it is a bound on retention rather than on memory. The delta
#: carries each side's file size before any text is produced, and a patch is
#: at most the changed lines plus context - so a file small on both sides
#: cannot yield a large patch. Checking the declared sizes first is the only
#: bound available *before* the allocation.
MAX_PATCH_SOURCE_BYTES = 2 * 1024 * 1024

#: Bytes of the PKGBUILD read to drive companion discovery.  The blob is
#: attacker-authored, and ``blob.data`` materialises all of it, so the bound
#: has to precede the read rather than the decode.
MAX_PKG_BUILD_BYTES = 5 * 1024 * 1024

#: Top-level tree entries inspected while looking for companions.  The
#: per-file cap is applied to the *selected* set, so without this the walk
#: that builds that set is itself unbounded.
MAX_COMPANION_TREE_ENTRIES = 4096

#: A referenced basename.  A name past this is not a filename an ordinary
#: recipe uses, and retaining it would put attacker-chosen bytes of arbitrary
#: length into a rendered hunk header.
MAX_COMPANION_NAME_BYTES = 256
MAX_URLS_PER_SIDE = 4096
MAX_URL_TOKEN_BYTES = 8192
MAX_DIFF_BYTES = 5 * 1024 * 1024


def truncate_diff(diff_text: str, max_bytes: int = MAX_DIFF_BYTES) -> tuple[str, bool]:
    """Return a deterministic UTF-8-safe prefix and truncation status."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    max_bytes = min(max_bytes, MAX_DIFF_BYTES)
    encoded = diff_text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return diff_text, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def map_diff_lines(diff_text: str) -> dict[int, tuple[str, int]]:
    """Map diff-line index → (file_name, new_file_line_number).

    Returns a dict keyed by the 0-based line index into *diff_text*'s
    lines, with each value being ``(file_name, line_number)``.
    Only content lines (`` `` context, ``+`` addition, ``-`` removal)
    produce entries; header lines are not mapped.
    """
    mapping: dict[int, tuple[str, int]] = {}
    lines = diff_text.splitlines()
    current_file = "PKGBUILD"
    new_lineno = 0
    in_hunk = False

    for i, line in enumerate(lines):
        if line.startswith("+++ "):
            # removeprefix, not lstrip: lstrip("b/") strips *characters*,
            # so "+++ b/build.sh" reported the file as "uild.sh" and every
            # finding in it cited a path that does not exist.
            name = line[4:].strip()
            current_file = name.removeprefix("b/") if name.startswith("b/") else name
            current_file = current_file[:MAX_DIFF_PATH_BYTES]
            continue
        if line.startswith("--- "):
            continue
        m = _HUNK_HEADER_RE.match(line)
        if m:
            try:
                new_lineno = int(m.group(1))
            except ValueError:
                in_hunk = False
                continue
            in_hunk = True
            continue
        if in_hunk and line.startswith(("+", " ", "-")):
            mapping[i] = (current_file, new_lineno)
            if line.startswith(("+", " ")):
                new_lineno += 1

    return mapping

_DELTA_STATUS_MAP = {
    GIT_DELTA_ADDED: "added",
    GIT_DELTA_DELETED: "removed",
    GIT_DELTA_MODIFIED: "modified",
    GIT_DELTA_RENAMED: "renamed",
}


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


def _is_metadata_path(path: str) -> bool:
    """Whether a delta path is one the analysis reads."""
    return (path in ("PKGBUILD", ".SRCINFO")
            or path.endswith(".install"))


def _bounded_path(path: str) -> str:
    """A path bounded for retention in a summary."""
    encoded = path.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_DIFF_PATH_BYTES:
        return path
    return encoded[:MAX_DIFF_PATH_BYTES].decode("utf-8", errors="ignore")


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
    old_commit = repo.get(old_oid)
    new_commit = repo.get(new_oid)
    if old_commit is None or new_commit is None:
        return "", DiffSummary(), False

    if max_bytes is None:
        max_bytes = MAX_GENERATED_DIFF_BYTES
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    max_bytes = min(max_bytes, MAX_GENERATED_DIFF_BYTES)

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
    """Two-value form, for callers that do not consume the truncation flag.

    Kept so existing callers and tests are unaffected. New code should use
    :func:`generate_diff_bounded`, because dropping the flag is exactly how a
    skipped patch becomes invisible.
    """
    text, summary, _truncated = generate_diff_bounded(
        repo, old_oid, new_oid, context_lines, max_bytes
    )
    return text, summary


_VCS_SOURCE_RE = re.compile(
    r"^\+(?:.*\b(?:git\+https?://|git://|svn://|hg://|bzr://|svn\+https?://|git\+ssh://))",
    re.IGNORECASE,
)
_GIT_PKG_RE = re.compile(r"^\+\s*source\s*=.*\.git\b", re.IGNORECASE)
_SIG_SRC_RE = re.compile(r"\.(?:sig|asc)[\'\"]?\s*$", re.IGNORECASE)
_VALIDPGPKEYS_RE = re.compile(r"^\+\s*validpgpkeys\s*=\s*\(", re.IGNORECASE)
_DKMS_RE = re.compile(r"^\+\s*DKMS", re.IGNORECASE)

_SKIP_JUSTIFICATION_CHECKS = [
    ("vcs source", lambda t: bool(_VCS_SOURCE_RE.search(t) or _GIT_PKG_RE.search(t) or _DKMS_RE.search(t))),
    ("signature file", lambda t: bool(_SIG_SRC_RE.search(t))),
    ("validpgpkeys present", lambda t: bool(_VALIDPGPKEYS_RE.search(t))),
]


def is_skip_justified(diff_text: str) -> str:
    """Check whether a ``SKIP`` checksum has a valid justification.

    Returns a short reason string (truthy) or ``""`` (falsy).
    """
    for reason, check in _SKIP_JUSTIFICATION_CHECKS:
        if any(check(line) for line in diff_text.splitlines()):
            return reason
    return ""


_URL_TOKEN_RE = re.compile(r"https?://[^\s\'\"\)]+")


def _clean_url(token: str) -> str:
    token = re.sub(r"[\)]+$", "", token)
    token = re.sub(r"[\)]+", ")", token)
    token = re.sub(r"[,;\s]+$", "", token)
    return token


def extract_urls_from_diff(diff_text: str) -> SourceChanges:
    """Extract added and removed URLs from a diff."""
    added_urls: set[str] = set()
    removed_urls: set[str] = set()

    for line in diff_text.splitlines():
        if line.startswith("+") and "http" in line:
            for u in _URL_TOKEN_RE.findall(line):
                if len(added_urls) < MAX_URLS_PER_SIDE and len(u) <= MAX_URL_TOKEN_BYTES:
                    added_urls.add(_clean_url(u))
        elif line.startswith("-") and "http" in line:
            for u in _URL_TOKEN_RE.findall(line):
                if len(removed_urls) < MAX_URLS_PER_SIDE and len(u) <= MAX_URL_TOKEN_BYTES:
                    removed_urls.add(_clean_url(u))

    checksum_behavior = detect_checksum_changes(diff_text)

    return SourceChanges(
        added_urls=sorted(added_urls),
        removed_urls=sorted(removed_urls),
        checksum_behavior=checksum_behavior,
    )


_CHECKSUM_VARS = "sha256sums|sha512sums|sha1sums|sha224sums|sha384sums|b2sums|md5sums"

_CHK_DECL_RE = re.compile(
    r"^\s*(?:" + _CHECKSUM_VARS + r")\s*=\s*", re.IGNORECASE,
)


def _added_checksum_arrays(diff_text: str) -> list[tuple[str, str]]:
    """``(var, contents)`` for each added checksum declaration.

    A declaration's array may span several lines (the usual PKGBUILD
    formatting splits ``sha256sums=(``, one quoted hash per ``+`` line, and
    a closing ``)``), so *contents* accumulates continuation lines until the
    array's closing ``)``.  Only added (``+``) lines contribute.
    """
    arrays: list[tuple[str, str]] = []
    cur_var: str | None = None
    cur_content: list[str] = []

    def flush() -> None:
        nonlocal cur_var, cur_content
        if cur_var is not None:
            arrays.append((cur_var, "\n".join(cur_content)))
        cur_var = None
        cur_content = []

    for line in diff_text.splitlines():
        if line.startswith(("-", "+++", "---", "@@")):
            continue
        if not line.startswith("+"):
            continue
        body = line[1:]
        m = _CHK_DECL_RE.match(body)
        if m:
            flush()
            cur_var = m.group(0).split("=", 1)[0].strip()
            rest = body[m.end():]
            cur_content.append(rest)
            if ")" in rest:
                flush()
            continue
        if cur_var is not None:
            cur_content.append(body)
            if ")" in body:
                flush()
    flush()
    return arrays


_CHK_HASH_CHAR_RE = re.compile(r"[0-9A-Za-z+/=]")
_CHK_SKIP_WORD_RE = re.compile(r"[\'\"]?(?:SKIP|NONE)[\'\"]?")


def detect_checksum_changes(diff_text: str) -> str:
    """Detect checksum-related changes in a diff.

    Deliberately reports only on the ``sha256sums`` array (PKU's default
    checksum), and correctly handles the multiline form: a diff that adds
    ``sha256sums=(\n  'SKIP'\n)`` must read as *skip*, not ``unchanged``.
    """
    for var, contents in _added_checksum_arrays(diff_text):
        if var != "sha256sums":
            continue
        if _CHK_SKIP_WORD_RE.search(contents):
            return "changed_from_sha256_to_skip"
        if "(" in contents and not _CHK_HASH_CHAR_RE.search(contents):
            return "checksum_array_emptied"
        return "checksum_added_or_changed"
    return "unchanged"


_CHECKSUM_LINE_RE = re.compile(
    r"(?:" + _CHECKSUM_VARS + r")\s*=",
    re.IGNORECASE,
)

# ``source=(... $(cmd) ...)`` or backticks inside the source array: the
# source list is data, and a command substitution there executes at parse
# time, before any rule that inspects build() has anything to look at.
_SOURCE_CMD_SUBST_RE = re.compile(
    r"^\+\s*(?:_?\w*source\w*)\s*=\s*\(?[^)]*(?:\$\(|`)",
    re.IGNORECASE,
)


def detect_checksum_removed(diff_text: str) -> bool:
    """Detect a checksum array deleted without a replacement.

    Distinct from ``checksum_array_emptied`` (``sha256sums=()`` added):
    here the declaration disappears from the file entirely, which leaves
    makepkg with nothing to verify.
    """
    removed = False
    added = False
    for line in diff_text.splitlines():
        if line.startswith("-") and _CHECKSUM_LINE_RE.search(line):
            removed = True
        elif line.startswith("+") and _CHECKSUM_LINE_RE.search(line):
            added = True
    return removed and not added


_SOURCE_ARRAY_START_RE = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*\(")


def extract_source_array_urls(diff_text: str, side: str = "after") -> set[str]:
    """URLs declared in ``source=()``, on one side of the diff.

    Distinct from :func:`extract_urls_from_diff`, which collects URLs from
    *any* added line.  R061 asks whether a download inside ``build()`` is
    also a declared source, and the broader helper would include the
    download's own URL, so the comparison could never fail.

    ``side="after"`` is the post-diff end-state (the default, which R061
    relies on); ``side="before"`` is the pre-diff state, so R064 can tell a
    URL that was downgraded from one that was always plain http.
    """
    skip = "-" if side == "after" else "+"
    urls: set[str] = set()
    in_array = False
    for line in diff_text.splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith(skip):
            continue
        body = line[1:] if line[:1] in ("+", "-") else line

        if not in_array:
            if not _SOURCE_ARRAY_START_RE.match(body):
                continue
            in_array = True
        for candidate in re.findall(r"https?://[^\s'\"\)]+", body):
            urls.add(_clean_url(candidate))
        if ")" in body:
            in_array = False
    return urls


_SOURCE_OPEN_RE = re.compile(r"^\+\s*(?:_?\w*source\w*)\s*=\s*\(", re.IGNORECASE)
_CMD_SUBST_RE = re.compile(r"\$\(|`")


def source_array_has_command_substitution(diff_text: str) -> bool:
    """Detect command substitution inside an added ``source=()`` array.

    Multi-line aware: the opener and the ``$(...)`` continuation line are
    usually different physical lines, so the whole open array is tracked, not
    just the single line the substitution shares with ``source=``.
    """
    in_array = False
    for line in diff_text.splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if _SOURCE_CMD_SUBST_RE.search(line):
            return True
        if not in_array:
            if _SOURCE_OPEN_RE.match(line) and ")" not in line:
                in_array = True
            continue
        # Inside an open array: only added/context lines belong to it.
        if line.startswith("+") and _CMD_SUBST_RE.search(line):
            return True
        if ")" in line:
            in_array = False
    return False


# A local ``source=()`` entry is a file shipped inside the AUR repo, which
# makepkg copies into ``$srcdir`` where ``prepare()``/``build()`` can run it.
# Its bytes are committed and visible, but generate_diff's filename filter
# used to drop everything that was not PKGBUILD/.SRCINFO/*.install, so a
# ``curl | bash`` moved into ``setup.sh`` reached no rule.  These helpers put
# that content back in front of the scanner.  Cap it: an untrusted repo must
# not force the reviewer to read an unbounded file, and the pipeline's own
# diff cap still bounds the combined text on top of this.
_COMPANION_MAX_BYTES = MAX_COMPANION_BYTES
# One array element: a single- or double-quoted string, or a bare word.
# bash accepts ``source=(setup.sh)`` unquoted, so a quoted-only parser was
# evaded by simply dropping the quotes.
_ARRAY_TOKEN_RE = re.compile(r"""'([^']*)'|"([^"]*)"|([^\s()'"]+)""")


def local_source_names(pkgbuild_text: str) -> set[str]:
    """Basenames of the local (non-URL) entries in the ``source=()`` arrays.

    A ``name::url`` rename is a download and is skipped; a bare filename,
    quoted or not, is a companion file the recipe ships.  ``source_x86_64``
    and friends count.
    """
    names: set[str] = set()
    in_array = False
    for raw in pkgbuild_text.splitlines():
        line = raw.strip()
        if not in_array:
            if not _SOURCE_ARRAY_START_RE.match(line):
                continue
            in_array = True
            line = line[line.index("(") + 1:]
        segment = line.split(")", 1)[0] if ")" in line else line
        for q1, q2, bare in _ARRAY_TOKEN_RE.findall(segment):
            tok = q1 or q2 or bare
            if not tok or "://" in tok:
                continue
            names.add(tok.rsplit("/", 1)[-1])
        if ")" in line:
            in_array = False
    return names


def _top_level_blob(tree, name: str):
    """The blob named *name* at the tree root, or None."""
    try:
        entry = tree[name]
    except (KeyError, TypeError):
        return None
    if getattr(entry, "type_str", None) != "blob":
        return None
    return entry


# Metadata files the diff already carries; scanning them here would double
# every finding.  ``.install`` is matched by suffix separately.
_COMPANION_SKIP = frozenset({"PKGBUILD", ".SRCINFO", ".gitignore"})


def _companion_names(tree, pkgbuild_text: str) -> list[str]:
    """Committed top-level files whose content the recipe pulls in.

    A file is included when it is a declared ``source=()`` entry *or* its name
    appears anywhere in the PKGBUILD: ``bash "${startdir}/helper.sh"`` names a
    committed file that makepkg never copies through ``source=()`` yet the
    build still executes, so declaring the source was never required to run
    it.  Tying the scan to files the recipe *names* keeps an unrelated
    committed blob out of it while leaving no referenced file unread.
    """
    declared = local_source_names(pkgbuild_text)
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
            continue
        if name in _COMPANION_SKIP or name.endswith(".install"):
            continue
        if name in declared or name in pkgbuild_text:
            names.append(name)
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


def companion_source_hunks(
    repo: pygit2.Repository, commit_oid: str, max_bytes: int = _COMPANION_MAX_BYTES
) -> str:
    """Committed companion files rendered as added-file diff hunks.

    Every committed text file the PKGBUILD names -- a declared ``source=()``
    entry or one it merely executes/sources/patches by path -- is emitted as
    a ``+++ b/<name>`` hunk whose whole current content is added lines, so the
    ordinary line rules, the tokenizer and ``map_diff_lines`` see it with
    correct file attribution.  Binary and ELF files are left out: R118-tree
    already owns embedded binaries, and text rules over binary bytes are
    noise.  The full current content is emitted, not just this commit's diff,
    so a payload committed earlier and merely referenced now is still read.
    """
    max_bytes = max(1, min(max_bytes, MAX_COMPANION_BYTES))
    commit = repo.get(commit_oid)
    if commit is None:
        return ""
    pkgbuild = _top_level_blob(commit.tree, "PKGBUILD")
    if pkgbuild is None:
        return ""
    try:
        blob = repo[pkgbuild.id]
        # Size before data: `blob.data` materialises the whole blob, so a
        # check afterwards bounds what is kept rather than what is read.
        if getattr(blob, "size", 0) > MAX_PKG_BUILD_BYTES:
            return ""
        pkgbuild_text = blob.data[:MAX_PKG_BUILD_BYTES].decode(
            "utf-8", errors="replace"
        )
    except (KeyError, TypeError, ValueError):
        return ""

    hunks: list[str] = []
    used = 0
    for name in sorted(set(_companion_names(commit.tree, pkgbuild_text)))[:MAX_COMPANION_FILES]:
        entry = _top_level_blob(commit.tree, name)
        if entry is None:
            continue
        try:
            blob = repo[entry.id]
            if getattr(blob, "size", 0) > max_bytes - used:
                break
            data = blob.data
        except (KeyError, TypeError, ValueError):
            continue
        # NUL in the head marks a binary; ELF is R118's job, not the text
        # rules'.
        if b"\x00" in data[:8192] or data[:4] == b"\x7fELF":
            continue
        text = data.decode("utf-8", errors="replace")
        lines: list[str] = []
        for ln in text.splitlines():
            if used + len(ln) + 1 > max_bytes:
                break
            lines.append(ln)
            used += len(ln) + 1
        if not lines:
            continue
        hunks.append(
            f"--- /dev/null\n+++ b/{name}\n@@ -0,0 +1,{len(lines)} @@\n"
            + "\n".join("+" + ln for ln in lines)
        )
        if used >= max_bytes:
            break
    return "\n".join(hunks)


_GPG_VERIFY_RE = re.compile(
    r"(?:gpg|gpgv|openpgp)\s+(?:--verify|--decrypt|\-\-check-signatures)",
    re.IGNORECASE,
)
_VALIDPGPKEYS_WITH_CONTENT_RE = re.compile(
    r"validpgpkeys\s*=\s*\(\s*['\"]?[A-Fa-f0-9]{16,}",
)
_CHECKSUM_ARRAY_RE = re.compile(
    r"(?:" + _CHECKSUM_VARS + r")\s*=\s*(?:\(|['\"]?[A-Fa-f0-9])",
)


def _post_diff_lines(diff_text: str) -> list[str]:
    """Reconstruct the post-diff file content lines.

    Applies the diff: keeps context (`` ``) and addition (``+``) lines,
    drops removal (``-``) and header lines.  Returns lines with their
    diff prefix stripped.
    """
    out: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith("-"):
            continue
        if line.startswith("+") or line.startswith(" "):
            out.append(line[1:])
    return out


def _has_checksum_in_post_diff(diff_text: str) -> bool:
    """Check whether the post-diff end-state declares checksums."""
    post = "\n".join(_post_diff_lines(diff_text))
    return bool(_CHECKSUM_ARRAY_RE.search(post))


def detect_gpg_verification_removed(diff_text: str) -> bool:
    """Detect whether GPG verification was removed in a diff."""
    had_content = False
    for line in diff_text.splitlines():
        if line.startswith("-") and _VALIDPGPKEYS_WITH_CONTENT_RE.search(line):
            had_content = True
            break
    if not had_content:
        return False
    post = "\n".join(_post_diff_lines(diff_text))
    return not bool(_VALIDPGPKEYS_WITH_CONTENT_RE.search(post))


def detect_verification_evidence(diff_text: str, checksum_behavior: str = "") -> list[str]:
    """Return a list of verification evidence strings present in the post-diff end-state.

    Each item is a key into ``scoring.DECLARED_REASONS``.  These are
    *declared* facts, reported at weight 0 (B10), never credited.
    Evidence is computed over the resolved PKGBUILD-as-it-will-be-installed,
    not over the diff delta; a checksum's protective value doesn't depend
    on whether it changed in this commit.
    """
    evidence: list[str] = []

    if checksum_behavior not in ("changed_from_sha256_to_skip", "checksum_array_emptied"):
        if _has_checksum_in_post_diff(diff_text):
            evidence.append("checksum_present")

    post = "\n".join(_post_diff_lines(diff_text))
    if _VALIDPGPKEYS_WITH_CONTENT_RE.search(post):
        evidence.append("validpgpkeys_declared")
    if _GPG_VERIFY_RE.search(post):
        evidence.append("gpg_verify_present")

    return evidence
