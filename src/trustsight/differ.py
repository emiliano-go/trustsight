import re

import pygit2
from pygit2 import GIT_DELTA_ADDED, GIT_DELTA_DELETED, GIT_DELTA_MODIFIED, GIT_DELTA_RENAMED

from .schema import DiffSummary, SourceChanges

_HUNK_HEADER_RE = re.compile(
    r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@"
)


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

    for i, line in enumerate(lines):
        if line.startswith("+++ "):
            # removeprefix, not lstrip: lstrip("b/") strips *characters*,
            # so "+++ b/build.sh" reported the file as "uild.sh" and every
            # finding in it cited a path that does not exist.
            name = line[4:].strip()
            current_file = name.removeprefix("b/") if name.startswith("b/") else name
            continue
        if line.startswith("--- "):
            continue
        m = _HUNK_HEADER_RE.match(line)
        if m:
            new_lineno = int(m.group(1))
            continue
        if line.startswith(("+", " ", "-")):
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


def generate_diff(
    repo: pygit2.Repository, old_oid: str, new_oid: str, context_lines: int = 3
) -> tuple[str, DiffSummary]:
    """Generate a unified diff between two commits."""
    old_commit = repo.get(old_oid)
    new_commit = repo.get(new_oid)
    if old_commit is None or new_commit is None:
        return "", DiffSummary()
    diff = repo.diff(old_commit.tree, new_commit.tree, context_lines=context_lines)

    filtered_patches = []
    for patch in diff:
        delta = patch.delta
        path = delta.new_file.path
        old_path = delta.old_file.path
        if (path in ("PKGBUILD", ".SRCINFO") or path.endswith(".install")
                or old_path in ("PKGBUILD", ".SRCINFO") or old_path.endswith(".install")):
            filtered_patches.append(patch.text)

    unified = "\n".join(filtered_patches)
    lines_added = diff.stats.insertions
    lines_removed = diff.stats.deletions
    files_changed = list({delta.new_file.path for delta in diff.deltas})

    file_changes = []
    for delta in diff.deltas:
        status = _DELTA_STATUS_MAP.get(delta.status, "modified")
        path = delta.new_file.path if delta.status != GIT_DELTA_DELETED else delta.old_file.path
        if path not in (".SRCINFO", ".gitignore"):
            file_changes.append({"path": path, "status": status})

    summary = DiffSummary(
        lines_added=lines_added,
        lines_removed=lines_removed,
        files_changed=files_changed,
        file_changes=file_changes,
    )

    return unified, summary


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
                added_urls.add(_clean_url(u))
        elif line.startswith("-") and "http" in line:
            for u in _URL_TOKEN_RE.findall(line):
                removed_urls.add(_clean_url(u))

    checksum_behavior = detect_checksum_changes(diff_text)

    return SourceChanges(
        added_urls=list(added_urls),
        removed_urls=list(removed_urls),
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
_COMPANION_MAX_BYTES = 65536
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
    for entry in tree:
        if getattr(entry, "type_str", None) != "blob":
            continue
        name = entry.name
        if name in _COMPANION_SKIP or name.endswith(".install"):
            continue
        if name in declared or name in pkgbuild_text:
            names.append(name)
    return names


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
    commit = repo.get(commit_oid)
    if commit is None:
        return ""
    pkgbuild = _top_level_blob(commit.tree, "PKGBUILD")
    if pkgbuild is None:
        return ""
    try:
        pkgbuild_text = repo[pkgbuild.id].data.decode("utf-8", errors="replace")
    except (KeyError, TypeError, ValueError):
        return ""

    hunks: list[str] = []
    used = 0
    for name in sorted(set(_companion_names(commit.tree, pkgbuild_text))):
        entry = _top_level_blob(commit.tree, name)
        if entry is None:
            continue
        try:
            data = repo[entry.id].data
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
        if line.startswith("-"):
            continue
        if line.startswith("+") or line.startswith(" "):
            out.append(line.lstrip("+ "))
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
