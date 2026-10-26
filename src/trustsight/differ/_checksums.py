"""Extracted from differ.py: _checksums."""

import re
from collections import Counter
from typing import NamedTuple
from ..diffdoc import parse_diff_lines
from ..tokenizer import split_lines
from ._common import _SOURCE_ARRAY_START_RE, _SOURCE_ARRAY_START_RE_TEXT

__all__ = ['_CHECKSUM_ARRAY_RE', '_CHECKSUM_LINE_RE', '_CHECKSUM_VARS', '_CHECKSUM_VAR_NAMES', '_CHK_DECL_RE', '_CHK_HASH_CHAR_RE', '_CHK_SKIP_WORD_RE', '_ChecksumArray', '_added_array_items', '_checksum_items', '_quoted_items', '_resolve_checksum_text', '_text_array_items', '_touched_checksum_arrays', '_unquoted_close', 'checksum_array_parity', 'checksum_array_parity_in_text', 'detect_checksum_changes', 'detect_checksum_removed', 'source_array_grew_in_diff']

_CHECKSUM_VAR_NAMES = (
    "sha256sums", "sha512sums", "sha1sums", "sha224sums", "sha384sums",
    "b2sums", "md5sums",
)

_CHECKSUM_VARS = "|".join(_CHECKSUM_VAR_NAMES)
#: A checksum array name, optionally arch-scoped (`sha256sums_x86_64`).
_CHECKSUM_ARRAY_NAMES = "(?:" + _CHECKSUM_VARS + r")(?:_[A-Za-z0-9_]+)?"

_CHK_DECL_RE = re.compile(
    r"^\s*(?:" + _CHECKSUM_ARRAY_NAMES + r")\s*\+?=\s*", re.IGNORECASE,
)

class _ChecksumArray(NamedTuple):
    """One ``*sums`` array as the diff shows it.

    ``added_text``/``removed_text`` are the ``+``/``-`` bodies that belong
    to the array, and ``added_items``/``removed_items`` are the tokens parsed
    from them.  Comparing the two item multisets separates a replaced hash
    (same count) from a removed entry (fewer tokens), which the old
    any-removed-line test could not.
    """

    var: str
    added_text: str
    removed_text: str
    added_items: list[str]
    removed_items: list[str]
    added_any: bool
    removed_any: bool
    decl_removed: bool

def _checksum_items(text: str) -> list[str]:
    """The tokens of a checksum array body, ignoring parens and commas.

    Handles the quoted and unquoted forms and the ``#`` comment makepkg
    allows inside the array.  The quotes are kept so both sides of a diff
    compare identically.
    """
    items: list[str] = []
    current: list[str] = []
    quote = ""
    for ch in text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch in "(),":
            if current:
                items.append("".join(current))
                current = []
        elif ch.isspace():
            if current:
                items.append("".join(current))
                current = []
        elif ch == "#":
            if current:
                items.append("".join(current))
                current = []
            break
        else:
            current.append(ch)
    if current:
        items.append("".join(current))
    return [item for item in items if any(c.isalnum() for c in item)]

def _touched_checksum_arrays(diff_text: str) -> list[_ChecksumArray]:
    """Every ``*sums`` array the diff touches, with both sides of the array.

    A declaration's array may span several lines (the usual PKGBUILD
    formatting splits ``sha256sums=(``, one quoted hash per line, and a
    closing ``)``), and the declaration line is frequently *context*: a
    commit adds one hash to an array whose ``sha256sums=(`` opener did not
    move.  Tracking only added declarations therefore read a real checksum
    change as ``unchanged``, and a package that swapped a checksum under a
    stable version reported no integrity finding at all.

    The ``+`` and ``-`` bodies are collected separately and parsed into
    items, so the caller compares what the array *held* rather than counting
    the minus lines.  An array cannot span files, so the state is flushed at
    a file boundary; it can span hunks, so it is not flushed at a hunk
    header.  A scalar declaration (``.SRCINFO``'s ``md5sums = <hash>``) has
    no array and is not tracked, so a dropped trailing blank line cannot
    read as an entry removal.

    ``decl_removed`` says the declaration line itself was on the ``-`` side,
    which distinguishes an entry removed from a surviving array from a whole
    array replaced - the replacement is an ordinary change, not a removal of
    one entry.
    """
    arrays: list[_ChecksumArray] = []
    cur_var: str | None = None
    cur_added: list[str] = []
    cur_removed: list[str] = []
    added_any = False
    removed_any = False
    decl_removed = False

    def flush() -> None:
        nonlocal cur_var, cur_added, cur_removed, added_any, removed_any, decl_removed
        if cur_var is not None:
            added_text = "\n".join(cur_added)
            removed_text = "\n".join(cur_removed)
            arrays.append(_ChecksumArray(
                cur_var, added_text, removed_text,
                _checksum_items(added_text), _checksum_items(removed_text),
                added_any, removed_any, decl_removed,
            ))
        cur_var = None
        cur_added = []
        cur_removed = []
        added_any = False
        removed_any = False
        decl_removed = False

    for line in parse_diff_lines(split_lines(diff_text)).lines:
        # The trailing space is the guard: file headers are `+++ b/path` /
        # `--- a/path`, so a content line whose text starts with `--` (an
        # unquoted array element, say) reads as `---…` and must not flush
        # the array state - the rest of the array would be dropped.  The
        # parser owns that decision now; the boundary flag is where the
        # header line stood.  An array cannot span files; leaving it open
        # leaked one file's state into the next.
        if line.file_boundary:
            flush()
        if not line.is_content:
            # Hunk headers and `@@`-junk never touched the state; other
            # structure lines fall through with their raw text, as the
            # legacy walk processed them.
            if line.raw.startswith("@@"):
                continue
            sign = ""
            body = line.raw
        else:
            sign = {"add": "+", "remove": "-", "context": " "}[line.side]
            body = line.content
        m = _CHK_DECL_RE.match(body)
        if m:
            rest = body[m.end():]
            if "(" not in rest:
                # A scalar, as ``.SRCINFO`` writes it.  It has no array and
                # no entry to remove, so it is not tracked.
                flush()
                continue
            flush()
            cur_var = m.group(0).split("=", 1)[0].strip()
            if sign == "+":
                cur_added.append(rest)
                added_any = True
            elif sign == "-":
                cur_removed.append(rest)
                removed_any = True
                decl_removed = True
            # A closing ``)`` on the ``-`` side does not end the array: its
            # ``+`` counterpart (the replacement closing line) is the next
            # line, and closing here would orphan it and read a changed entry
            # as a removal.
            if ")" in rest and sign != "-":
                flush()
            continue
        if cur_var is not None:
            if sign == "+":
                cur_added.append(body)
                added_any = True
            elif sign == "-":
                cur_removed.append(body)
                removed_any = True
            if ")" in body and sign != "-":
                flush()
    flush()
    return arrays

_CHK_HASH_CHAR_RE = re.compile(r"[0-9A-Za-z+/=]")

_CHK_SKIP_WORD_RE = re.compile(r"[\'\"]?(?:SKIP|NONE)[\'\"]?")

def _resolve_checksum_text(
    diff_text: str, contents: str, current_text: str | None = None,
) -> str:
    """*contents* with the diff's own variables substituted.

    Checksum rules read the array as text, so `_cs=SKIP` two lines above
    and `sha256sums=("${_cs}")` below reported `checksum_added_or_changed`:
    verification was off and the reader was told a checksum had been set.
    The name is the writer's to choose and the value is in the same diff,
    which is the argument for resolving everywhere else too.
    """
    if "$" not in contents:
        return contents
    from ..expansion import text_variable_table
    from ..tokenizer import TokenizerUnavailable, variable_table

    readable = [
        line.content
        for line in parse_diff_lines(split_lines(diff_text)).lines
        if line.side == "add" and not line.raw.startswith("+++")
    ]
    if current_text:
        table = text_variable_table(current_text)
    else:
        table = {}
    try:
        diff_table, _arrays = variable_table(readable)
    except TokenizerUnavailable:
        # A missing tokenizer is a refusal, not "the checksum did not
        # change": the package is not vetted and the caller fails closed.
        raise
    except Exception:
        # Returning the unresolved text is the neutral value a complete
        # resolution also produces, so without this note a `${_cs}=SKIP`
        # indirection would read as a set checksum and clear the gap.
        from ..coverage import note_stage_failure
        note_stage_failure("checksum-resolution")
        return contents
    table.update(diff_table)
    out = contents
    for name, value in table.items():
        if not isinstance(value, str):
            continue
        for spelling in (f"${{{name}}}", f"${name}"):
            if spelling in out:
                out = out.replace(spelling, value)
    return out

def checksum_array_parity(diff_text: str) -> tuple[int, int, str] | None:
    """``(sources, sums, var)`` when a declared array is short, else None.

    makepkg pairs `source=()` with each `*sums=()` by position, and a
    missing entry is not a missing check - it is a *failed* build, unless
    the array is short in the direction that leaves an entry unverified.
    In practice a mismatch is either a mistake or a source slipped in
    beside a checksum list nobody recounted, and no rule looked at the two
    lengths together: adding a second source with one checksum scored
    nothing but priors.

    Only the added side is read, and only when both arrays are declared in
    this diff - comparing a new source array against a checksum array the
    diff does not show would be guessing at the other half.
    """
    sources = _added_array_items(diff_text, _SOURCE_ARRAY_START_RE)
    if sources is None:
        return None
    for var in _CHECKSUM_VAR_NAMES:
        items = _added_array_items(
            diff_text, re.compile(r"^\s*" + var + r"(?:_[A-Za-z0-9_]+)?\s*\+?=\s*\("))
        if items is None:
            continue
        if len(items) < len(sources):
            return (len(sources), len(items), var)
    return None

def checksum_array_parity_in_text(recipe_text: str) -> tuple[int, int, str] | None:
    """``(sources, sums, var)`` when the recipe's declared array is short.

    The diff-based :func:`checksum_array_parity` reads only wholly-added
    arrays, so an element inserted into an existing ``source=()`` beside an
    unchanged ``*sums=()`` is invisible to it, and a first-seen recipe has
    no diff at all.  This variant reads the complete recipe, so no array
    length is inferred from a hunk: the arrays are fully visible by
    construction, and the 26-benign-package false positive that made the
    diff version refuse partial arrays cannot recur.
    """
    sources = _text_array_items(recipe_text, _SOURCE_ARRAY_START_RE_TEXT)
    if sources is None:
        return None
    for var in _CHECKSUM_VAR_NAMES:
        items = _text_array_items(
            recipe_text, re.compile(r"^\s*" + var + r"(?:_[A-Za-z0-9_]+)?\s*\+?=\s*\(", re.MULTILINE))
        if items is None:
            continue
        if len(items) < len(sources):
            return (len(sources), len(items), var)
    return None

def _quoted_items(contents: str) -> list[str] | None:
    """The array elements in *contents*, or None if it never closed.

    Elements are split on *unquoted* whitespace, which a token regex
    cannot do: `"$_pkgsrc"::"git+$url.git"` is makepkg's rename form and is
    one source, and reading it as a quoted token followed by the rest read
    it as two. Every renamed source in the corpus then looked like an
    array one element longer than its checksum list.
    """
    open_idx = contents.find("(")
    if open_idx < 0:
        return None
    close_idx = _unquoted_close(contents, open_idx + 1)
    if close_idx is None:
        return None
    inner = contents[open_idx + 1:close_idx]
    items: list[str] = []
    current: list[str] = []
    quote = ""
    for ch in inner:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch.isspace():
            if current:
                items.append("".join(current))
                current = []
        elif ch == "#":
            # A comment inside the array ends the element and the line.
            break
        else:
            current.append(ch)
    if current:
        items.append("".join(current))
    return items

def _unquoted_close(text: str, start: int = 0) -> int | None:
    """Index of the first ``)`` outside a quoted span, or None.

    A quoted element may contain a paren, so stopping at the first one
    would read half an array as a whole one.
    """
    quote = ""
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == ")":
            return i
    return None

def _text_array_items(text: str, start_re) -> list[str] | None:
    """Elements of the last array matching *start_re* in a whole file.

    Bash semantics: a later assignment of the same name replaces the
    earlier one, so `source=(...)` twice means the second array is the
    declared one.  A later declaration under a *different* name (the
    arch-suffixed `source_x86_64`) is a separate variable and does not
    replace it.  ``None`` when the tracked declaration never closes: the
    closing paren is found by scanning the whole text, not the line,
    because a multi-line array's ``)`` is on its own line.
    """
    latest: list[str] | None = None
    wanted: str | None = None
    for match in start_re.finditer(text):
        open_idx = text.find("(", match.start())
        if open_idx < 0:
            continue
        declaration = text[match.start():open_idx].strip()
        if wanted is None:
            wanted = declaration
        if declaration != wanted:
            continue
        close_idx = _unquoted_close(text, open_idx + 1)
        if close_idx is None:
            return None
        latest = _quoted_items(text[open_idx:close_idx + 1])
    return latest

def _added_array_items(diff_text: str, start_re) -> list[str] | None:
    """Elements of the last *wholly added* array matching *start_re*.

    ``None`` unless the array opens and closes inside added lines with no
    context line between. A diff shows a hunk, not a file: an array that
    opens on a `+` line and continues through unchanged entries is only
    partly visible, and counting what is visible reported a two-element
    array as one. That mistake fired on 26 benign packages - every
    multi-source recipe whose diff touched one entry.

    The *last* assignment of the tracked declaration wins, as it does in
    bash: an overridden ``source=`` on the next line is the one makepkg
    reads.  A later declaration under a different name (`source_x86_64`)
    is a separate variable and does not replace it.
    """
    latest: list[str] | None = None
    wanted: str | None = None
    collecting: str | None = None
    parts: list[str] = []
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        if not line.is_content:
            continue
        added = line.side == "add"
        body = line.content if line.is_content else line.raw
        if collecting is None:
            if added and start_re.match(body):
                collecting = body[:body.index("(")].strip()
                if wanted is None:
                    wanted = collecting
                parts = [body[body.index("("):]]
                if ")" in parts[-1]:
                    if collecting == wanted:
                        latest = _quoted_items(
                            "(" + "\n".join(parts).split("(", 1)[1]
                        )
                    collecting = None
            continue
        if not added:
            # The tracked array continues into text this diff does not add,
            # so what it holds in full is not something this function
            # knows; fail closed.  A different declaration going partially
            # visible is not the one being read.
            if collecting == wanted:
                return None
            collecting = None
            parts = []
            continue
        parts.append(body)
        if ")" in body:
            if collecting == wanted:
                latest = _quoted_items("(" + "\n".join(parts).split("(", 1)[1])
            collecting = None
            parts = []
    return latest

def source_array_grew_in_diff(diff_text: str) -> bool:
    """True when a source array gains more lines than it loses in *diff_text*.

    The gate for falling back to :func:`checksum_array_parity_in_text`: an
    array that already mismatched must not fire merely because the diff
    touched it, and a pure re-indentation is not a new source.  A hunk
    boundary ends the region, because the lines after it may belong to an
    unrelated part of the file.
    """
    inside = False
    added = removed = 0
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        if line.raw.startswith(("+++", "---", "@@")):
            inside = False
            continue
        if line.is_content:
            prefix = {"add": "+", "remove": "-", "context": " "}[line.side]
            body = line.content
        else:
            prefix = ""
            body = line.raw
        if not inside:
            if _SOURCE_ARRAY_START_RE.match(body):
                inside = True
            else:
                continue
        if prefix == "+":
            added += 1
        elif prefix == "-":
            removed += 1
        if _unquoted_close(body) is not None:
            inside = False
    return added > removed

def detect_checksum_changes(
    diff_text: str, current_text: str | None = None,
) -> str:
    """Detect checksum-related changes in a diff.

    Reads *every* checksum array, and correctly handles the multiline form:
    a diff that adds ``sha256sums=(\n  'SKIP'\n)`` must read as *skip*, not
    ``unchanged``.

    It used to read `sha256sums` alone, on the reasoning that it is
    makepkg's default. makepkg accepts `b2sums`, `sha512sums`, `md5sums` and
    the rest just as happily, and a package that declares only one of those
    is verified by that one - so `b2sums=('SKIP')` disabled verification and
    reported `unchanged`, which is H001 not firing at all. Modern AUR
    packages increasingly ship `b2sums`, so the default was becoming the
    minority case.

    A SKIP anywhere wins over a hash elsewhere: the array carrying SKIP is
    the one that stopped verifying a source, whatever a sibling array does.
    """
    seen = False
    emptied = False
    entry_removed = False
    for array in _touched_checksum_arrays(diff_text):
        if not (array.added_any or array.removed_any):
            # The array is fully context: it did not move in this diff.
            continue
        added = Counter(array.added_items)
        removed = Counter(array.removed_items)
        if added == removed and array.added_items:
            # The same hashes on both sides: a reformat or re-indentation,
            # not a checksum change.
            continue
        seen = True
        contents = _resolve_checksum_text(
            diff_text, " ".join(array.added_items), current_text)
        if _CHK_SKIP_WORD_RE.search(contents):
            return "changed_from_sha256_to_skip"
        if array.added_any and not array.added_items:
            emptied = True
        # An entry removed from an array that survives is the integrity
        # event.  A hash *replaced* by another keeps the count, so only a
        # genuine net loss - fewer entries added than removed - is a removal.
        # A declaration replaced wholesale is an ordinary change: the new
        # array carries the hashes.
        if (
            not array.decl_removed
            and sum(removed.values()) > sum(added.values())
        ):
            entry_removed = True
    if emptied:
        return "checksum_array_emptied"
    if entry_removed:
        return "checksum_entry_removed"
    return "checksum_added_or_changed" if seen else "unchanged"

_CHECKSUM_LINE_RE = re.compile(
    r"(?:" + _CHECKSUM_ARRAY_NAMES + r")\s*\+?=",
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
    # The walk reads raw lines, headers included, so the typed document
    # supplies them unchanged: a crafted `--- a/sha256sums=x` path reads
    # as a removal here, exactly as the text walk read it.
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        if not line.is_content:
            continue
        if line.side == "remove" and _CHECKSUM_LINE_RE.search(line.content):
            removed = True
        elif line.side == "add" and _CHECKSUM_LINE_RE.search(line.content):
            added = True
    return removed and not added

_CHECKSUM_ARRAY_RE = re.compile(
    r"(?:" + _CHECKSUM_ARRAY_NAMES + r")\s*\+?=\s*(?:\(|['\"]?[A-Fa-f0-9])",
)
