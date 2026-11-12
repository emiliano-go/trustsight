"""Extracted from differ.py: _common."""

import re
from ..buckets import _SOURCE_ARRAY_START_RE
from ..diffdoc import parse_diff_lines
from ..tokenizer import split_lines

__all__ = ['_SOURCE_ARRAY_START_RE', '_SOURCE_ARRAY_START_RE_TEXT', '_clean_url', '_is_metadata_path', '_post_diff_lines', '_pre_diff_lines', 'pre_image_from_post']

def _is_metadata_path(path: str) -> bool:
    """Whether a delta path is one the analysis reads."""
    return (path in ("PKGBUILD", ".SRCINFO")
            or path.endswith(".install"))

def _clean_url(token: str) -> str:
    # A URL written in angle brackets - a maintainer line's
    # `<https://aur.archlinux.org/account/foo>` is the common case - keeps
    # the closing `>` in the token, and a source URL with a `>` on the end
    # is a URL no bucket or novelty lookup will ever recognise.  The
    # closing bracket is punctuation, not part of the address.
    token = token.rstrip(")<>")
    token = re.sub(r"[\)]+", ")", token)
    # Trailing braces from a nested shell default (`${A:-${B:-https://x}}`)
    # are shell syntax, but the `}` closing a `${var}` inside the URL is
    # part of the template: strip only the braces nothing opened.
    trailing = len(token) - len(token.rstrip("}"))
    excess = token.count("}") - token.count("{")
    if trailing and excess > 0:
        token = token[:len(token) - min(trailing, excess)]
    end = len(token)
    while end and (token[end - 1] in ",;" or token[end - 1].isspace()):
        end -= 1
    token = token[:end]
    return token

_SOURCE_ARRAY_START_RE_TEXT = re.compile(_SOURCE_ARRAY_START_RE.pattern, re.MULTILINE)


def pre_image_from_post(diff_text: str, post_text: str) -> str | None:
    """Rebuild the PKGBUILD before the change from the post file and diff.

    A hunk can start inside an array, leaving its opener outside the diff.
    Reconstructing only from the hunk then reads an incomplete array and
    loses a removed source entry.  Applying the hunks in reverse to the
    full post text restores the whole pre image.

    Returns ``None`` when the diff has no PKGBUILD hunk or when a hunk does
    not match *post_text*; callers must keep their diff-only fallback then.
    """
    if not post_text:
        return None
    doc = parse_diff_lines(split_lines(diff_text))
    target = next((f for f in doc.files if f.path == "PKGBUILD"), None)
    if target is None or not target.hunks:
        return None
    lines = split_lines(post_text)
    for hunk in reversed(target.hunks):
        post_segment = [
            line.content for line in hunk.lines if line.side != "remove"
        ]
        pre_segment = [
            line.content for line in hunk.lines if line.side != "add"
        ]
        start = hunk.new_start - 1
        end = start + len(post_segment)
        if start < 0 or end > len(lines) or lines[start:end] != post_segment:
            return None
        lines[start:end] = pre_segment
    return "\n".join(lines)

def _post_diff_lines(diff_text: str) -> list[str]:
    """Reconstruct the post-diff file content lines.

    Applies the diff: keeps context (`` ``) and addition (``+``) lines,
    drops removal (``-``) and header lines.  Returns lines with their
    diff prefix stripped.

    A projection of the typed parse (:mod:`trustsight.diffdoc`); the
    header-shape guard (``+++ ``/``--- `` carry a trailing space, so a
    content line starting with ``++`` survives) is the parser's decision
    now, made once.
    """
    return parse_diff_lines(split_lines(diff_text)).post_lines()

def _pre_diff_lines(diff_text: str) -> list[str]:
    """Reconstruct the pre-diff file content lines.

    The mirror of :func:`_post_diff_lines`: keeps context (`` ``) and
    removal (``-``) lines, drops additions (``+``) and headers.  Needed to
    answer "was this declared *before*?" when the declaration's own line is
    context and only its contents changed.  A projection of the typed
    parse, as its mirror is.
    """
    return parse_diff_lines(split_lines(diff_text)).pre_lines()
