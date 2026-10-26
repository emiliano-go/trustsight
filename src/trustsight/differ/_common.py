"""Extracted from differ.py: _common."""

import re
from ..diffdoc import parse_diff_lines
from ..tokenizer import split_lines
from ..line_lex import strip_comment_stateful

__all__ = ['_SOURCE_ARRAY_START_RE', '_SOURCE_ARRAY_START_RE_TEXT', '_clean_url', '_is_metadata_path', '_post_diff_lines', '_pre_diff_lines', '_without_comments']

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
    token = token.rstrip(")<>]")
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

_SOURCE_ARRAY_START_RE = re.compile(
    r"^\s*source(?:_[a-z0-9_]+)?\s*\+?=\s*\("
)

_SOURCE_ARRAY_START_RE_TEXT = re.compile(_SOURCE_ARRAY_START_RE.pattern, re.MULTILINE)

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


def _without_comments(text: str) -> str:
    """*text* with shell comments removed, quote state carried per line.

    Verification and SKIP-justification predicates read prose as evidence
    when they scan raw post-diff text: a comment saying ``see x.sig`` made a
    SKIP look signature-backed, and ``# sha256sums=…`` looked like a declared
    checksum.  This is the same comment boundary the tokenizer uses.
    """
    out: list[str] = []
    quote = ""
    for line in text.split("\n"):
        code, quote = strip_comment_stateful(line, quote)
        out.append(code)
    return "\n".join(out)
