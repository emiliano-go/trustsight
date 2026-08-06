"""Rendering untrusted text to a terminal.

Almost everything TrustSight prints is attacker-controlled: package names,
maintainer names, file paths, and the diff excerpts quoted as evidence all
come from an AUR repository that, by assumption, may be hostile.  Printed
raw, that text is not inert.  It can

* repaint the screen with ANSI escapes and forge a verdict that was never
  computed, or scroll the real one out of view;
* interpret as Rich console markup, so ``[green]`` in a package name
  recolours the row, and an unbalanced tag raises ``MarkupError`` and
  aborts the render of every remaining package in the batch;
* carry C1 control bytes, which some terminals still act on.

The defence is one function applied at the boundary: :func:`clean` for
anything that reaches a terminal, :func:`safe_markup` when the string is
about to be interpolated into a Rich markup string.  Neither is a
substitute for the other, and neither belongs deep in the analysis code:
the value is sanitised where it is *rendered*, so that the evidence stored
in the database and the JSON report stays byte-exact.
"""

import re

# Full escape sequences, removed before the leftover-byte sweep so that
# their parameters do not survive as visible junk.  Covers CSI (including
# the 8-bit C1 form), OSC up to its terminator, and the two-character
# escapes.  ``unicode.strip_ansi`` handles only the first of these; it
# stays as it is because R013 evidence uses it on stored text.
_ESCAPE_SEQUENCE_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)"   # OSC ... BEL / ST / truncated
    r"|[\x1b\x9b]\[[0-?]*[ -/]*[@-~]"        # CSI
    r"|\x1b[@-Z\\-_]"                        # single-character escapes
    r"|\x1b."                                # anything else ESC introduces
)

# What is left after the sequences are gone: bare control bytes, DEL, and
# the C1 range.  Tab and newline are handled separately - they are not
# forgery, they are layout, and a table cell wants neither.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

_WHITESPACE_RE = re.compile(r"[\t\n\r\f\v]+")

# Rich reads these as markup.  Escaping the opening bracket is enough:
# a closing bracket with no opener is literal.
_MARKUP_RE = re.compile(r"\[")


def clean(value, limit: int | None = None) -> str:
    """Return *value* with everything a terminal would act on removed.

    Not lossy for ordinary text: a normal package name, path or version
    passes through unchanged.  *limit* truncates the result, with an
    ellipsis, for cells that must not be allowed to fill the screen.
    """
    text = value if isinstance(value, str) else str(value)
    text = _ESCAPE_SEQUENCE_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    text = _WHITESPACE_RE.sub(" ", text)
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 1)] + "…"
    return text


def safe_markup(value, limit: int | None = None) -> str:
    """:func:`clean`, plus escaping so Rich reads the result as text.

    Use this only where the surrounding string really is markup.  Where
    the whole cell is untrusted, pass ``Text(clean(value))`` instead: it
    cannot be re-interpreted by a later formatting step.
    """
    return _MARKUP_RE.sub(r"\\[", clean(value, limit))
