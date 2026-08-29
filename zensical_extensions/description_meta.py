"""Zensical extension: read curated page descriptions from HTML comments.

Zensical's Rust renderer does not strip YAML frontmatter, so a
``description:`` field in ``---`` blocks leaks into the visible page body
and into auto-generated SEO excerpts. This extension lets authors put the
curated description in an HTML comment at the top of the page:

    <!-- description: The page description goes here. -->

The extension copies the text into ``page.meta["description"]`` (where
seoslug reads it) and removes the comment from the rendered source so it
never appears on the page.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from markdown import Extension
from markdown.preprocessors import Preprocessor

try:
    from zensical.extensions.context import ContextPreprocessor
except ImportError:  # pragma: no cover
    ContextPreprocessor = None

if TYPE_CHECKING:
    from markdown import Markdown


_DESCRIPTION_COMMENT_RE = re.compile(
    r"^<!--\s*description:\s*(.+?)\s*-->$",
    re.DOTALL,
)


class DescriptionMetaPreprocessor(Preprocessor):
    """Read a description HTML comment and store it in page meta."""

    name = "description_meta"

    def run(self, lines: list[str]) -> list[str]:
        if ContextPreprocessor is None:
            return lines

        ctx = ContextPreprocessor.from_markdown(self.md)
        if not ctx:
            return lines

        page = ctx.page
        kept: list[str] = []
        for line in lines:
            match = _DESCRIPTION_COMMENT_RE.match(line)
            if match and "description" not in page.meta:
                page.meta["description"] = " ".join(
                    match.group(1).split()
                )
                continue
            kept.append(line)
        return kept


class DescriptionMetaExtension(Extension):
    """Register the description-meta preprocessor."""

    name = "zensical_extensions.description_meta"

    def extendMarkdown(self, md: Markdown) -> None:
        md.registerExtension(self)
        preprocessor = DescriptionMetaPreprocessor(md)
        # Run before seoslug so the description is in page.meta when seoslug
        # looks for it.
        md.preprocessors.register(preprocessor, preprocessor.name, 200)


def makeExtension(**kwargs):  # noqa: D103
    return DescriptionMetaExtension(**kwargs)
