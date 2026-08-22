"""Build the ``llms.txt`` and ``llms-full.txt`` companions to the docs site.

Every rendered page carries ``<link rel="alternate" type="text/plain">``
pointing at these two files, so the templates promise them on all 57 pages.
Nothing produced them: seoslug does not, and there is no docs workflow that
did, which left two 404s advertised site-wide.

The two files answer different questions, which is why the convention names
both (see llmstxt.org):

``llms.txt``
    A map.  The site title, its one-line description, then one section per
    navigation group listing every page as a link with a short summary.  It
    is small enough to paste whole and tells a reader which page to fetch.

``llms-full.txt``
    The territory.  Every page's Markdown concatenated in navigation order,
    each under a header naming its title and canonical URL.  It is the whole
    corpus in one request, for a reader that would otherwise crawl 57 pages.

Structure comes from ``zensical.toml``'s ``nav`` rather than from a second
list in this file: a page added to the site is a page added here, and a nav
entry with no file fails the build below rather than emitting a dead link.

Usage::

    python scripts/build_llms_txt.py                  # writes into site/
    python scripts/build_llms_txt.py --out some/dir
    python scripts/build_llms_txt.py --check          # verify, write nothing
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "zensical.toml"

#: Longest summary carried into ``llms.txt``.  A map entry that runs to a
#: paragraph stops being a map.
_MAX_SUMMARY = 200


def _config() -> dict:
    """Parse ``zensical.toml``.

    The file holds a multi-line inline table, which TOML 1.0 forbids and
    ``tomllib`` rejects, so the two sections this script needs are parsed on
    their own rather than the file as a whole.
    """
    text = CONFIG.read_text()
    nav_start = text.index("[[project.nav]]")
    nav_end = text.index("# Markdown extensions")
    # Trim back to the start of the banner comment above that heading.
    nav_end = text.rindex("\n# ===", nav_start, nav_end)
    nav = tomllib.loads(text[nav_start:nav_end])

    meta = {}
    for key in ("site_name", "site_description", "site_url", "docs_dir"):
        match = re.search(rf'^{key}\s*=\s*"(.*)"$', text, re.M)
        if match:
            meta[key] = match.group(1)
    meta["nav"] = nav["project"]["nav"]
    return meta


def _walk(node, out: list[tuple[str, str]]) -> None:
    """Collect ``(title, path)`` pairs from a nav subtree, in order."""
    if isinstance(node, dict):
        for title, value in node.items():
            if isinstance(value, str):
                out.append((title, value))
            else:
                _walk(value, out)
    elif isinstance(node, list):
        for item in node:
            _walk(item, out)


def _sections(meta: dict) -> list[tuple[str, list[tuple[str, str]]]]:
    """The nav as ``(section title, [(page title, path), ...])``."""
    sections = []
    for entry in meta["nav"]:
        for title, value in entry.items():
            pages: list[tuple[str, str]] = []
            _walk(value, pages)
            sections.append((title, pages))
    return sections


def _strip_frontmatter(text: str) -> tuple[str, str]:
    """Split leading YAML frontmatter off *text*, returning (front, body)."""
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    return (match.group(1), text[match.end():]) if match else ("", text)


def _summary(front: str, body: str) -> str:
    """A one-line summary: the declared description, or the opening prose.

    A page without frontmatter still has a first paragraph, and on this site
    that paragraph is written as the page's own summary.  Tables, fences,
    admonitions and headings are not prose and are skipped rather than
    quoted, which is what makes an entry like `exit-codes` read as a
    sentence instead of as a row of column headers.
    """
    declared = re.search(r"^description:\s*(.+?)\s*$", front, re.M)
    if declared:
        return _one_line(declared.group(1))

    in_fence = False
    for block in body.split("\n\n"):
        stripped = block.strip()
        if not stripped:
            continue
        if stripped.startswith("```"):
            in_fence = not in_fence if stripped.count("```") % 2 else in_fence
            continue
        if in_fence:
            continue
        first = stripped.splitlines()[0].lstrip()
        if first.startswith(("#", "|", ">", "-", "*", "!!!", "???", "<!--", "<", "---")):
            continue
        return _one_line(stripped)
    return ""


def _one_line(text: str) -> str:
    """Collapse *text* to a single trimmed line of at most `_MAX_SUMMARY`.

    Emphasis markers are removed; underscores are not.  Stripping every
    ``_`` turned `ensure_default_configs()` into `ensuredefaultconfigs()`,
    which names nothing.
    """
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)   # links to their text
    text = text.replace("`", "")
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"(?<![\w*])\*([^*]+)\*(?![\w*])", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    # A quoted frontmatter value keeps its quotes through the TOML-free read.
    if len(text) > 1 and text[0] == text[-1] == '"':
        text = text[1:-1].strip()
    if len(text) <= _MAX_SUMMARY:
        return text
    cut = text[:_MAX_SUMMARY]
    stop = max(cut.rfind(". "), cut.rfind("; "), cut.rfind(", "))
    return (cut[:stop + 1] if stop > _MAX_SUMMARY // 2 else cut.rstrip()) + "..."


def _url(base: str, path: str) -> str:
    """The canonical URL for a docs-relative Markdown path."""
    slug = path[:-3] if path.endswith(".md") else path
    if slug == "index":
        return base
    if slug.endswith("/index"):
        slug = slug[: -len("/index")]
    return f"{base}{slug}/"


def build(docs: Path, meta: dict) -> tuple[str, str]:
    """Return the ``(llms.txt, llms-full.txt)`` bodies."""
    base = meta["site_url"].rstrip("/") + "/"
    name = meta.get("site_name", "docs")
    description = meta.get("site_description", "")

    index = [f"# {name}", ""]
    if description:
        index += [f"> {description}", ""]
    index += [
        "This file indexes the documentation. `llms-full.txt` holds the same "
        "pages in full.",
        "",
    ]

    full = [
        f"# {name}",
        "",
        f"> {description}" if description else "",
        "",
        f"Complete documentation, concatenated in navigation order from {base}.",
        "",
    ]

    missing: list[str] = []
    for section, pages in _sections(meta):
        index.append(f"## {section}")
        index.append("")
        for title, path in pages:
            page = docs / path
            if not page.exists():
                missing.append(path)
                continue
            front, body = _strip_frontmatter(page.read_text())
            summary = _summary(front, body)
            url = _url(base, path)
            index.append(f"- [{title}]({url})" + (f": {summary}" if summary else ""))

            full += ["", "=" * 78, f"# {title}", f"Source: {url}", "=" * 78, "",
                     body.strip(), ""]
        index.append("")

    if missing:
        raise SystemExit(
            "nav names pages that do not exist, so llms.txt would advertise "
            "dead links:\n" + "\n".join(f"  {m}" for m in missing)
        )

    return "\n".join(index).rstrip() + "\n", "\n".join(full).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=None,
                        help="output directory (default: the configured site_dir)")
    parser.add_argument("--check", action="store_true",
                        help="verify the files on disk are current; write nothing")
    args = parser.parse_args(argv)

    meta = _config()
    docs = ROOT / meta.get("docs_dir", "docs")
    out = Path(args.out) if args.out else ROOT / "site"

    index, full = build(docs, meta)

    if args.check:
        stale = []
        for name, want in (("llms.txt", index), ("llms-full.txt", full)):
            path = out / name
            if not path.exists():
                stale.append(f"{path} is missing")
            elif path.read_text() != want:
                stale.append(f"{path} is out of date")
        if stale:
            print("\n".join(stale), file=sys.stderr)
            return 1
        print(f"llms.txt and llms-full.txt are current in {out}")
        return 0

    out.mkdir(parents=True, exist_ok=True)
    (out / "llms.txt").write_text(index)
    (out / "llms-full.txt").write_text(full)
    print(f"{out / 'llms.txt'}       {len(index):>9,} bytes")
    print(f"{out / 'llms-full.txt'}  {len(full):>9,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
