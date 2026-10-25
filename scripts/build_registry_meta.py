"""Bootstrap ``registry_meta.json`` from the current rule sources.

One-time: after this runs, ``src/trustsight/registry_meta.json`` is the
source of truth for a section's display name and the ``Target`` /
``Severity`` / ``Category`` bullets, and ``docs_src/sections/`` is prose
only.  The dictionary is keyed by anchor (a rule may have two sections -
H026 has a per-package and a corpus path), and each entry carries the
permanent ``uid`` plus a ``canonical`` flag for the one the rule itself is
named after.

Code can emit a rule under more than one name or severity (H075 names the
three process-substitution paths; H078 tiers replacement/addition/
introduction), so the docs keep one representative name and the full
severity text - the per-branch spellings stay in the emitters and are
checked by ``tests/test_rule_metadata.py``.

Run once::

    uv run python scripts/build_registry_meta.py

It refuses to overwrite an existing file without ``--force``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

SRC = ROOT / "docs_src"
SECTIONS = SRC / "sections"
LAYOUT = SRC / "layout.json"
OUT = ROOT / "src" / "trustsight" / "registry_meta.json"

META = re.compile(r"^<!-- (uid|name|anchor): (.*) -->$")
BULLET = re.compile(r"^- \*\*(Target|Severity|Category):\*\* (.*)$")
SEVERITY = re.compile(r"\b(FATAL|CRITICAL|HIGH|MEDIUM|LOW|INFO)\b")


def _parse(text: str) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """(comments, metadata bullets, remaining body lines).

    A bullet may wrap onto indented continuation lines (H025 and H103 both
    list two severity tiers that way); the continuation belongs to the
    bullet, so it is not left behind in the prose.
    """
    comments: dict[str, str] = {}
    values: dict[str, str] = {}
    body: list[str] = []
    in_header = True
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if in_header:
            found = META.match(line)
            if found:
                comments[found.group(1)] = found.group(2)
                i += 1
                continue
            in_header = False
        found = BULLET.match(line)
        if found:
            value = found.group(2).rstrip()
            i += 1
            while i < len(lines) and lines[i].startswith("  ") and lines[i].strip():
                value += "\n" + lines[i]
                i += 1
            values[found.group(1)] = value
            continue
        body.append(line)
        i += 1
    return comments, values, body


def _canonical_anchors() -> dict[str, str]:
    """uid -> the first anchor the curated layout shows for that rule."""
    layout = json.loads(LAYOUT.read_text())
    first: dict[str, str] = {}
    for anchors in layout.values():
        for anchor in anchors:
            comments, _values, _body = _parse(
                (SECTIONS / f"{anchor}.md").read_text()
            )
            first.setdefault(comments["uid"], anchor)
    return first


def _head_metadata() -> dict:
    """The last committed metadata, used only for prose-only legacy sections."""
    import subprocess

    result = subprocess.run(
        ["git", "show", "HEAD:src/trustsight/registry_meta.json"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    if result.returncode:
        return {}
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def main() -> None:
    force = "--force" in sys.argv[1:]
    if OUT.exists() and not force:
        raise SystemExit(f"{OUT} exists; pass --force to rewrite it")

    canonical = _canonical_anchors()
    previous = _head_metadata()
    meta: dict[str, dict] = {}
    for section in sorted(SECTIONS.glob("*.md")):
        text = section.read_text()
        comments, values, body = _parse(text)
        uid = comments.get("uid")
        anchor = comments.get("anchor", section.stem)
        if not uid:
            raise SystemExit(f"{section.name}: no uid comment")
        severity_text = values.get("Severity")
        found = SEVERITY.search(severity_text) if severity_text else None
        capability = values.get("Category")
        if capability:
            capability = capability.strip("`").strip()
        prior = previous.get(anchor, {})
        meta[anchor] = {
            "uid": uid,
            # Older prose-only sections have no name comment. Preserve the
            # committed display metadata rather than nulling every rule when
            # the registry is regenerated (new comments always win).
            "name": comments.get("name") or prior.get("name"),
            "canonical": canonical.get(uid) == anchor,
            "severity_text": severity_text or prior.get("severity_text"),
            "severity": found.group(1) if found else prior.get("severity"),
            "capability": capability or prior.get("capability"),
            "target": values.get("Target") or prior.get("target"),
        }
        # Prose only: the bullets are rendered back from the registry. Keep
        # the name comment too, or the next regeneration cannot reproduce it.
        name = meta[anchor]["name"]
        section.write_text(
            f"<!-- uid: {uid} -->\n"
            f"<!-- anchor: {anchor} -->\n"
            + (f"<!-- name: {name} -->\n" if name else "")
            + "\n"
            + "\n".join(body).strip("\n")
            + "\n"
        )

    OUT.write_text(json.dumps(dict(sorted(meta.items())), indent=2) + "\n")
    print(f"wrote {len(meta)} sections to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
