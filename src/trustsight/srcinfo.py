"""Parsing for ``.SRCINFO``, the generated metadata beside a PKGBUILD.

Used by ``scripts/generate_seed.py`` to read sources and dependencies out of
a corpus checkout. The text is written by the party under review, so the
bounds here are A14 bounds rather than tidiness: a ``.SRCINFO`` is generated
by ``makepkg --printsrcinfo`` in the ordinary case and by whatever the
author likes in the case that matters.
"""

import re
from collections import defaultdict

#: Bytes of ``.SRCINFO`` text parsed. The real files are a few KiB; nothing
#: in the format needs more, and the blob arrives from a repository.
MAX_SRCINFO_BYTES = 4 * 1024 * 1024

#: Lines read from one file. The byte cap is not a line cap, and the parse
#: cost is per line.
MAX_SRCINFO_LINES = 100_000

#: Values retained per key. `depends` legitimately holds dozens; a file
#: declaring millions is bounding this process's memory, not its packaging.
MAX_SRCINFO_VALUES_PER_KEY = 4096

SRCINFO_RE = re.compile(r"^\s*(?:\w+)\s*=\s*(.+)$")

_LINE_RE = re.compile(r"^\s*(\w+)\s*=\s*(.+)$")


def parse_srcinfo(text: str) -> dict[str, list[str]]:
    """Parse a .SRCINFO text into a key-value mapping."""
    if len(text) > MAX_SRCINFO_BYTES:
        text = text[:MAX_SRCINFO_BYTES]
    result: dict[str, list[str]] = defaultdict(list)
    # Membership by set rather than by scanning the list: the duplicate
    # check used to be `value not in result[key]`, which is linear in the
    # values already held and quadratic over a file that repeats one key.
    seen: dict[str, set[str]] = defaultdict(set)
    for index, line in enumerate(text.splitlines()):
        if index >= MAX_SRCINFO_LINES:
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if m:
            key = m.group(1)
            value = m.group(2).strip()
            if value in seen[key]:
                continue
            if len(result[key]) >= MAX_SRCINFO_VALUES_PER_KEY:
                continue
            seen[key].add(value)
            result[key].append(value)
    return dict(result)


SCALAR_KEYS = frozenset({
    "pkgbase", "pkgver", "pkgrel", "epoch", "pkgdesc",
    "url", "install", "changelog",
})
ARRAY_KEYS = frozenset({
    "arch", "license", "groups", "source",
    "noextract", "backup", "options", "validpgpkeys",
    "depends", "makedepends", "checkdepends", "optdepends",
    "provides", "conflicts", "replaces",
    "md5sums", "sha1sums", "sha224sums", "sha256sums",
    "sha384sums", "sha512sums", "b2sums",
})


def diff_srcinfo(
    old: dict[str, list[str]], new: dict[str, list[str]]
) -> dict[str, dict]:
    """Compare two parsed .SRCINFO dicts and return the changes."""
    changes: dict[str, dict] = {}
    all_keys = set(old) | set(new)
    for key in sorted(all_keys):
        old_vals = old.get(key, [])
        new_vals = new.get(key, [])
        if old_vals == new_vals:
            continue
        if key in SCALAR_KEYS:
            changes[key] = {"old": old_vals[0] if old_vals else "", "new": new_vals[0] if new_vals else ""}
        else:
            # Sets for membership, lists for output: the comprehensions
            # below were each linear in the other side, so comparing two
            # large arrays cost their product.
            old_set = set(old_vals)
            new_set = set(new_vals)
            added = [v for v in new_vals if v not in old_set]
            removed = [v for v in old_vals if v not in new_set]
            if added or removed:
                changes[key] = {"added": added, "removed": removed}
    return changes


def get_srcinfo_from_tree(repo, commit_oid: str) -> dict[str, list[str]]:
    """Retrieve and parse .SRCINFO from a git commit tree."""
    try:
        commit = repo.get(commit_oid)
        if commit is None:
            return {}
        tree = commit.tree
        entry = tree.get(".SRCINFO")
        if entry is None:
            return {}
        blob = repo.get(entry.oid)
        if blob is None:
            return {}
        return parse_srcinfo(blob.data.decode("utf-8", errors="replace"))
    except (AttributeError, KeyError, TypeError):
        return {}
