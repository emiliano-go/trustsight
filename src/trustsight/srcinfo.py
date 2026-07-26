import re
from collections import defaultdict

SRCINFO_RE = re.compile(r"^\s*(?:\w+)\s*=\s*(.+)$")


def parse_srcinfo(text: str) -> dict[str, list[str]]:
    """Parse a .SRCINFO text into a key-value mapping."""
    result: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^\s*(\w+)\s*=\s*(.+)$", line)
        if m:
            key = m.group(1)
            value = m.group(2).strip()
            if value not in result[key]:
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
            added = [v for v in new_vals if v not in old_vals]
            removed = [v for v in old_vals if v not in new_vals]
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
