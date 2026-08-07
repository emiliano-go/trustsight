"""B7: what the diff did, whether or not any rule matched.

A report made only of findings cannot distinguish "nothing fired and
nothing changed" from "nothing fired and a great deal changed".  Absence
of alerts then reads as absence of change, which is the same collapse the
evidence taxonomy already refuses one layer down: an unknown must not read
as nothing found, and neither must a change.

Every entry here is a *declared fact* about the diff, derived from data
already parsed.  Entries carry no severity and no points, never appear in
``triggered_rules``, and are not findings: conflating the two would
corrupt the calibration and the reader's sense of what a finding means.
"""

# Files that regenerate on nearly every bump.  Listing them trains the
# reader to skim the section, which costs more than the information is
# worth.
import re

ALWAYS_NOISY = frozenset({".SRCINFO", ".gitignore"})


def _host(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].lower()


_PKGVER_RE = re.compile(r"^([+-])\s*pkgver\s*=\s*(.+?)\s*$", re.MULTILINE)


def _pkgver_move(diff_text: str) -> str | None:
    """``pkgver`` as the diff itself shows it changing.

    The bare-diff path (``scan_diff``, the corpus adapter) has no installed
    version to compare against, so the fact's version fields are empty and
    the move is only visible in the text.  A change summary that missed
    "the version moved" on that path would be missing the single most
    common change there is.
    """
    old = new = None
    for sign, value in _PKGVER_RE.findall(diff_text or ""):
        if sign == "-":
            old = value.strip("\"'")
        else:
            new = value.strip("\"'")
    if new and old and old != new:
        return f"pkgver {old} -> {new}"
    if new and not old:
        return f"pkgver set to {new}"
    return None


def summarise(fact, diff_text: str = "") -> list[str]:
    """The change summary for *fact*, most structural first."""
    from .analysis.version import COMPARISON_INCONCLUSIVE

    entries: list[str] = []

    # "Nothing moved" is itself the most useful thing to be told.
    if fact.old_commit and fact.old_commit == fact.new_commit:
        return [
            "no changes in the AUR since last review "
            f"(commit {fact.new_commit[:8]})"
        ]

    old, new = fact.old_version, fact.new_version
    if not (old and new and old != new):
        moved = _pkgver_move(diff_text)
        if moved:
            entries.append(moved)
    if old and new and old != new:
        if getattr(fact, "version_comparison", "") == COMPARISON_INCONCLUSIVE:
            entries.append(f"pkgver {old} installed / {new} in the AUR (not comparable)")
        else:
            entries.append(f"pkgver {old} -> {new}")

    behaviour = getattr(fact.source_changes, "checksum_behavior", "")
    if behaviour and behaviour != "unchanged":
        entries.append(f"checksums {behaviour.replace('_', ' ')}")

    if fact.maintainer_changed:
        entries.append(
            f"maintainer changed ({fact.previous_maintainer or '?'} -> "
            f"{fact.current_maintainer or '?'})"
        )

    added_hosts = {_host(u) for u in fact.source_changes.added_urls}
    removed_hosts = {_host(u) for u in fact.source_changes.removed_urls}
    new_hosts = sorted(h for h in added_hosts - removed_hosts if h)
    if new_hosts and removed_hosts:
        entries.append(f"source host changed: {', '.join(new_hosts)}")
    elif new_hosts:
        entries.append(f"source host added: {', '.join(new_hosts)}")

    for change in fact.diff_summary.file_changes:
        path = change.get("path", "")
        if not path or path in ALWAYS_NOISY:
            continue
        status = change.get("status", "modified")
        if status == "added":
            entries.append(f"new file: {path}")
        elif status == "removed":
            entries.append(f"file removed: {path}")
        elif status == "renamed":
            entries.append(f"file renamed: {path}")

    for kind, names in (("depends", getattr(fact, "dependency_changes", None) or {}),):
        for op, listed in sorted(names.items()):
            if listed:
                sign = "+" if op == "added" else "-"
                entries.append(f"{kind}: {' '.join(sign + n for n in sorted(listed))}")

    if not entries:
        entries.append("no declared facts changed in the recipe")
    return entries
