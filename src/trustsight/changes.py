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

The same module owns the typed *change-as-data* view (spec §1):
:func:`change_delta` parses a diff once into a :class:`ChangeDelta`, the
single query every consumer shares.  The prose summary above and the JSON
``change`` object render from that one object, so they cannot disagree by
construction.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .recipedoc import ArrayDelta

# Files that regenerate on nearly every bump.  Listing them trains the
# reader to skim the section, which costs more than the information is
# worth.
ALWAYS_NOISY = frozenset({".SRCINFO", ".gitignore"})

#: The checksum arrays makepkg reads, without their arch suffixes.
_CHECKSUM_NAMES = frozenset(
    {"md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums",
     "sha512sums", "b2sums"}
)

#: The dependency array families ``ChangeDelta`` reports separately.
_DEP_FAMILIES = ("depends", "makedepends", "checkdepends", "optdepends")


@dataclass(frozen=True)
class FileDelta:
    """One file's change: its status and the hunks it carries."""

    path: str
    old_path: str
    status: str
    hunks: tuple[int, ...]  # each hunk's new-side start line

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "old_path": self.old_path,
            "status": self.status,
            "hunks": list(self.hunks),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FileDelta":
        return cls(
            path=data.get("path", ""),
            old_path=data.get("old_path", ""),
            status=data.get("status", ""),
            hunks=tuple(data.get("hunks", ())),
        )


@dataclass(frozen=True)
class VersionFacts:
    """The resolved pkgver/pkgrel/epoch move, or what the diff shows of it.

    A value the pre- or post-projection does not carry (its assignment
    line sat outside every hunk) stays empty, and a comparison needs both
    sides, so ``moved`` is false rather than guessed.
    """

    old_pkgver: str = ""
    new_pkgver: str = ""
    old_pkgrel: str = ""
    new_pkgrel: str = ""
    old_epoch: str = ""
    new_epoch: str = ""
    pkgver_changed: bool = False
    moved: bool = False

    def to_dict(self) -> dict:
        return {
            "old_pkgver": self.old_pkgver,
            "new_pkgver": self.new_pkgver,
            "old_pkgrel": self.old_pkgrel,
            "new_pkgrel": self.new_pkgrel,
            "old_epoch": self.old_epoch,
            "new_epoch": self.new_epoch,
            "pkgver_changed": self.pkgver_changed,
            "moved": self.moved,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VersionFacts":
        return cls(
            old_pkgver=data.get("old_pkgver", ""),
            new_pkgver=data.get("new_pkgver", ""),
            old_pkgrel=data.get("old_pkgrel", ""),
            new_pkgrel=data.get("new_pkgrel", ""),
            old_epoch=data.get("old_epoch", ""),
            new_epoch=data.get("new_epoch", ""),
            pkgver_changed=bool(data.get("pkgver_changed", False)),
            moved=bool(data.get("moved", False)),
        )


@dataclass(frozen=True)
class ChangeDelta:
    """What changed in a diff, as one typed query result (spec §1).

    Built purely from the typed core: the diff parses once into a
    ``DiffDoc``, the pre/post projections become ``RecipeDoc``s, and each
    array family is an ``array_diff`` multiset query.  Consumers render
    this object instead of re-deriving change facts from raw text, so the
    summary, the change report and the rules cannot disagree.
    """

    files: tuple[FileDelta, ...]
    hosts_gained: frozenset[str]
    hosts_lost: frozenset[str]
    sources: "ArrayDelta"
    checksums: "ArrayDelta"
    pgp_keys: "ArrayDelta"
    dependencies: "ArrayDelta"
    makedependencies: "ArrayDelta"
    checkdependencies: "ArrayDelta"
    optdependencies: "ArrayDelta"
    version: VersionFacts
    #: The checksum-behaviour classification the summary already emits
    #: (``checksum_added_or_changed``, ``checksum_array_emptied``, ...).
    #: Carried so the prose summary is a pure render of this object and
    #: the two cannot disagree.
    checksum_behavior: str = "unchanged"
    #: Non-URL ``source=()`` entries whose local name appeared (or left)
    #: between the two sides.  ``local_source_names`` reads a tokenization
    #: the array delta does not reproduce exactly (comments, brace
    #: expansions), so its answer is carried here rather than re-derived
    #: by each consumer.
    local_sources_gained: frozenset[str] = frozenset()
    local_sources_lost: frozenset[str] = frozenset()
    #: True when a checksum array's entries changed relative order.
    #: Populated from ``sources``/``checksums``/``pgp_keys``; no rule
    #: consumes it in v1 (spec §6).
    reordered: bool = False

    def to_dict(self) -> dict:
        return {
            "files": [f.to_dict() for f in self.files],
            "hosts_gained": sorted(self.hosts_gained),
            "hosts_lost": sorted(self.hosts_lost),
            "sources": self.sources.to_dict(),
            "checksums": self.checksums.to_dict(),
            "pgp_keys": self.pgp_keys.to_dict(),
            "dependencies": self.dependencies.to_dict(),
            "makedependencies": self.makedependencies.to_dict(),
            "checkdependencies": self.checkdependencies.to_dict(),
            "optdependencies": self.optdependencies.to_dict(),
            "version": self.version.to_dict(),
            "checksum_behavior": self.checksum_behavior,
            "local_sources_gained": sorted(self.local_sources_gained),
            "local_sources_lost": sorted(self.local_sources_lost),
            "reordered": self.reordered,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChangeDelta":
        from .recipedoc import ArrayDelta

        return cls(
            files=tuple(FileDelta.from_dict(f) for f in data.get("files", ())),
            hosts_gained=frozenset(data.get("hosts_gained", ())),
            hosts_lost=frozenset(data.get("hosts_lost", ())),
            sources=ArrayDelta.from_dict(data.get("sources", {})),
            checksums=ArrayDelta.from_dict(data.get("checksums", {})),
            pgp_keys=ArrayDelta.from_dict(data.get("pgp_keys", {})),
            dependencies=ArrayDelta.from_dict(data.get("dependencies", {})),
            makedependencies=ArrayDelta.from_dict(
                data.get("makedependencies", {})),
            checkdependencies=ArrayDelta.from_dict(
                data.get("checkdependencies", {})),
            optdependencies=ArrayDelta.from_dict(
                data.get("optdependencies", {})),
            version=VersionFacts.from_dict(data.get("version", {})),
            checksum_behavior=data.get("checksum_behavior", "unchanged"),
            local_sources_gained=frozenset(data.get("local_sources_gained", ())),
            local_sources_lost=frozenset(data.get("local_sources_lost", ())),
            reordered=bool(data.get("reordered", False)),
        )


def _family(arrays: dict, base_names) -> tuple[str, ...]:
    """The occurrences of every ``name``/``name_<arch>`` array, in key order."""
    out: list[str] = []
    for key in sorted(arrays):
        if key in base_names or key.split("_", 1)[0] in base_names:
            out.extend(arrays[key])
    return tuple(out)


def _version_facts(pre, post) -> VersionFacts:
    """The resolved version scalars from the diff's two projections."""
    def scalar(recipe, name: str) -> str:
        return (recipe.scalars.get(name, "") or "").strip().strip("'\"")

    old_pkgver, new_pkgver = scalar(pre, "pkgver"), scalar(post, "pkgver")
    old_pkgrel, new_pkgrel = scalar(pre, "pkgrel"), scalar(post, "pkgrel")
    old_epoch, new_epoch = scalar(pre, "epoch"), scalar(post, "epoch")
    pairs = (
        (old_pkgver, new_pkgver), (old_pkgrel, new_pkgrel),
        (old_epoch, new_epoch),
    )
    moved = any(a and b and a != b for a, b in pairs)
    pkgver_changed = bool(old_pkgver and new_pkgver and old_pkgver != new_pkgver)
    return VersionFacts(
        old_pkgver=old_pkgver, new_pkgver=new_pkgver,
        old_pkgrel=old_pkgrel, new_pkgrel=new_pkgrel,
        old_epoch=old_epoch, new_epoch=new_epoch,
        pkgver_changed=pkgver_changed, moved=moved,
    )


def change_delta(diff_text: str) -> ChangeDelta:
    """Build the ``ChangeDelta`` for *diff_text* (spec §1).

    The one construction site: parse the diff once, project the pre/post
    recipes, and answer each family with ``recipedoc.array_diff``.

    The host sets mirror the summary's established URL facts (every
    URL-bearing added/removed line, not only ``source=()`` entries), so
    the prose summary is byte-identical when it renders from this object
    and the two surfaces cannot disagree by construction.  ``sources`` /
    ``checksums`` / ``pgp_keys`` stay the raw array deltas.
    """
    from .diffdoc import parse_diff
    from .differ import (
        _post_diff_lines,
        _pre_diff_lines,
        extract_urls_from_diff,
        local_source_names,
    )
    from .recipedoc import array_diff, recipe_states

    doc = parse_diff(diff_text)
    pre, post = recipe_states(doc)

    sources = array_diff(_family(pre.arrays, {"source"}),
                         _family(post.arrays, {"source"}))
    checksums = array_diff(_family(pre.arrays, _CHECKSUM_NAMES),
                           _family(post.arrays, _CHECKSUM_NAMES))
    pgp_keys = array_diff(pre.arrays.get("validpgpkeys", ()),
                          post.arrays.get("validpgpkeys", ()))
    dep_deltas = {
        name: array_diff(_family(pre.arrays, {name}),
                         _family(post.arrays, {name}))
        for name in _DEP_FAMILIES
    }
    # The summary's host and checksum facts, reproduced exactly: added
    # URLs' hosts minus removed URLs' hosts (and the mirror for lost), and
    # the checksum classification the same walk settles (including its
    # `checksum_array_removed` override for a declaration deleted whole).
    url_changes = extract_urls_from_diff(diff_text)
    added_hosts = {_host(u) for u in url_changes.added_urls if _host(u)}
    removed_hosts = {_host(u) for u in url_changes.removed_urls if _host(u)}
    post_sources = local_source_names("\n".join(_post_diff_lines(diff_text)))
    pre_sources = local_source_names("\n".join(_pre_diff_lines(diff_text)))
    return ChangeDelta(
        files=tuple(
            FileDelta(path=f.path, old_path=f.old_path, status=f.status,
                      hunks=tuple(h.new_start for h in f.hunks))
            for f in doc.files
        ),
        hosts_gained=frozenset(added_hosts - removed_hosts),
        hosts_lost=frozenset(removed_hosts - added_hosts),
        sources=sources,
        checksums=checksums,
        pgp_keys=pgp_keys,
        dependencies=dep_deltas["depends"],
        makedependencies=dep_deltas["makedepends"],
        checkdependencies=dep_deltas["checkdepends"],
        optdependencies=dep_deltas["optdepends"],
        version=_version_facts(pre, post),
        checksum_behavior=url_changes.checksum_behavior,
        local_sources_gained=frozenset(post_sources - pre_sources),
        local_sources_lost=frozenset(pre_sources - post_sources),
        reordered=(sources.reordered or checksums.reordered
                   or pgp_keys.reordered),
    )


def _host(url: str) -> str:
    """The host of *url*, in the one spelling the program agrees on.

    Routed through ``buckets.canonical_host`` so the change summary names
    the same host the classifier buckets: a URL with userinfo or a default
    port (``https://user@github.com:443/…``) is ``github.com`` to both, not
    ``github.com`` to the classifier and ``user@github.com:443`` to the
    reader.
    """
    rest = url.split("://", 1)[-1]
    netloc = rest.split("/", 1)[0]
    from .buckets import canonical_host

    return canonical_host(netloc)


def _pkgver_move(fact, diff_text: str) -> str | None:
    """``pkgver`` as the analysis resolved it changing.

    The bare-diff path (``scan_diff``, the corpus adapter) has no installed
    version to compare against, so the fact's version fields are empty and
    the move is only visible in the text.  A change summary that missed
    "the version moved" on that path would be missing the single most
    common change there is.

    The resolved values come from the fact (``pkgver_old``/``pkgver_new``),
    which the pipeline computed *with* the post-diff text.  Recomputing
    here from the diff alone lost the move whenever the ``pkgver=`` line
    sat outside the hunk and only its variable was visible - the summary
    said nothing changed while the rules fired.
    """
    if getattr(fact, "pkgver_changed", False):
        old = getattr(fact, "pkgver_old", "")

        new = getattr(fact, "pkgver_new", "")
        if old and new:
            return f"pkgver {old} -> {new}"
        if new:
            return f"pkgver set to {new}"
    # No canonical value on the fact (a hand-built fact, or a diff-only
    # caller): fall back to reading the diff.
    from .analysis.version import pkgver_move_in_diff

    moved, old, new = pkgver_move_in_diff(diff_text or "")
    if moved and old and new:
        return f"pkgver {old} -> {new}"
    if new and not old:
        return f"pkgver set to {new}"
    return None


def _delta_for(fact, diff_text: str):
    """The ``ChangeDelta`` behind *fact*, rebuilt from its stored form or
    the diff text; ``None`` when neither is available (an old cached row)."""
    raw = getattr(fact, "change", None)
    if raw:
        return ChangeDelta.from_dict(raw)
    if diff_text:
        return change_delta(diff_text)
    return None


def summarise(fact, diff_text: str = "") -> list[str]:
    """The change summary for *fact*, most structural first.

    The host and checksum entries render the :class:`ChangeDelta` (spec
    §1), so the prose and the JSON ``change`` object read the same facts.
    The remaining entries are facts the pipeline already settled on the
    fact (version resolution, maintainer, dependency names, file status).
    """
    from .analysis.version import COMPARISON_INCONCLUSIVE

    delta = _delta_for(fact, diff_text)
    entries: list[str] = []

    # "Nothing moved" is itself the most useful thing to be told.
    if fact.old_commit and fact.old_commit == fact.new_commit:
        return [
            "no changes in the AUR since last review "
            f"(commit {fact.new_commit[:8]})"
        ]

    old, new = fact.old_version, fact.new_version
    if not (old and new and old != new):
        moved = _pkgver_move(fact, diff_text)
        if moved:
            entries.append(moved)
    if old and new and old != new:
        if getattr(fact, "version_comparison", "") == COMPARISON_INCONCLUSIVE:
            from .verdict import inconclusive_reason

            entries.append(
                f"pkgver {old} installed / {new} in the AUR "
                f"(not comparable: {inconclusive_reason(fact)})"
            )
        else:
            entries.append(f"pkgver {old} -> {new}")

    # Two of the three values already begin with the word "checksum", so
    # prefixing every one of them produced "checksums checksum added or
    # changed".  Each is spelled out here instead of being derived from the
    # identifier, because the identifier is a key and this is a sentence.
    _CHECKSUM_WORDING = {
        "checksum_added_or_changed": "checksums added or changed",
        "checksum_array_emptied": "checksums emptied",
        "checksum_entry_removed": "checksum entry removed",
        "checksum_array_removed": "checksum array removed",
        "changed_from_sha256_to_skip": "checksums changed from sha256 to SKIP",
    }
    behaviour = (
        delta.checksum_behavior if delta is not None
        else getattr(fact.source_changes, "checksum_behavior", "")
    )
    if behaviour and behaviour != "unchanged":
        entries.append(
            _CHECKSUM_WORDING.get(behaviour, f"checksums {behaviour.replace('_', ' ')}")
        )

    if fact.maintainer_changed:
        entries.append(
            f"maintainer changed ({fact.previous_maintainer or '?'} -> "
            f"{fact.current_maintainer or '?'})"
        )

    if delta is not None:
        new_hosts = sorted(delta.hosts_gained)
        removed_hosts = set(delta.hosts_lost)
    else:
        added_hosts = {_host(u) for u in fact.source_changes.added_urls}
        removed_hosts = {_host(u) for u in fact.source_changes.removed_urls}
        new_hosts = sorted(h for h in added_hosts - removed_hosts if h)
    if new_hosts and removed_hosts:
        entries.append(f"source host changed: {', '.join(new_hosts)}")
    elif new_hosts:
        entries.append(f"source host added: {', '.join(new_hosts)}")

    # A source entry that is not a URL (a committed patch, a companion file)
    # is invisible to the host summary above.  On the history path the file
    # itself is not in the diff at all, so naming it is the only signal that
    # the source set grew.
    new_sources: list[str] = []
    if delta is not None:
        new_sources = sorted(delta.local_sources_gained)
    elif diff_text:
        from .differ import _post_diff_lines, _pre_diff_lines, local_source_names

        post_sources = local_source_names("\n".join(_post_diff_lines(diff_text)))
        pre_sources = local_source_names("\n".join(_pre_diff_lines(diff_text)))
        new_sources = sorted(post_sources - pre_sources)
    if new_sources:
        entries.append("source file(s) added: " + ", ".join(new_sources))

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

    # extract_dependency_changes returns {field: {newly added names}}, so
    # every name here is an addition.  This block read a {op: names} shape
    # that nothing produced, and the field it read was never populated, so
    # dependency changes were silently absent from every summary.
    for field_name, names in sorted((getattr(fact, "dependency_changes", None) or {}).items()):
        if names:
            added = " ".join("+" + n for n in sorted(names))
            entries.append(f"{field_name}: {added}")

    if not entries:
        entries.append("no declared facts changed in the recipe")
    return entries
