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

The same module owns the typed *change-as-data* view:
:func:`change_delta` parses a diff once into a :class:`ChangeDelta`, the
single query every consumer shares.  The prose summary above and the JSON
``change`` object render from that one object, so they cannot disagree by
construction.
"""

from dataclasses import dataclass, field

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

#: Every field ``deps.extract_dependency_changes`` extracts: the four
#: dependency families plus the three relational arrays.
_DEP_ALL_FIELDS = _DEP_FAMILIES + ("provides", "replaces", "conflicts")


@dataclass(frozen=True)
class FileDelta:
    """One file's change: its status and the hunks it carries.

    :ivar path: path in the post-change tree.
    :ivar old_path: path in the pre-change tree (the same as :attr:`path`
        unless the file was renamed).
    :ivar status: one of ``added``, ``removed`` or ``modified``.
    :ivar hunks: each hunk's new-side start line.

    Example:
        .. code-block:: python

            for change in report.change_delta.files:
                print(change.status, change.path, change.hunks)
    """

    path: str
    old_path: str
    status: str
    hunks: tuple[int, ...]  # each hunk's new-side start line

    def to_dict(self) -> dict:
        """Serialize the file change to a plain dict."""
        return {
            "path": self.path,
            "old_path": self.old_path,
            "status": self.status,
            "hunks": list(self.hunks),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FileDelta":
        """Rebuild a file change from :meth:`to_dict` output."""
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

    :ivar old_pkgver: resolved ``pkgver`` before the change, or "".
    :ivar new_pkgver: resolved ``pkgver`` after the change, or "".
    :ivar old_pkgrel: ``pkgrel`` before the change, or "".
    :ivar new_pkgrel: ``pkgrel`` after the change, or "".
    :ivar old_epoch: ``epoch`` before the change, or "".
    :ivar new_epoch: ``epoch`` after the change, or "".
    :ivar pkgver_changed: the diff moved ``pkgver`` itself.
    :ivar moved: any of ``pkgver``/``pkgrel``/``epoch`` moved by resolved
        value.

    Example:
        .. code-block:: python

            version = report.change_delta.version
            if version.moved:
                print(version.old_pkgver, "->", version.new_pkgver)
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
        """Serialize the version facts to a plain dict."""
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
        """Rebuild version facts from :meth:`to_dict` output."""
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
class ManifestDelta:
    """One committed manifest's change, from the typed diff (U-series).

    Derived once from the parsed ``ManifestDoc`` on each side, so the change
    summary, the U-rules and the correlation feed read one object.

    :ivar path: manifest path in the package tree.
    :ivar format: manifest format (for example ``Cargo.lock`` or
        ``package.json``).
    :ivar status: ``added``, ``removed`` or ``modified``.
    :ivar added: dependency names the change added.
    :ivar removed: dependency names the change removed.
    :ivar remote_added: remote name/host pairs the change introduced.
    :ivar redirects: ``(from, to)`` registry redirects the change records.
    :ivar unresolved: entries the parser could not resolve.
    :ivar old_count: dependency count before the change.
    :ivar new_count: dependency count after the change.
    :ivar origin_changes: credential-free dependency origin transitions.
    :ivar integrity_changes: lock integrity removals or algorithm downgrades.

    Example:
        .. code-block:: python

            for manifest in report.change_delta.manifests:
                print(manifest.format, manifest.added)
    """

    path: str
    format: str
    status: str
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    remote_added: tuple[str, ...] = ()
    redirects: tuple[tuple[str, str], ...] = ()
    unresolved: tuple[str, ...] = ()
    old_count: int = 0
    new_count: int = 0
    origin_changes: tuple[str, ...] = ()
    integrity_changes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        """Serialize the manifest change to a plain dict."""
        return {
            "path": self.path,
            "format": self.format,
            "status": self.status,
            "added": list(self.added),
            "removed": list(self.removed),
            "remote_added": list(self.remote_added),
            "redirects": [list(r) for r in self.redirects],
            "unresolved": list(self.unresolved),
            "old_count": self.old_count,
            "new_count": self.new_count,
            "origin_changes": list(self.origin_changes),
            "integrity_changes": list(self.integrity_changes),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ManifestDelta":
        """Rebuild a manifest change from :meth:`to_dict` output."""
        return cls(
            path=data.get("path", ""),
            format=data.get("format", ""),
            status=data.get("status", ""),
            added=tuple(data.get("added", ())),
            removed=tuple(data.get("removed", ())),
            remote_added=tuple(data.get("remote_added", ())),
            redirects=tuple((r[0], r[1]) for r in data.get("redirects", ())),
            unresolved=tuple(data.get("unresolved", ())),
            old_count=int(data.get("old_count", 0)),
            new_count=int(data.get("new_count", 0)),
            origin_changes=tuple(data.get("origin_changes", ())),
            integrity_changes=tuple(data.get("integrity_changes", ())),
        )


@dataclass(frozen=True)
class ChangeDelta:
    """What changed in a diff, as one typed query result.

    Built purely from the typed core: the diff parses once into a
    ``DiffDoc``, the pre/post projections become ``RecipeDoc``s, and each
    array family is an ``array_diff`` multiset query.  Consumers render
    this object instead of re-deriving change facts from raw text, so the
    summary, the change report and the rules cannot disagree.

    :ivar files: one :class:`FileDelta` per file the diff touched.
    :ivar hosts_gained: canonical source hosts the change introduced.
    :ivar hosts_lost: canonical source hosts the change removed.
    :ivar sources: multiset delta of the raw ``source=()`` entries.
    :ivar checksums: multiset delta of the checksum arrays.
    :ivar pgp_keys: multiset delta of ``validpgpkeys``.
    :ivar dependencies: multiset delta of ``depends``.
    :ivar makedependencies: multiset delta of ``makedepends``.
    :ivar checkdependencies: multiset delta of ``checkdepends``.
    :ivar optdependencies: multiset delta of ``optdepends``.
    :ivar version: resolved ``pkgver``/``pkgrel``/``epoch`` movement.
    :ivar provides: multiset delta of ``provides``.
    :ivar replaces: multiset delta of ``replaces``.
    :ivar conflicts: multiset delta of ``conflicts``.
    :ivar added_dependencies: normalised added names per dependency field,
        the same view ``deps.extract_dependency_changes`` produces.
    :ivar checksum_behavior: the checksum classification the summary
        emits (``checksum_added_or_changed``, ``checksum_array_emptied``,
        ...).
    :ivar local_sources_gained: non-URL ``source=()`` local names that
        appeared.
    :ivar local_sources_lost: non-URL ``source=()`` local names that left.
    :ivar reordered: a checksum array's entries changed relative order.
    :ivar checksum_parity: ``(sources, sums, var)`` when the declared
        checksum array is short, else ``None``.
    :ivar source_array_grew: the source array grew in this diff.
    :ivar manifests: one :class:`ManifestDelta` per committed manifest the
        diff touched.

    Example:
        .. code-block:: python

            from trustsight import TrustSight

            change = TrustSight().inspect("some-package").change_delta
            print(change.version.old_pkgver, "->", change.version.new_pkgver)
            for name in change.added_dependencies.get("depends", ()):
                print("new dependency:", name)
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
    # The relational arrays, raw. ``provides`` /
    #: ``replaces`` / ``conflicts`` claim or remove another name; they are
    #: dependency-shaped and share the extraction path.
    provides: ArrayDelta = field(default_factory=lambda: ArrayDelta((), (), False))
    replaces: ArrayDelta = field(default_factory=lambda: ArrayDelta((), (), False))
    conflicts: ArrayDelta = field(default_factory=lambda: ArrayDelta((), (), False))
    #: The *normalised* added names per dependency field, the exact view
    #: ``deps.extract_dependency_changes`` produces (version constraints and
    #: optdepends descriptions dropped, unresolved/soname entries filtered).
    #: H030/H064 and the D-series read this instead of re-extracting, so the
    #: change view and the rules cannot disagree.
    added_dependencies: dict[str, tuple[str, ...]] = field(default_factory=dict)
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
    #: consumes it in v1.
    reordered: bool = False
    #: H091's parity result over wholly-added arrays, and whether the source
    #: array grew in the diff (the gate for reading the complete recipe
    #: instead).  Carried so the rule reads one shared object rather than
    #: re-walking the diff; the ``current_text`` fallback still runs in the
    #: rule, because the whole PKGBUILD is not part of a diff object.
    checksum_parity: "tuple[int, int, str] | None" = None
    source_array_grew: bool = False
    #: U-series: one entry per committed upstream manifest the diff touched
    #: (added, removed or modified).  Empty when the diff carries none.
    manifests: tuple[ManifestDelta, ...] = ()

    def to_dict(self) -> dict:
        """Serialize the change view to the report's ``change`` body."""
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
            "provides": self.provides.to_dict(),
            "replaces": self.replaces.to_dict(),
            "conflicts": self.conflicts.to_dict(),
            "added_dependencies": {
                k: list(v) for k, v in sorted(self.added_dependencies.items())
            },
            "version": self.version.to_dict(),
            "checksum_behavior": self.checksum_behavior,
            "local_sources_gained": sorted(self.local_sources_gained),
            "local_sources_lost": sorted(self.local_sources_lost),
            "reordered": self.reordered,
            "checksum_parity": (
                {"sources": self.checksum_parity[0],
                 "sums": self.checksum_parity[1],
                 "var": self.checksum_parity[2]}
                if self.checksum_parity is not None else None
            ),
            "source_array_grew": self.source_array_grew,
            "manifests": [m.to_dict() for m in self.manifests],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChangeDelta":
        """Rebuild the change view from :meth:`to_dict` output."""
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
            provides=ArrayDelta.from_dict(data.get("provides", {})),
            replaces=ArrayDelta.from_dict(data.get("replaces", {})),
            conflicts=ArrayDelta.from_dict(data.get("conflicts", {})),
            added_dependencies={
                k: tuple(v) for k, v in
                (data.get("added_dependencies", {}) or {}).items()
            },
            version=VersionFacts.from_dict(data.get("version", {})),
            checksum_behavior=data.get("checksum_behavior", "unchanged"),
            local_sources_gained=frozenset(data.get("local_sources_gained", ())),
            local_sources_lost=frozenset(data.get("local_sources_lost", ())),
            reordered=bool(data.get("reordered", False)),
            checksum_parity=(
                (data["checksum_parity"]["sources"],
                 data["checksum_parity"]["sums"],
                 data["checksum_parity"]["var"])
                if data.get("checksum_parity") else None
            ),
            source_array_grew=bool(data.get("source_array_grew", False)),
            manifests=tuple(
                ManifestDelta.from_dict(m)
                for m in data.get("manifests", ())
            ),
        )


def _array_closes(text: str, start: int) -> bool:
    """True when the ``(`` at *start* is balanced by a later ``)``.

    Depth-aware, quote-aware, and comment-aware: ``source=(`` followed by
    ``_makeopts=(CC=gcc-15 CXX=g++-15)`` never reaches depth 0 - the nested
    array's own paren only balances itself - so the declaration is read as
    unterminated, exactly as the tokenizer's collector reads it.
    """
    depth = 0
    quote = ""
    comment = False
    boundary = True
    for ch in text[start:]:
        if comment:
            if ch == "\n":
                comment = False
                boundary = True
            continue
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "#" and boundary:
            comment = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return True
        boundary = ch.isspace() or ch in ";|&("
    return False


def _drop_unclosed_arrays(
    arrays: dict[str, tuple[str, ...]], text: str
) -> dict[str, tuple[str, ...]]:
    """Arrays whose closing paren never appears in *text*.

    A hunk can show ``source=(`` without its ``)``: the tokenizer then reads
    every following line - another array's opener, hex-looking words - as
    entries of the still-open array, and the array delta leaks them.
    Fail-closed, mirroring ``_added_array_items``: a declaration that does
    not close inside this side's projection is not a value this side knows,
    so it is dropped before diffing.
    """
    import re

    kept: dict[str, tuple[str, ...]] = {}
    for name, entries in arrays.items():
        opener = re.compile(
            r"^\s*" + re.escape(name) + r"\s*\+?=\s*\(", re.MULTILINE
        )
        last_open: int | None = None
        for match in opener.finditer(text):
            last_open = text.index("(", match.start())
        if last_open is not None and not _array_closes(text, last_open):
            continue
        kept[name] = entries
    return kept


def _fold_scalars(
    entries: tuple[str, ...], scalars: dict[str, str]
) -> tuple[str, ...]:
    """Literal array entries with the recipe's scalars folded in.

    The array table keeps entries literal (``${pkgbase%-bin}``), so a
    reader comparing values has to apply the same fold the relational
    arrays use.  makepkg's implicit ``pkgbase=$pkgname`` default is applied
    when no explicit ``pkgbase`` is declared.  Unresolved entries are
    returned as they stand; the caller decides whether that is "unknown"
    (dependency validation) or "drop" (relational diffing).
    """
    import re

    from .expansion import resolve_expansions

    table = dict(scalars)
    table.setdefault("pkgbase", (table.get("pkgname") or "").strip())
    folded: list[str] = []
    for entry in entries:
        # Braced forms first: resolve_expansions handles ${pkgbase%-bin}
        # against the table; a naive $name replace would shred the `${`.
        value, _ok = resolve_expansions(entry, table)
        value = re.sub(
            r"\$([A-Za-z_][A-Za-z0-9_]*)",
            lambda m: table.get(m.group(1), m.group(0)),
            value,
        )
        folded.append(value)
    return tuple(folded)


def _resolve_relational(
    entries: tuple[str, ...], scalars: dict[str, str]
) -> tuple[str, ...]:
    """Relational-array entries with the recipe's scalars folded in.

    An entry that still holds an unexpanded ``${``/``$(`` after
    substitution is dropped rather than diffed raw, following the fold
    model of ``deps.declared_package_names``.
    """
    return tuple(
        value for value in _fold_scalars(entries, scalars)
        if "${" not in value and "$(" not in value
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


def change_delta(
    diff_text: str,
    pkgbase: str = "",
    current_text: str | None = None,
) -> ChangeDelta:
    """Build the ``ChangeDelta`` for *diff_text*.

    The one construction site: parse the diff once, project the pre/post
    recipes, and answer each family with ``recipedoc.array_diff``.

    The host sets mirror the summary's established URL facts (every
    URL-bearing added/removed line, not only ``source=()`` entries), so
    the prose summary is byte-identical when it renders from this object
    and the two surfaces cannot disagree by construction.  ``sources`` /
    ``checksums`` / ``pgp_keys`` stay the raw array deltas.

    *pkgbase* lets the normalised ``added_dependencies`` view apply the
    same self-output filter ``deps.extract_dependency_changes`` uses; the
    rules pass the analysed package name.  *current_text*, when it is the
    authoritative post-state recipe, validates those claims against the
    arrays the change actually leaves behind (see
    ``deps.extract_dependency_changes``).
    """
    from .diffdoc import parse_diff
    from .differ import (
        _post_diff_lines,
        _pre_diff_lines,
        checksum_array_parity,
        extract_urls_from_diff,
        local_source_names,
        source_array_grew_in_diff,
    )
    from .recipedoc import array_diff, recipe_states

    doc = parse_diff(diff_text)
    pre, post = recipe_states(doc)
    pre_arrays = _drop_unclosed_arrays(pre.arrays, "\n".join(doc.pre_lines()))
    post_arrays = _drop_unclosed_arrays(post.arrays, "\n".join(doc.post_lines()))

    sources = array_diff(_family(pre_arrays, {"source"}),
                         _family(post_arrays, {"source"}))
    checksums = array_diff(_family(pre_arrays, _CHECKSUM_NAMES),
                           _family(post_arrays, _CHECKSUM_NAMES))
    pgp_keys = array_diff(pre_arrays.get("validpgpkeys", ()),
                          post_arrays.get("validpgpkeys", ()))
    dep_deltas = {
        name: array_diff(_family(pre_arrays, {name}),
                         _family(post_arrays, {name}))
        for name in _DEP_FAMILIES
    }
    relational = {
        name: array_diff(
            _resolve_relational(_family(pre_arrays, {name}), pre.scalars),
            _resolve_relational(_family(post_arrays, {name}), post.scalars),
        )
        for name in ("provides", "replaces", "conflicts")
    }
    from .deps import extract_dependency_changes

    extracted = extract_dependency_changes(
        diff_text, pkgbase, current_text=current_text
    )
    added_dependencies = {
        name: tuple(sorted(extracted.get(name, ())))
        for name in _DEP_ALL_FIELDS
    }
    # The summary's host and checksum facts, reproduced exactly: added
    # URLs' hosts minus removed URLs' hosts (and the mirror for lost), and
    # the checksum classification the same walk settles (including its
    # `checksum_array_removed` override for a declaration deleted whole).
    url_changes = extract_urls_from_diff(diff_text, current_text=current_text)
    declared_urls = set(url_changes.declared_urls)
    manifests = _manifest_deltas(doc)
    added_hosts = {_host(u) for u in url_changes.added_urls
                   if u not in declared_urls and _host(u)}
    removed_hosts = {_host(u) for u in url_changes.removed_urls
                     if u not in declared_urls and _host(u)}
    # U003: a remote host a committed manifest introduces joins the same
    # ``hosts_gained`` view as a ``source=()`` host, so host-novelty tiers,
    # source buckets and the G-series read both the same way.
    added_hosts |= {h for m in manifests for h in m.remote_added}
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
        provides=relational["provides"],
        replaces=relational["replaces"],
        conflicts=relational["conflicts"],
        added_dependencies=added_dependencies,
        version=_version_facts(pre, post),
        checksum_behavior=url_changes.checksum_behavior,
        local_sources_gained=frozenset(post_sources - pre_sources),
        local_sources_lost=frozenset(pre_sources - post_sources),
        reordered=(sources.reordered or checksums.reordered
                   or pgp_keys.reordered),
        checksum_parity=checksum_array_parity(diff_text),
        source_array_grew=source_array_grew_in_diff(diff_text),
        manifests=manifests,
    )


def manifest_delta_from_docs(
    path: str, fmt: str, status: str, pre_doc, post_doc,
    *, added_text: str = "", removed_text: str = "",
) -> ManifestDelta:
    """Diff two parsed manifests, optionally with hunk-only fallback text.

    Complete old/new documents give exact old state. The fallback keeps the
    section-agnostic reader for standalone diffs whose section headers sit
    outside the hunk.
    """
    from .analysis.manifests import (
        upstream_redirect_signals,
        upstream_source_deps,
        upstream_source_hosts,
    )

    old = {d.name for d in (pre_doc.dependencies if pre_doc else ()) if d.name}
    new = {d.name for d in (post_doc.dependencies if post_doc else ()) if d.name}
    old |= {d.name for d in upstream_source_deps(removed_text) if d.name}
    new |= {d.name for d in upstream_source_deps(added_text) if d.name}
    old_remotes = {
        d.remote for d in (pre_doc.dependencies if pre_doc else ()) if d.remote
    }
    new_remotes = {
        d.remote for d in (post_doc.dependencies if post_doc else ()) if d.remote
    }
    old_remotes |= upstream_source_hosts(removed_text)
    new_remotes |= upstream_source_hosts(added_text)

    before = {d.name: d for d in (pre_doc.dependencies if pre_doc else ()) if d.name}
    after = {d.name: d for d in (post_doc.dependencies if post_doc else ()) if d.name}
    origin_changes = []
    integrity_changes = []
    for name in sorted(before.keys() & after.keys()):
        old_dep, new_dep = before[name], after[name]
        old_origin = (old_dep.source_kind, old_dep.origin)
        new_origin = (new_dep.source_kind, new_dep.origin)
        if old_origin != new_origin and (old_dep.origin or new_dep.origin):
            old_label = old_dep.origin or "default registry"
            new_label = new_dep.origin or "default registry"
            origin_changes.append(f"{name}: {old_label} -> {new_label}")
        old_integrity, new_integrity = old_dep.integrity, new_dep.integrity
        if old_integrity and not new_integrity:
            integrity_changes.append(f"{name} (integrity removed)")
        elif old_integrity and new_integrity:
            def strength(value):
                algorithm = value.split("-", 1)[0].lower()
                return {"md5": 1, "sha1": 1, "sha256": 2, "sha384": 3,
                        "sha512": 4}.get(algorithm, 0)
            if strength(new_integrity) < strength(old_integrity):
                integrity_changes.append(f"{name} (integrity algorithm downgraded)")

    unresolved = ()
    if status in ("added", "removed"):
        unresolved = tuple(pre_doc.unresolved if pre_doc else ()) + tuple(
            post_doc.unresolved if post_doc else ())
    post_redirects: dict[str, str] = {}
    for kind, value in (post_doc.redirects if post_doc else ()):
        post_redirects[value] = kind
    for kind, value in upstream_redirect_signals(added_text):
        post_redirects.setdefault(value, kind)
    pre_redirects = {value for _kind, value in (pre_doc.redirects if pre_doc else ())}
    pre_redirects |= {value for _kind, value in upstream_redirect_signals(removed_text)}
    redirects = tuple(sorted(
        (kind, value) for value, kind in post_redirects.items()
        if value not in pre_redirects
    ))
    return ManifestDelta(
        path=path, format=fmt, status=status,
        added=tuple(sorted(new - old)), removed=tuple(sorted(old - new)),
        remote_added=tuple(sorted(new_remotes - old_remotes)),
        origin_changes=tuple(origin_changes),
        integrity_changes=tuple(integrity_changes),
        redirects=redirects, unresolved=unresolved,
        old_count=len(old), new_count=len(new),
    )


def _manifest_deltas(doc) -> tuple[ManifestDelta, ...]:
    """One :class:`ManifestDelta` per manifest file the diff touched."""
    from .analysis.manifests import manifest_format, parse_manifest

    out: list[ManifestDelta] = []
    for file in doc.files:
        path = file.old_path if file.status == "removed" else file.path
        if not path or path == "/dev/null":
            path = file.path
        fmt = manifest_format(path)
        if fmt is None:
            continue
        pre_text = "\n".join(
            line.content for line in doc.lines
            if line.file == file.path and line.side in ("remove", "context")
        )
        post_text = "\n".join(
            line.content for line in doc.lines
            if line.file == file.path and line.side in ("add", "context")
        )
        added_text = "\n".join(
            line.content for line in doc.lines
            if line.file == file.path and line.side == "add"
        )
        removed_text = "\n".join(
            line.content for line in doc.lines
            if line.file == file.path and line.side == "remove"
        )
        pre_doc = parse_manifest(path, pre_text) if pre_text else None
        post_doc = parse_manifest(path, post_text) if post_text else None
        out.append(manifest_delta_from_docs(
            path, fmt, file.status, pre_doc, post_doc,
            added_text=added_text, removed_text=removed_text,
        ))
    return tuple(out)


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

    The host and checksum entries render the :class:`ChangeDelta`, so the
    prose and the JSON ``change`` object read the same facts.
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

    # The summary's dependency fact is ``extract_dependency_changes``, a
    # *normalised* view (it drops version constraints and already-known
    # names) - not the ChangeDelta's raw array delta.  Rendering the raw
    # delta here changed the prose on 119 corpus diffs, so the summary keeps
    # its established source and the delta remains a raw view beside it
    # (records the divergence). Both are documented on the report
    # schema; neither is claimed to be the other.
    for field_name, names in sorted(
            (getattr(fact, "dependency_changes", None) or {}).items()):
        if names:
            added = " ".join("+" + n for n in sorted(names))
            entries.append(f"{field_name}: {added}")

    if not entries:
        entries.append("no declared facts changed in the recipe")
    return entries
