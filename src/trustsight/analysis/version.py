"""- Class B version rules, and the version comparison.

H063 fires on an ``epoch=`` that is newly present in a diff.

The rest of this module answers a question the CLI used to answer wrongly:
*is the AUR ahead of what is installed?*  Two objects were being compared
that are not comparable.  ``pacman -Q`` reports a full version
(``[epoch:]pkgver-pkgrel``) of what was **built locally**; the AUR side is
the bare ``pkgver`` **as written in the PKGBUILD**.  For a VCS package that
bare value is not even the version that will be built - ``pkgver()`` computes
it at build time from whatever the upstream repository holds - so a local
rebuild routinely carries a *newer* commit than the AUR text names, and the
old comparison rendered that as ``1:1.93.1.r7964.8646e821-1 ->
1.93.1.r7961.93d62158``: an update arrow pointing backwards.

The contract here is the same one the rest of TrustSight uses for anything
it cannot resolve: say so.  A VCS package's comparison is ``inconclusive``,
never a silent arrow, and a non-VCS package whose AUR pkgver is not ahead
reports ``no AUR change`` rather than a change.
"""

import re

from ..diffdoc import parse_diff_lines
from ..expansion import resolve_text, text_variable_table, variable_table
from ..tokenizer import resolve_added_lines
from ..tokenizer import split_lines

# ---------------------------------------------------------------------------
# Full-version parsing
# ---------------------------------------------------------------------------

# makepkg allows alphanumerics, ``.``, ``_``, ``+`` and ``~`` in a pkgver.
# Anything else - a ``$``, a brace, a quote - means the value was never
# resolved, and an unresolved value must not be compared as if it were a
# version.
_FULL_VERSION_RE = re.compile(
    r"^(?:(?P<epoch>\d+):)?(?P<pkgver>[A-Za-z0-9._+~]+)"
    r"(?:-(?P<pkgrel>[A-Za-z0-9._+~]+))?$"
)

# ``-git``/``-hg``/... and the friends makepkg treats the same way.
_VCS_SUFFIX_RE = re.compile(r"-(?:git|hg|svn|bzr|cvs|darcs|fossil)$", re.IGNORECASE)
_PKGVER_FUNCTION_RE = re.compile(r"^\s*pkgver\s*\(\s*\)\s*\{", re.MULTILINE)
# ``name::git+https://...`` is the common form, so the boundary cannot be a
# quote or whitespace - it only has to not be part of a longer word.
_VCS_SOURCE_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])(?:git|hg|svn|bzr|cvs|darcs|fossil)\+[a-z]+://",
    re.IGNORECASE,
)


class Version:
    """A parsed ``[epoch:]pkgver[-pkgrel]``.

    ``full`` records whether a pkgrel was present: comparing a full version
    with a bare pkgver is the bug this class exists to prevent, so the two
    are distinguishable rather than both being "a version string".
    """

    __slots__ = ("epoch", "pkgver", "pkgrel", "raw")

    def __init__(self, epoch: int, pkgver: str, pkgrel: str | None, raw: str):
        self.epoch = epoch
        self.pkgver = pkgver
        self.pkgrel = pkgrel
        self.raw = raw

    @property
    def full(self) -> bool:
        return self.pkgrel is not None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Version({self.raw!r})"


def parse_version(text: str | None) -> Version | None:
    """Parse ``[epoch:]pkgver[-pkgrel]``, or None when it is not a version."""
    if not text:
        return None
    match = _FULL_VERSION_RE.match(text.strip())
    if not match:
        return None
    epoch = int(match.group("epoch")) if match.group("epoch") else 0
    return Version(epoch, match.group("pkgver"), match.group("pkgrel"), text.strip())


# The three scalars that make up a pacman version, read off the PKGBUILD
# rather than off ``pkgver=`` alone.  ``epoch=``/``pkgrel=`` must be literal
# and end the line.  ``pkgver=`` may be a reference to a variable the file
# assigns (``pkgver=${_pkgver//-/_}``); that is resolved.  A variable the
# file never assigns names a value this tool cannot know, and a version it
# cannot know must not be assembled into one it presents.
_PKGVER_ASSIGN_RE = re.compile(
    r"^\s*pkgver\s*=\s*[\"']?([A-Za-z0-9._+~]+)[\"']?\s*(?:#.*)?$", re.MULTILINE
)
_PKGREL_ASSIGN_RE = re.compile(
    r"^\s*pkgrel\s*=\s*[\"']?([A-Za-z0-9._+~]+)[\"']?\s*(?:#.*)?$", re.MULTILINE
)


def full_version_from_pkgbuild(text: str) -> str:
    """Assemble ``[epoch:]pkgver[-pkgrel]`` from a PKGBUILD's own fields.

    Reading ``pkgver=`` alone and calling the result "the AUR version" is
    what produced the reported line

        1:1.93.1.r7967.caea422f-2 installed / AUR pkgver 1.93.1.r7966.7ccbff5e

    for a package whose PKGBUILD declares ``epoch=1`` and ``pkgrel=2``.  The
    two sides were not the same kind of object, so the maintainer read the
    missing ``1:`` as the epoch being lost - which it was.

    It is not only display.  :func:`compare_installed_to_aur` compares
    epochs first and parses an absent one as 0, so an installed ``1:2.0-1``
    against a declared ``epoch=1 pkgver=2.1`` used to come out as
    *installed ahead*: a real update, reported as a backwards move.

    Returns ``""`` when ``pkgver`` is missing or is a reference the file
    never assigns, which leaves the caller's existing fallbacks in charge
    rather than inventing a version.  ``epoch=0`` is omitted, as pacman
    itself renders it.
    """
    if not text:
        return ""
    pkgver = _PKGVER_ASSIGN_RE.search(text)
    if pkgver:
        pkgver_value = pkgver.group(1)
    else:
        # ``pkgver=${_pkgver//-/_}``: the literal regex refuses a value with
        # ``$``/``{``, but the recipe assigns the variable it names, so the
        # value is knowable without executing anything.  Returning ``""``
        # here made a variable-driven bump read as "no version declared",
        # which fired C001 instead of C002.
        raw = re.search(r"^\s*pkgver\s*=\s*(.+?)\s*(?:#.*)?$", text, re.MULTILINE)
        if not raw:
            return ""
        resolved = resolve_text(
            _strip_value(raw.group(1)), text_variable_table(text)
        )
        match = _FULL_VERSION_RE.match(resolved)
        if not match:
            return ""
        pkgver_value = match.group("pkgver")
    epoch = _EPOCH_ASSIGN_RE.search(text)
    pkgrel = _PKGREL_ASSIGN_RE.search(text)
    prefix = f"{epoch.group(1)}:" if epoch and epoch.group(1) != "0" else ""
    suffix = f"-{pkgrel.group(1)}" if pkgrel else ""
    return f"{prefix}{pkgver_value}{suffix}"


def vercmp(a: str, b: str) -> int:
    """Compare two version strings the way pacman does (-1 / 0 / 1)."""
    from ..discovery import _vercmp

    return _vercmp(a, b)


def has_vcs_source(pkgbuild_text: str) -> bool:
    """True when a ``source=`` entry uses a VCS transport (``git+https``...)."""
    return bool(pkgbuild_text and _VCS_SOURCE_RE.search(pkgbuild_text))


def is_vcs_package(pkg_name: str = "", pkgbuild_text: str = "") -> bool:
    """True when the built pkgver is *computed* rather than declared.

    The property that makes a comparison impossible is not "uses git" - it
    is that the version only exists after a build, which is exactly what a
    ``pkgver()`` function means.  A commit-pinned ``git+https`` source with a
    plain ``pkgver=0.7`` declares its version like any other package and
    compares fine; treating it as incomparable would replace a wrong arrow
    with a wrong shrug.

    The name suffix and the VCS source are only consulted when the PKGBUILD
    is not available: without the file, ``-git`` is the best evidence there
    is, and an inconclusive answer beats a fabricated one.
    """
    if pkgbuild_text:
        return bool(_PKGVER_FUNCTION_RE.search(pkgbuild_text))
    return bool(pkg_name and _VCS_SUFFIX_RE.search(pkg_name))


# Comparison outcomes.  Anything unresolvable is INCONCLUSIVE, never clean.
COMPARISON_AHEAD = "aur_ahead"
COMPARISON_SAME = "no_aur_change"
COMPARISON_BEHIND = "installed_ahead"
COMPARISON_INCONCLUSIVE = "inconclusive"


def compare_installed_to_aur(
    installed: str | None, aur_pkgver: str | None, is_vcs: bool = False,
) -> str:
    """Classify the installed version against the AUR's declared pkgver.

    Returns one of the ``COMPARISON_*`` constants.  ``inconclusive`` covers
    every case where the two sides are not the same kind of object: a VCS
    package (whose real pkgver only exists after a build), an unparseable
    version, or a missing side.

    When both sides are full versions they are compared as full versions,
    pkgrel included, which is what pacman and every AUR helper do: an AUR
    ``pkgrel`` bump is a rebuild users are meant to take.  That branch was
    unreachable until ``full_version_from_pkgbuild`` started supplying the
    declared ``epoch`` and ``pkgrel``; before it, the AUR side was always a
    bare pkgver.  A bare side still compares by epoch and pkgver alone,
    because a pkgrel that was never declared cannot be a difference.
    """
    if is_vcs:
        return COMPARISON_INCONCLUSIVE
    local = parse_version(installed)
    remote = parse_version(aur_pkgver)
    if local is None or remote is None:
        return COMPARISON_INCONCLUSIVE
    if remote.full and local.full:
        result = vercmp(local.raw, remote.raw)
    else:
        if local.epoch != remote.epoch:
            result = -1 if local.epoch < remote.epoch else 1
        else:
            result = vercmp(local.pkgver, remote.pkgver)
    if result < 0:
        return COMPARISON_AHEAD
    if result > 0:
        return COMPARISON_BEHIND
    return COMPARISON_SAME

# ---------------------------------------------------------------------------
# Did the version move?  (C001/C002 and the verdict prefix)
# ---------------------------------------------------------------------------

# A ``pkgver=`` line anywhere in the diff, on either side or as context.  A
# context line is the common case: the version is usually carried by a
# variable assigned a few lines above, so ``pkgver=${_gtkver}`` itself does
# not appear on a ``+`` or ``-`` line at all.
_PKGVER_LINE_RE = re.compile(r"^([+\- ])\s*pkgver\s*=\s*(.+?)\s*$")


def _strip_value(value: str) -> str:
    return value.strip().strip("'\"")


_SCALAR_LINE_RE = re.compile(
    r"^([+\- ])\s*(pkgver|pkgrel|epoch)\s*=\s*(.+?)\s*$", re.IGNORECASE
)

def _resolved_scalar(doc, scalar: str, table: dict[str, str],
                     prefixes: frozenset[str]) -> str | None:
    """Resolve one version scalar from the diff side named by *prefixes*."""
    for line in doc.lines:
        match = _SCALAR_LINE_RE.match(line.raw)
        if (match and match.group(1) in prefixes
                and match.group(2).lower() == scalar):
            return resolve_text(_strip_value(match.group(3)), table)
    return None


def any_version_scalar_moved(
    diff_text: str, current_text: str | None = None
) -> bool:
    """True when ``pkgver``, ``pkgrel`` or ``epoch`` genuinely changed value.

    H033 asks "did the maintainer declare a new version?", and a ``pkgrel``
    rebuild or an epoch bump is a declared new build just as a ``pkgver``
    move is, so a repinned commit alongside any of them is expected.  The
    check is by *resolved value*, not by token presence: an added no-op
    ``+epoch=0`` (the value was already 0) must not suppress the finding,
    which a lexical token match would allow.

    A variable-driven bump can leave the ``pkgver=`` line outside every hunk
    - the edit is in the variable it references - so when no scalar line
    moved and *current_text* is available the post-diff recipe supplies the
    ``pkgver`` reference to resolve.
    """
    doc = parse_diff_lines(split_lines(diff_text or ""))
    # _variable_table's signature takes the raw lines; the typed document
    # hands them over unchanged (``raw`` is the line as it appeared).
    lines = [line.raw for line in doc.lines]
    old_table = variable_table(lines, frozenset({"-", " "}))
    new_table = variable_table(lines, frozenset({"+", " "}))
    old_prefixes = frozenset({"-", " "})
    new_prefixes = frozenset({"+", " "})

    for scalar in ("pkgver", "pkgrel", "epoch"):
        old_val = _resolved_scalar(doc, scalar, old_table, old_prefixes)
        new_val = _resolved_scalar(doc, scalar, new_table, new_prefixes)
        if old_val is not None and new_val is not None and old_val != new_val:
            return True
    if current_text:
        return pkgver_move_in_diff(diff_text, current_text)[0]
    return False


def pkgver_move_in_diff(
    diff_text: str, current_text: str | None = None
) -> tuple[bool, str | None, str | None]:
    """Return ``(moved, old, new)`` for the diff's ``pkgver``.

    Reading only the literal ``-pkgver=`` / ``+pkgver=`` lines treated
    ``pkgver=${_gtkver}`` as a stable version, so a routine variable-driven
    update fired C001 (checksum changed without a version move, HIGH)
    instead of C002.  The recipe assigns the variable in the same diff, so
    the value is knowable without executing anything.

    *current_text* is the post-diff PKGBUILD, used when the ``pkgver=`` line
    falls outside the hunk; it lets the reference be read even then.
    """
    doc = parse_diff_lines(split_lines(diff_text or ""))
    lines = [line.raw for line in doc.lines]
    old_ref = new_ref = context_ref = None
    for line in doc.lines:
        match = _PKGVER_LINE_RE.match(line.raw)
        if match is None:
            continue
        sign, raw = match.group(1), _strip_value(match.group(2))
        if sign == "-":
            old_ref = raw
        elif sign == "+":
            new_ref = raw
        else:
            context_ref = raw

    if old_ref is None and new_ref is None and context_ref is None:
        if current_text:
            match = re.search(
                r"^\s*pkgver\s*=\s*(.+?)\s*(?:#.*)?$", current_text, re.MULTILINE
            )
            if match:
                old_ref = new_ref = _strip_value(match.group(1))
        if old_ref is None:
            return False, None, None

    if context_ref is not None:
        if old_ref is None:
            old_ref = context_ref
        if new_ref is None:
            new_ref = context_ref

    old_table = variable_table(lines, frozenset({"-", " "}))
    new_table = variable_table(lines, frozenset({"+", " "}))
    resolved_old = resolve_text(old_ref, old_table) if old_ref is not None else None
    resolved_new = resolve_text(new_ref, new_table) if new_ref is not None else None
    moved = (
        resolved_old is not None
        and resolved_new is not None
        and resolved_old != resolved_new
    )
    return moved, resolved_old, resolved_new


# MULTILINE so the same expression serves both readers: ``_epoch_introduced``
# searches one diff line at a time, ``full_version_from_pkgbuild`` searches a
# whole file.
_EPOCH_ASSIGN_RE = re.compile(
    r"^\s*epoch\s*=\s*['\"]?(\d+)['\"]?",
    re.IGNORECASE | re.MULTILINE,
)


def _epoch_introduced(diff_text: str) -> tuple[bool, str | None]:
    """Return ``(introduced, value)``: was ``epoch=`` absent before the diff
    and present after it?

    Mirrors :func:`~trustsight.analysis.base._pkgver_changed_in_diff`: if an
    ``epoch=`` assignment appears on the ``+`` side and none did on the ``-``
    side, the diff introduced the field.  An unchanged ``epoch=`` is not part
    of any hunk and never surfaces here.
    """
    had_epoch = any(
        re.match(r"\s*-\s*epoch\s*=", line.raw)
        for line in parse_diff_lines(split_lines(diff_text)).lines
    )
    if had_epoch:
        return False, None
    for line in resolve_added_lines(diff_text):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        match = _EPOCH_ASSIGN_RE.search(line[1:])
        if match:
            return True, match.group(1)
    return False, None


def _epoch_removed_unchanged(diff_text: str) -> tuple[bool, str | None]:
    """Return ``(removed, value)``: was ``epoch=`` dropped with pkgver/pkgrel
    unchanged by resolved value?

    Low priority: epoch removal is usually legitimate (a rebase onto a
    version that no longer needs the prefix), so this is annotation-tier.
    It matters only because the ordering override silently disappears.
    """
    doc = parse_diff_lines(split_lines(diff_text or ""))
    lines = [line.raw for line in doc.lines]
    removed = [line for line in lines if re.match(r"\s*-\s*epoch\s*=", line)]
    if not removed:
        return False, None
    added_epoch = any(
        _EPOCH_ASSIGN_RE.search(line[1:])
        for line in resolve_added_lines(diff_text)
        if line.startswith("+") and not line.startswith("+++")
    )
    if added_epoch:
        return False, None

    old_table = variable_table(lines, frozenset({"-", " "}))
    new_table = variable_table(lines, frozenset({"+", " "}))

    for scalar in ("pkgver", "pkgrel"):
        old_val = _resolved_scalar(doc, scalar, old_table, frozenset({"-", " "}))
        new_val = _resolved_scalar(doc, scalar, new_table, frozenset({"+", " "}))
        if old_val is not None and new_val is not None and old_val != new_val:
            return False, None

    match = _EPOCH_ASSIGN_RE.search(re.sub(r"^\s*-\s*", "", removed[0]))
    return True, match.group(1) if match else None


def _epoch_findings(diff_text: str, config, add, whole_recipe: bool = False,
                    delta=None) -> None:
    """A diff introduces ``epoch=`` where none existed (H063, MEDIUM).

    Introducing an epoch overrides the version ordering: a nonzero epoch
    makes the package sort above anything that shares its pkgver/pkgrel,
    which is how a package can be pushed ahead of an established one.
    ``epoch=0`` merely initialises the field and is closer to a no-op.

    A whole-recipe analysis has no ``-`` side, so every field is "new" by
    construction and "newly introduced" would be a claim the run cannot
    support: the epoch is merely present.  The finding is kept (the reader
    still wants to know the field is there), but it says what it knows.

    With *delta* the introduction is read from the shared ``ChangeDelta``:
    ``epoch`` absent pre and present post.  The line number still comes from
    the diff so the citation is unchanged.
    """
    # Low priority: epoch dropped while pkgver/pkgrel stood still.
    # Checked before H063's early return: a removal is never an introduction.
    removed, removed_value = _epoch_removed_unchanged(diff_text)
    if removed:
        suffix = f"{removed_value}" if removed_value else "?"
        add("C030", "Epoch Removed With Version Unchanged", "INFO", "version",
            f"epoch={suffix} removed while pkgver/pkgrel are unchanged",
            line=next(
                (
                    i
                    for i, line in enumerate(
                        parse_diff_lines(split_lines(diff_text)).lines, 1)
                    if line.raw.startswith("-")
                    and _EPOCH_ASSIGN_RE.search(line.raw[1:])
                ),
                None,
            ),
            epoch=removed_value or "0")

    if delta is None:
        introduced, value = _epoch_introduced(diff_text)
    else:
        # the shared delta answers "was epoch absent before and
        # present now" from the pre/post projections, the same question the
        # regex above asks of the diff lines.
        introduced = (not (delta.version.old_epoch or "").strip()
                      and bool((delta.version.new_epoch or "").strip()))
        value = (delta.version.new_epoch or "").strip() or None
    if not introduced:
        return
    severity = "MEDIUM" if value and value != "0" else "INFO"
    if whole_recipe:
        reason = f"epoch={value} present" if value else "epoch present"
    else:
        reason = f"epoch={value} newly introduced" if value else "epoch newly introduced"
    add("H063", "Epoch Introduced", severity, "version",
        reason,
        line=next(
            (
                i
                for i, line in enumerate(
                    parse_diff_lines(split_lines(diff_text)).lines, 1)
                if line.raw.startswith("+") and _EPOCH_ASSIGN_RE.search(line.raw[1:])
            ),
            None,
        ),
        epoch=value or "0")
