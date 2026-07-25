"""Dependency-array extraction for the D-series rules.

``rules.py`` strips ``depends``/``makedepends``/``optdepends``/``checkdepends``
lines before any pattern runs, because dependency churn is routine and matching
inside it produces false positives.  That filter is why the dependency graph is
invisible to the rule engine, and why this module reads the diff directly
instead of going through :func:`~trustsight.rules.apply_rules`.
"""

import re

from .tokenizer import resolve_added_lines

DEP_FIELDS = (
    "depends", "makedepends", "optdepends", "checkdepends",
    # Not dependencies, but parsed by the same machinery: `provides` and
    # `replaces` declare which packages this one satisfies or supersedes,
    # which is how a package inserts itself in front of a system package.
    "provides", "replaces",
)

# `name>=1.2`, `name<3`, `name=1:2.3-4`, and the `name: why you want it`
# form that only optdepends uses.
_CONSTRAINT_RE = re.compile(r"[<>=].*$")

# Arch-suffixed arrays (depends_x86_64) are where -bin packages put their
# real dependencies, so they count too.
_ARRAY_START_RE = re.compile(
    r"^\s*(?:" + "|".join(DEP_FIELDS) + r")(?:_[a-z0-9_]+)?\s*=\s*\("
)

_QUOTED_RE = re.compile(r"""['"]([^'"]+)['"]""")

# Arch package names are lowercase alphanumerics plus @._+- and must start
# with an alphanumeric.  Validating against this is what keeps shell
# fragments ("if", "[[", "!", "git+https") out of the dependency set when a
# diff hunk leaves an array looking unterminated.
_PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9@._+-]*$")

# Longest dependency array worth believing before assuming the closing
# paren fell outside the hunk.
_MAX_ARRAY_SPAN = 60


def _is_package_name(token: str) -> bool:
    return bool(_PACKAGE_NAME_RE.match(normalize_dependency(token)))


def _strip_comment(body: str) -> str:
    """Drop an unquoted ``#`` comment and everything after it.

    Maintainers annotate dependency arrays freely::

        makedepends=(
          krisp   # required because the bundled one is disabled
        )

    Without this, every word of that note is read as a dependency name.
    A ``#`` inside quotes is data, not a comment.
    """
    quote: str | None = None
    for index, char in enumerate(body):
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#":
            return body[:index]
    return body


def _closes_array(body: str) -> bool:
    """True when an unquoted ``)`` ends the array on this line.

    A ``)`` inside a quoted optdepends description ("foo: (optional) bar")
    does not close anything, and treating it as a terminator would silently
    truncate the array.
    """
    depth = 0
    quote: str | None = None
    for char in body:
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                return True
            depth -= 1
    return False

# Suffixes that mark a variant of the same upstream project rather than a
# different project.
_VARIANT_SUFFIXES = ("-git", "-bin", "-svn", "-hg", "-bzr", "-cvs", "-nightly",
                     "-beta", "-stable", "-lts", "-devel")


def normalize_dependency(raw: str) -> str:
    """Reduce a dependency entry to the bare package name.

    Shared with ``scripts/generate_seed.py`` on purpose: if the seed
    normalised names differently from the runtime lookup, every query would
    miss and every dependency would read as novel.
    """
    name = raw.split(":", 1)[0]
    name = _CONSTRAINT_RE.sub("", name)
    return name.strip().strip("'\"").lower()


def _package_stem(pkgbase: str) -> str:
    """Strip variant suffixes so companion packages can be recognised."""
    stem = pkgbase.lower()
    changed = True
    while changed:
        changed = False
        for suffix in _VARIANT_SUFFIXES:
            if stem.endswith(suffix) and len(stem) > len(suffix):
                stem = stem[: -len(suffix)]
                changed = True
    return stem


# Prefixes shared by thousands of unrelated packages.  Two names both
# starting with "python-" say nothing about a common project, so these must
# not be treated as evidence of relatedness or `python-evil` claiming
# `python-requests` would be suppressed.
_ECOSYSTEM_PREFIXES = frozenset({
    "python", "python2", "python3", "perl", "ruby", "rust", "golang", "go",
    "php", "lua", "nodejs", "node", "js", "haskell", "ocaml", "texlive",
    "r", "vim", "emacs", "ttf", "otf", "font", "fonts", "lib", "lib32",
    "mingw", "aur", "sh",
})


def is_related_package(name: str, pkgbase: str) -> bool:
    """True when *name* belongs to the same project as *pkgbase*.

    ``htop-vim`` providing ``htop`` and ``lmstudio-bin`` providing
    ``lmstudio`` are the ordinary variant pattern, and accounted for every
    ``provides``/``replaces`` hit in the benign corpus.  A package claiming
    an *unrelated* name is the hijack D004 looks for.

    Siblings count as related even when neither name is a prefix of the
    other: ``linux-cachyos`` provides ``linux-headers`` and
    ``mutter-hdr-update`` provides ``mutter-devkit``.  A shared leading
    token is enough, unless that token is a generic ecosystem prefix.
    """
    if not pkgbase or not name:
        return False
    stem = _package_stem(pkgbase)
    other = _package_stem(name)
    if not stem or not other:
        return False
    if stem.startswith(other) or other.startswith(stem):
        return True
    head = stem.split("-")[0]
    return (
        head == other.split("-")[0]
        and head not in _ECOSYSTEM_PREFIXES
        and len(head) >= 3
    )


def is_ignorable(name: str, pkgbase: str = "") -> bool:
    """Names that must never be treated as novel dependencies.

    Each case was measured as a false positive against the benign corpus:

    - ``$_pkgname`` / ``${pkgbase}``: a reference the tokenizer could not
      resolve. It is not a name at all, so it cannot be looked up.
    - ``libwlroots-0.21.so``: a soname, satisfied by whichever package
      provides that ABI rather than by a package of that name.
    - ``jellyfin-desktop-libcef-bin`` alongside ``jellyfin-desktop-git``: a
      companion package from the same split build, which is expected to be
      globally unknown because it belongs to this project alone.
    """
    if not name or "$" in name:
        return True
    if ".so" in name:
        return True
    if pkgbase:
        stem = _package_stem(pkgbase)
        if stem and len(stem) >= 4 and name.startswith(stem):
            return True
    return False


def _side_names(lines: list[str], marker: str) -> dict[str, set[str]]:
    """Dependency names on one side of the diff, keyed by field.

    *marker* is ``+`` or ``-``; context lines belong to both sides.  The two
    sides are reconstructed and then compared, rather than simply reading
    ``+`` lines, so that re-wrapping an array does not read as though every
    dependency were newly added.
    """
    found: dict[str, set[str]] = {f: set() for f in DEP_FIELDS}
    field: str | None = None
    span = 0
    for line in lines:
        if line.startswith(("+++", "---", "@@")):
            continue
        if line[:1] in ("+", "-") and line[:1] != marker:
            continue
        body = line[1:] if line[:1] in ("+", "-") else line

        if field is None:
            match = _ARRAY_START_RE.match(body)
            if match:
                field = match.group(0).split("=")[0].strip().split("_")[0]
                body = body[match.end():]
                span = 0
            else:
                continue
        else:
            # A diff is a fragment: a hunk can open an array whose closing
            # paren is simply not in the patch.  Without a bound, every
            # later line in the file would be read as a dependency.
            span += 1
            if span > _MAX_ARRAY_SPAN:
                field = None
                continue

        body = _strip_comment(body)

        for token in _QUOTED_RE.findall(body):
            if _is_package_name(token):
                found[field].add(token)
        # Unquoted entries are legal in a PKGBUILD array, but the fallback
        # has to be validated rather than trusted: a diff hunk can leave an
        # array looking unterminated, and splitting arbitrary shell on
        # whitespace then yields "if", "[[", and "!" as dependency names.
        for token in re.split(r"[\s()]+", _QUOTED_RE.sub(" ", body)):
            if _is_package_name(token):
                found[field].add(token)

        if _closes_array(body):
            field = None
    return found


def extract_dependency_changes(
    diff_text: str, pkgbase: str = ""
) -> dict[str, set[str]]:
    """Return ``{field: {added names}}`` for a PKGBUILD diff.

    Variables are resolved first, so ``depends=("$_pkgname-x11")`` is
    compared as its expanded value where that value is known.
    """
    # Resolved so that depends=("$_pkgname-x11") is compared by its real
    # name where the value is known; positions are preserved.
    after = _side_names(resolve_added_lines(diff_text), "+")
    before = _side_names(diff_text.splitlines(), "-")

    added: dict[str, set[str]] = {}
    for f in DEP_FIELDS:
        names = {normalize_dependency(n) for n in after[f]} - {
            normalize_dependency(n) for n in before[f]
        }
        # The stem check suppresses companion packages, which is right for
        # dependencies but is the whole signal for provides/replaces: a
        # package claiming to be an *unrelated* one is the hijack.  That
        # comparison is made by the rule, so only the universal filters
        # (unresolved variables, sonames) apply here.
        if f in ("provides", "replaces"):
            added[f] = {n for n in names if not is_ignorable(n)}
        else:
            added[f] = {n for n in names if not is_ignorable(n, pkgbase)}
    return added
