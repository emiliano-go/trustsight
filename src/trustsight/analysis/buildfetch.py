"""Build steps that resolve dependencies from a package registry.

This is a **coverage** question, not a detection one, and the distinction is
the whole reason the module exists separately from the rules.

``makepkg`` verifies ``source=()`` against ``sha256sums``.  It verifies
nothing about a dependency a build step resolves at build time: when
``prepare()`` runs ``npm install foo``, the bytes that arrive are whatever
the registry serves at that moment, chosen by a service this analysis never
contacts, and no checksum in the recipe covers them.  The code that will
execute on the reviewer's machine is therefore *not in the text being
analysed*.

That is a missing sensor, and the model's rule is that a missing sensor
reaches the panel rather than reading as silence.  So this records the
``unpinned_build_deps`` coverage gap, and [B2] then forbids the run from
reporting UNFLAGGED.

**Why a gap and not a rule.** ``npm install`` inside ``prepare()`` is what
thousands of legitimate AUR packages do; a rule firing on it would blow the
30% benign fire-rate ceiling and bury real findings, which is exactly why
R081 is scoped to install hooks and why a calibration gate keeps it there.
The June 2026 campaign worked *because* its build step looked ordinary. A
gap makes no accusation: it says the analysis could not see what the build
will run, which is true of the attack and equally true of the thousands of
honest packages that share the shape. Scoring it would be a lie; hiding it
would be the quiet skip B2 exists to prevent.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..deps import _strip_comment
from ..tokenizer import split_lines
from ..rules import _classify_enclosing_function, clamp_text, join_line_continuations

#: Functions makepkg runs while building.  ``package()`` is included: it
#: runs too, and a dependency resolved there is no more verifiable than one
#: resolved in ``build()``.
BUILD_FUNCTIONS = ("prepare", "build", "check", "package")

#: A dependency resolution that reaches a registry, in command position.
#:
#: Each fragment is anchored the way ``DEFAULT_PARSE_TIME_FETCH`` is, so a
#: manager named in a string, a comment or an array element does not count -
#: only one actually being invoked.  The list is deliberately about
#: *resolution*, not installation: ``npm ci``, ``bun install`` and
#: ``cargo fetch`` all pull code the recipe does not pin.
_REGISTRY_RESOLVE = [
    # JavaScript: the ecosystem the June 2026 campaign used.
    r"npm\s+(?:install|i|add|ci)\b",
    r"bun\s+(?:install|i|add)\b",
    r"pnpm\s+(?:install|i|add)\b",
    r"yarn\s+(?:install|add)\b",
    r"npx\s+",
    r"bunx\s+",
    # Python.
    r"pip3?\s+install\b",
    r"uv\s+(?:pip\s+install|sync|add)\b",
    r"poetry\s+(?:install|add)\b",
    # Rust, Go, Ruby, PHP, Java, .NET, Haskell, Elixir.
    r"cargo\s+(?:install|fetch|build|update)\b",
    r"go\s+(?:get|install|mod\s+download)\b",
    r"gem\s+install\b",
    r"bundle\s+install\b",
    r"composer\s+(?:install|require|update)\b",
    r"mvn\s+(?:install|package|dependency:)",
    r"gradle\w*\s+",
    r"dotnet\s+(?:restore|add\s+package)\b",
    r"cabal\s+(?:install|build|update)\b",
    r"stack\s+(?:install|build)\b",
    r"mix\s+(?:deps\.get|deps\.compile)\b",
]

_COMMAND_POSITION = r"(?:\A\s*|[;&|(]\s*|\$\(\s*|&&\s*|\|\|\s*)"

_REGISTRY_RESOLVE_RE = re.compile(
    "|".join(f"{_COMMAND_POSITION}{frag}" for frag in _REGISTRY_RESOLVE),
    re.IGNORECASE,
)

# ``--offline`` / ``--frozen-lockfile`` and friends do not make the fetch
# verifiable by *this* recipe, but they do mean the build is not free to
# resolve whatever it likes, so they are worth not crying wolf over when the
# recipe also vendors the dependencies. Kept narrow on purpose: a flag is a
# claim the recipe makes, and A-series reasoning says a claim an attacker can
# add for free must not silence a signal. So this only suppresses the gap
# when the manager is explicitly offline, which cannot reach a registry at
# all.
_OFFLINE_RE = re.compile(
    r"--offline\b|--no-network\b|--frozen-lockfile\s+--offline\b", re.IGNORECASE
)




#: Diffs retained by the resolution cache.  Three separate callers ask the
#: same question about the same diff - the coverage gap, the IOC surface and
#: the R143 composition - and each pass re-joins every line and re-classifies
#: every function. Bounded rather than unbounded for the same reason the
#: comment cache is: the keys are attacker-controlled text.
_RESOLUTION_CACHE = 4


@lru_cache(maxsize=_RESOLUTION_CACHE)
def _registry_resolutions_cached(diff_text: str) -> tuple[tuple[str, str], ...]:
    return tuple(_registry_resolutions_uncached(diff_text))


def registry_resolutions(diff_text: str) -> list[tuple[str, str]]:
    """``(function, command)`` for each build-time registry resolution added.

    A thin cached wrapper: see :func:`_registry_resolutions_uncached` for
    what it computes.
    """
    return list(_registry_resolutions_cached(diff_text))


def _registry_resolutions_uncached(diff_text: str) -> list[tuple[str, str]]:
    """``(function, command)`` for each build-time registry resolution added.

    Only *added* lines count: a resolution that was already in the recipe is
    not something this diff introduced, and the gap describes what this
    analysis of this change could not see. A package that has always fetched
    from npm still gets the gap on the run that first sees the recipe,
    because ``first_seen`` analyses read the whole file as added.
    """
    lines = join_line_continuations(split_lines(clamp_text(diff_text)))
    enclosing = _classify_enclosing_function(lines)
    found: list[tuple[str, str]] = []
    for i, line in enumerate(lines):
        if not line.startswith("+"):
            continue
        function = enclosing.get(i)
        if function not in BUILD_FUNCTIONS:
            continue
        body = _strip_comment(line[1:])
        if not body.strip():
            continue
        if _OFFLINE_RE.search(body):
            continue
        match = _REGISTRY_RESOLVE_RE.search(body)
        if match:
            found.append((function, body.strip()[:200]))
    return found


def has_unpinned_build_deps(diff_text: str) -> bool:
    """True when this change adds a build step that resolves from a registry."""
    return bool(registry_resolutions(diff_text))


# Subcommand words that precede the package list, so they are not mistaken
# for a package name themselves.
_SUBCOMMANDS = frozenset({
    "install", "i", "add", "ci", "require", "get", "restore", "sync",
    "fetch", "update", "build", "package", "download", "mod",
    "deps.get", "deps.compile", "pip",
})

# A registry package name: npm scoped names, extras, and version specifiers
# all reduce to the name the indicator lists.
_NAME_RE = re.compile(r"^(@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*")


def registry_install_names(diff_text: str) -> list[tuple[str, str, str]]:
    """``(function, command, package_name)`` for names a build step installs.

    An IOC ``package`` indicator is matched against the AUR package name,
    ``pkgbase`` and the dependency arrays.  The June 2026 campaign named its
    payload in neither: ``atomic-lockfile`` appeared only as an argument to
    ``npm install`` inside ``prepare()``, so an indicator list naming it
    would have matched nothing.  This is the surface that closes that.

    Version specifiers, extras and scopes are reduced to the bare name
    (``foo@1.2.3`` and ``foo[extra]`` both yield ``foo``), because that is
    what a curator lists. Flags and shell operators are skipped, and a
    ``$`` anywhere in a token means the name is not statically known, so it
    is not reported rather than reported wrongly.
    """
    found: list[tuple[str, str, str]] = []
    for function, command in registry_resolutions(diff_text):
        # Only the first shell command on the line owns the argument list.
        head = re.split(r"[;&|]", command)[0]
        tokens = head.split()
        seen_subcommand = False
        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            if "$" in token or "`" in token:
                continue
            low = token.lower()
            if not seen_subcommand:
                if low in _SUBCOMMANDS:
                    seen_subcommand = True
                continue
            if low in _SUBCOMMANDS:
                continue
            # A path or URL argument is not a registry name.
            if token.startswith((".", "/", "~")) or "://" in token:
                continue
            match = _NAME_RE.match(token)
            if not match:
                continue
            name = match.group(0)
            if name.lower() in _SUBCOMMANDS:
                continue
            found.append((function, command, name))
    return found
