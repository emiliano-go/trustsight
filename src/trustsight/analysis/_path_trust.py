"""Trust test for PATH-like assignments built from local build roots.

H025 and X024 both report an environment path that is assigned a value the
reviewer cannot see literally.  A toolchain path assembled from ``$HOME``,
``$srcdir``, ``/usr``, ``/opt`` or a default expansion such as
``${CUDA_PATH:-/opt/cuda}`` is build plumbing, not a hidden directory.  This
module holds the one test both rules use, so they cannot disagree.
"""

from __future__ import annotations

import re
from functools import lru_cache

__all__ = ["is_trusted_path_append", "path_variable_is_trusted"]

#: The assignment that extends a search path with a leading component.
#: The value is read linearly, not with a backtracking span: a resolved line
#: can be thousands of bytes and a lazy span over it turns the suffix search
#: into a quadratic scan on the thread that shares the GIL with the tokenizer
#: client.
_ASSIGN_START_RE = re.compile(
    r"(?<![A-Za-z0-9_.])(?:PATH|LD_LIBRARY_PATH)\s*=\s*", re.IGNORECASE
)
#: A self-append: `:${PATH}`, `:${LD_LIBRARY_PATH}`, or the
#: `${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}` spelling (both carry the same
#: `:$VAR` tail).
_SELF_APPEND_RE = re.compile(
    r":\s*\$\{?(?:PATH|LD_LIBRARY_PATH)\b", re.IGNORECASE
)
#: How much of a resolved value either end is inspected for names/self-append.
_INSPECT = 4096

_PATH_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")

_TRUSTED_ROOTS = frozenset({"HOME", "SRCDIR", "STARTDIR", "PKGDIR", "PWD"})

#: Toolchain roots whose value is the compiler/runtime the build names.
_TOOLCHAIN_ROOTS = frozenset({
    "CUDA_HOME", "CUDA_PATH", "CUDATOOLKIT_ROOT", "CUDNN_HOME",
    "ROCM_PATH", "HIP_PATH", "VULKAN_SDK",
})

_RUNTIME_PREFIX_RE = re.compile(
    r"^[\"']?(?:/tmp|/var/tmp|/dev/shm|/run)(?:/|$)"
)
_TRUSTED_VALUE_RE = re.compile(
    r"^\s*[\"']?(?:~|"
    r"\$\{?(?:HOME|srcdir|startdir|pkgdir|PWD)\}?|"
    r"/(?:usr|opt)(?:/|$))",
    re.IGNORECASE,
)
#: A default expansion whose fallback is a trusted path:
#: `${CUDA_PATH:-/opt/cuda}` or `${HOME:-~}`.
_TRUSTED_DEFAULT_RE = re.compile(
    r":[-=+]\s*[\"']?(?:~|"
    r"\$\{?(?:HOME|srcdir|startdir|pkgdir|PWD)\}?|"
    r"/(?:usr|opt)(?:/|$))",
    re.IGNORECASE,
)

#: Bounds that keep a hostile line from multiplying the work: a value names
#: a handful of variables, and indirection is followed a few levels only.
_MAX_NAMES = 12
_MAX_DEPTH = 4


@lru_cache(maxsize=256)
def _assign_re(name: str) -> re.Pattern:
    return re.compile(
        rf"^\s*(?:local\s+|export\s+|declare\s+-\w+\s+)?"
        rf"{re.escape(name)}\s*=\s*(.+)$"
    )


def _assignment_value(lines: list[str], index: int, name: str) -> str | None:
    """The value assigned to *name* in the bounded window above *index*."""
    assign = _assign_re(name)
    for previous in range(index - 1, max(-1, index - 50), -1):
        text = lines[previous]
        text = text[1:] if text[:1] in "+-" else text
        match = assign.match(text)
        if match:
            return match.group(1).strip().strip("\"'")
    return None


def _value_is_trusted(
    value: str,
    lines: list[str] | None,
    index: int,
    seen: frozenset[str] = frozenset(),
) -> bool:
    """True when *value* names a local toolchain/build path, not hidden code."""
    if not value or "$(" in value or "`" in value:
        return False
    if _TRUSTED_VALUE_RE.search(value) or _TRUSTED_DEFAULT_RE.search(value):
        return True
    names = [
        name for name in _PATH_VAR_RE.findall(value)
        if name.upper() not in ("PATH", "LD_LIBRARY_PATH")
    ][:_MAX_NAMES]
    if not names or len(seen) >= _MAX_DEPTH:
        return False
    for name in names:
        if name.upper() in _TRUSTED_ROOTS or name.upper() in _TOOLCHAIN_ROOTS:
            continue
        if lines is None or name in seen:
            return False
        assigned = _assignment_value(lines, index, name)
        if assigned is None or not _value_is_trusted(
            assigned, lines, index, seen | {name}
        ):
            return False
    return True


def path_variable_is_trusted(lines: list[str], index: int, name: str) -> bool:
    """Whether *name* was assigned a path under a trusted build root.

    Resolves one level of indirection and default expansions, so
    ``local cuda_root="${CUDAToolkit_ROOT:-${CUDA_PATH:-/opt/cuda}}"`` is
    trusted while a command substitution or an undefined name is not.
    """
    assigned = _assignment_value(lines, index, name)
    if assigned is None:
        return False
    return _value_is_trusted(assigned, lines, index)


def _append_value(body: str) -> str | None:
    """The right-hand side of the first PATH-like assignment in *body*."""
    start = _ASSIGN_START_RE.search(body)
    if start is None:
        return None
    rest = body[start.end():]
    if rest[:1] in ("\"", "'"):
        quote = rest[0]
        end = rest.find(quote, 1)
        return rest[1:end if end >= 0 else len(rest)]
    return rest.split("\n", 1)[0].split(None, 1)[0] if rest.strip() else ""


def is_trusted_path_append(
    body: str, variable: str, lines: list[str], index: int,
) -> bool:
    """True for a PATH/LD_LIBRARY_PATH extension built from trusted paths."""
    value = _append_value(body)
    if value is None:
        return False
    if "$(" in value or "`" in value:
        return False
    if not _SELF_APPEND_RE.search(value[-_INSPECT:]):
        return False
    head = value[:_INSPECT]
    prefix = head.split(":", 1)[0].strip()
    if prefix and not prefix.startswith("$") and _RUNTIME_PREFIX_RE.match(prefix):
        return False
    for name in _PATH_VAR_RE.findall(head)[:_MAX_NAMES]:
        if name.upper() in (variable.upper(), "PATH", "LD_LIBRARY_PATH"):
            continue
        if name.upper() in _TRUSTED_ROOTS or name.upper() in _TOOLCHAIN_ROOTS:
            continue
        if not path_variable_is_trusted(lines, index, name):
            return False
    return True
