"""Dependency-free safeguards for regexes applied to hostile text."""

from __future__ import annotations

import time
import re

BACKTRACK_REPS = 22
BACKTRACK_BUDGET_S = 0.02

BACKTRACK_PROBES = (
    "a" * BACKTRACK_REPS + "!",
    "a" * BACKTRACK_REPS,
    " " * BACKTRACK_REPS + "!",
    "https://" + "a." * (BACKTRACK_REPS // 2) + "com",
    "curl " + "|" * BACKTRACK_REPS,
    "/" * BACKTRACK_REPS + "!",
)

# Restrict the structural check to the classic ambiguous single-atom forms.
# Broader nested-quantifier heuristics reject safe patterns whose inner and
# outer character classes are disjoint, such as ``(?:-\S+\s+)*``.
_NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:\?:)?(?:[A-Za-z0-9.]|\.\*|\.\+|\\[wds])[*+]\)\s*[*+{]"
)


def has_nested_quantifier(pattern: str) -> bool:
    """Conservatively detect nested quantified groups."""
    return _NESTED_QUANTIFIER_RE.search(pattern) is not None


def backtracking_risk(compiled: re.Pattern) -> float:
    """Return the worst bounded-probe match time in seconds."""
    worst = 0.0
    for probe in BACKTRACK_PROBES:
        start = time.perf_counter()
        try:
            compiled.search(probe)
        except (RecursionError, MemoryError):
            return BACKTRACK_BUDGET_S * 100
        worst = max(worst, time.perf_counter() - start)
    return worst
