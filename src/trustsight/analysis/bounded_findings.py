"""Bound how much one rule may say about a single package.

The manifest rules read a whole source tree, and a tree can carry hundreds of
manifests.  A version bump used to rename every one of them, so one analysis
recorded 128 ``U001`` rows for a single package update: the report, the signed
scan document and the database all carried the flood.

Two properties keep that bounded without losing evidence:

* an exact repeat (same rule, file and evidence) is the same fact twice and is
  dropped;
* past a listing cap the rest collapses into one counted finding, so the rule
  still states how many it saw.

The summary carries ``weight_override=0``: the rule already scored for the
rows it listed, and a report of the remainder must not score again.
"""

from __future__ import annotations

#: Distinct findings one rule may list for a single package.
MAX_LISTED_PER_RULE = 25


def bounded_add(add):
    """Wrap a finding *add* callable; return ``(emit, flush)``.

    ``emit`` has the same signature as ``add`` plus a de-duplication key, and
    ``flush`` must be called once at the end to emit the overflow summary.
    """
    emitted: set[tuple[str, str, str]] = set()
    counts: dict[str, int] = {}
    overflow: dict[str, list] = {}

    def emit(rule_id, name, severity, category, match, **extra):
        key = (rule_id, str(extra.get("file") or ""), match)
        if key in emitted:
            return
        emitted.add(key)
        counts[rule_id] = counts.get(rule_id, 0) + 1
        if counts[rule_id] <= MAX_LISTED_PER_RULE:
            add(rule_id, name, severity, category, match, **extra)
            return
        entry = overflow.setdefault(rule_id, [name, severity, category, 0])
        entry[3] += 1

    def flush():
        for rule_id, (name, severity, category, hidden) in overflow.items():
            add(rule_id, name, severity, category,
                f"{hidden} further {name.lower()} finding(s) not listed",
                file="", suppressed=hidden, weight_override=0)

    return emit, flush
