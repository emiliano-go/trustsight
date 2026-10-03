"""Operator-authored structural rules over the typed recipe.

The R-series matches diff lines.  A ``[[structural]]`` rule asks the typed
core instead: did an array gain an entry, did a host appear, did a scalar
change, did a source local name move under a kept URL.  The table is
user-only and ships empty; the semantics, the changed-line anchor and the
severity cap are in ``docs/explanation/structural-user-rules.md``.
"""

from urllib.parse import urlparse

from ..buckets import canonical_host
from ..config import STRUCTURAL_MATCHES, load_structural_rules
from ..coverage import note_stage_failure
from ..diffdoc import parse_diff_lines
from ..findings import stamp
from ..recipedoc import Span, array_diff, parse_recipe, recipe_states
from ..rules import _compiled
from ..tokenizer import split_lines

_MAX_MATCH = 100


def apply_structural_rules(
    diff_text: str = "",
    current_text: str | None = None,
    rules: list[dict] | None = None,
    package_name: str = "",
) -> list[dict]:
    """Evaluate the operator's structural rules and return their findings.

    *diff_text* empty means a first-seen package: the complete post-state
    *current_text* is the whole evidence, and the change primitives degrade
    to presence checks.  A diff-derived recipe carries each value's real
    file, line and side, so a finding is anchored to where the value was
    read; without that provenance there is no evidence and no finding.
    """
    if rules is None:
        rules = load_structural_rules()
    if not rules:
        return []

    doc = parse_diff_lines(split_lines(diff_text)) if diff_text else None
    if doc is not None:
        pre, post = recipe_states(doc)
    else:
        pre = None
        post = parse_recipe(current_text, file="PKGBUILD") if current_text else None
    if post is None:
        return []

    findings: list[dict] = []
    for rule in rules:
        if rule.get("enabled") is False:
            continue
        if rule.get("match") not in STRUCTURAL_MATCHES:
            continue
        compiled = _compiled(rule.get("pattern", ""), rule_id=rule.get("id", ""))
        if compiled is None:
            note_stage_failure(f"rule:{rule.get('id', '')}")
            continue
        finding = _evaluate(rule, compiled, pre, post)
        if finding is not None:
            findings.append(finding)
    return findings


def _evaluate(rule, compiled, pre, post) -> dict | None:
    matcher = rule["match"]
    if matcher == "scalar_changed":
        return _scalar_changed(rule, compiled, pre, post)
    if matcher == "renamed":
        return _renamed(rule, compiled, pre, post)
    if matcher == "entry_removed":
        return _entry_removed(rule, compiled, pre, post)
    return _entry_added(rule, compiled, pre, post, matcher)


def _entry_added(rule, compiled, pre, post, matcher):
    name = rule["field"]
    old = pre.arrays.get(name, ()) if pre is not None else ()
    new = post.arrays.get(name, ())
    if pre is None:
        candidates = sorted(new)
    else:
        candidates = sorted(array_diff(old, new).gained)
    require_side = "add" if pre is not None else ""
    for entry in candidates:
        if matcher == "host_added":
            value = _host_of(entry)
            if not value or not compiled.search(value):
                continue
            params = {"entry": entry, "host": value}
        else:
            value = entry
            if not compiled.search(value):
                continue
            params = None
        span = _entry_span(post, name, entry, require_side)
        if span is not None:
            return _finding(rule, value, span, params)
    return None


def _entry_removed(rule, compiled, pre, post):
    if pre is None:
        return None
    name = rule["field"]
    lost = array_diff(pre.arrays.get(name, ()), post.arrays.get(name, ())).lost
    for entry in sorted(lost):
        if not compiled.search(entry):
            continue
        span = _entry_span(pre, name, entry, "remove")
        if span is not None:
            return _finding(rule, entry, span)
    return None


def _scalar_changed(rule, compiled, pre, post):
    key = rule["field"][len("scalars."):]
    new = post.scalars.get(key)
    if new is None:
        return None
    if pre is not None:
        old = pre.scalars.get(key)
        if old is None or old == new:
            return None
    if not compiled.search(new):
        return None
    span = post.scalar_spans.get(key)
    if span is None or (pre is not None and span.side != "add"):
        return None
    return _finding(rule, new, span)


def _renamed(rule, compiled, pre, post):
    if pre is None:
        return None
    from .delivery import _source_urls_by_local_name

    old = {url: name for name, (url, _s) in _source_urls_by_local_name(pre).items()}
    new = {
        url: (name, span)
        for name, (url, span) in _source_urls_by_local_name(post).items()
    }
    for url in sorted(set(old) & set(new)):
        name, span = new[url]
        if old[url] == name or not compiled.search(name):
            continue
        if span is None or span.side != "add":
            continue
        return _finding(rule, name, span,
                        {"old_name": old[url], "new_name": name, "url": url})
    return None


def _entry_span(recipe, field: str, entry: str, side: str) -> Span | None:
    """The span of *entry* in *field*, requiring *side* when it is set.

    Spans and values are built in the same pass, so index i of the span
    tuple belongs to entry i.  An entry with no span on the required side
    is not evidence for a change.
    """
    values = recipe.arrays.get(field, ())
    spans = recipe.array_spans.get(field, ())
    for index, value in enumerate(values):
        if value != entry or index >= len(spans):
            continue
        span = spans[index]
        if side and span.side != side:
            continue
        return span
    return None


def _host_of(entry: str) -> str:
    _name, sep, url = entry.partition("::")
    if not sep:
        url = entry
    parsed = urlparse(url)
    if not parsed.hostname:
        return ""
    return canonical_host(parsed.hostname)


def _finding(rule, value, span: Span, params=None) -> dict:
    finding = {
        "rule_id": rule["id"],
        "name": rule.get("name", rule["id"]),
        "severity": rule.get("severity", "MEDIUM"),
        "category": rule.get("category", "structural"),
        "match": str(value)[:_MAX_MATCH],
        "file": span.file,
        "line": span.line or None,
    }
    if params:
        finding["params"] = params
    if "weight_override" in rule:
        finding["weight_override"] = rule["weight_override"]
    return stamp(finding)
