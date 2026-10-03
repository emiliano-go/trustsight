"""Operator-authored structural rules over the typed recipe.

The R-series matches diff lines.  A ``[[structural]]`` rule asks the typed
core instead: did an array gain an entry, did a host appear, did a scalar
change, did a source local name move under a kept URL.  The table is
user-only and ships empty; the semantics, the changed-line anchor and the
severity cap are in ``docs/explanation/structural-user-rules.md``.
"""

import re
from urllib.parse import urlparse

from ..buckets import canonical_host
from ..config import STRUCTURAL_MATCHES, load_structural_rules
from ..coverage import note_stage_failure
from ..diffdoc import DiffDoc, parse_diff_lines
from ..findings import stamp
from ..recipedoc import array_diff, parse_recipe, recipe_states
from ..rules import _compiled
from ..tokenizer import split_lines

_MAX_MATCH = 100

_SCALAR_ASSIGNMENT = r"^\s*(?:export\s+|local\s+|declare\s+\S+\s+)?{key}\s*\+?="


def apply_structural_rules(
    diff_text: str = "",
    current_text: str | None = None,
    rules: list[dict] | None = None,
    package_name: str = "",
) -> list[dict]:
    """Evaluate the operator's structural rules and return their findings.

    *diff_text* empty means a first-seen package: the complete post-state
    *current_text* is the whole evidence, and the change primitives degrade
    to presence checks.  Findings are anchored to ``file``/``line`` or
    dropped; the changed-line anchor is the only evidence a rule may claim.
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
        post = None
    if current_text:
        post = parse_recipe(current_text)
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
        finding = _evaluate(rule, compiled, pre, post, doc, current_text)
        if finding is not None:
            findings.append(finding)
    return findings


def _evaluate(rule, compiled, pre, post, doc, current_text) -> dict | None:
    matcher = rule["match"]
    if matcher == "scalar_changed":
        return _scalar_changed(rule, compiled, pre, post, doc, current_text)
    if matcher == "renamed":
        return _renamed(rule, compiled, pre, post, doc, current_text)
    if matcher == "entry_removed":
        return _entry_removed(rule, compiled, pre, post, doc)
    return _entry_added(rule, compiled, pre, post, doc, current_text, matcher)


def _entry_added(rule, compiled, pre, post, doc, current_text, matcher):
    name = rule["field"]
    old = pre.arrays.get(name, ()) if pre is not None else ()
    new = post.arrays.get(name, ())
    if pre is None:
        candidates = sorted(new)
    else:
        candidates = sorted(array_diff(old, new).gained)
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
        where = _anchor(doc, current_text, entry, "add")
        if where is not None:
            return _finding(rule, value, where, params)
    return None


def _entry_removed(rule, compiled, pre, post, doc):
    if pre is None:
        return None
    name = rule["field"]
    lost = array_diff(pre.arrays.get(name, ()), post.arrays.get(name, ())).lost
    for entry in sorted(lost):
        if not compiled.search(entry):
            continue
        where = _line_of(doc, entry, "remove")
        if where is not None:
            return _finding(rule, entry, where)
    return None


def _scalar_changed(rule, compiled, pre, post, doc, current_text):
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
    where = _scalar_line(doc, current_text, key)
    if where is None:
        return None
    return _finding(rule, new, where)


def _renamed(rule, compiled, pre, post, doc, current_text):
    if pre is None:
        return None
    from .delivery import _source_urls_by_local_name

    old = {url: name for name, url in _source_urls_by_local_name(pre).items()}
    new = {url: name for name, url in _source_urls_by_local_name(post).items()}
    for url in sorted(set(old) & set(new)):
        name = new[url]
        if old[url] == name or not compiled.search(name):
            continue
        where = _anchor(doc, current_text, url, "add")
        if where is not None:
            return _finding(rule, name, where,
                            {"old_name": old[url], "new_name": name, "url": url})
    return None


def _host_of(entry: str) -> str:
    _name, sep, url = entry.partition("::")
    if not sep:
        url = entry
    parsed = urlparse(url)
    if not parsed.hostname:
        return ""
    return canonical_host(parsed.hostname)


def _anchor(doc: DiffDoc | None, current_text: str | None, needle: str,
            side: str = "add"):
    """The ``(file, line)`` of *needle*, or None when the diff lacks it.

    With a diff, only the given side counts: an entry that is not on the
    changed side is not evidence.  A first-seen package has no diff, so the
    full post-state text supplies the location instead.
    """
    where = _line_of(doc, needle, side)
    if where is not None:
        return where
    if doc is None and current_text and needle:
        for number, line in enumerate(split_lines(current_text), start=1):
            if needle in line:
                return ("PKGBUILD", number)
    return None


def _line_of(doc: DiffDoc | None, needle: str, side: str):
    """The ``(file, line)`` of *needle* on the diff's given side, or None."""
    if doc is None or not needle:
        return None
    lines = doc.added_lines() if side == "add" else doc.removed_lines()
    line_map = doc.line_map()
    for line in lines:
        if needle in line.content:
            return line_map.get(line.index)
    return None


def _scalar_line(doc: DiffDoc | None, current_text: str | None, key: str):
    pattern = re.compile(_SCALAR_ASSIGNMENT.format(key=re.escape(key)))
    if doc is not None:
        line_map = doc.line_map()
        for line in doc.added_lines():
            if pattern.match(line.content):
                where = line_map.get(line.index)
                if where is not None:
                    return where
        return None
    if current_text:
        for number, line in enumerate(split_lines(current_text), start=1):
            if pattern.match(line):
                return ("PKGBUILD", number)
    return None


def _finding(rule, value, where, params=None) -> dict:
    file, line = where
    finding = {
        "rule_id": rule["id"],
        "name": rule.get("name", rule["id"]),
        "severity": rule.get("severity", "MEDIUM"),
        "category": rule.get("category", "structural"),
        "match": str(value)[:_MAX_MATCH],
        "file": file,
        "line": line,
    }
    if params:
        finding["params"] = params
    if "weight_override" in rule:
        finding["weight_override"] = rule["weight_override"]
    return stamp(finding)
