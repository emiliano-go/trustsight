"""Extracted from _tokenizer_engine.py: _aliases."""

import re
from ._common import _MAX_LINE_LEN

__all__ = ['_ALIAS_DEF_RE', '_ALIAS_USE_PREFIX', '_MAX_ALIASES', '_MAX_ALIAS_LEN', '_alias_pairs', '_alias_table', '_expand_aliases']

_ALIAS_DEF_RE = re.compile(r"^\s*alias\s+(?!-)(.+)$")

_ALIAS_USE_PREFIX = re.compile(
    r"(^|[;&|(){}]|&&|\|\||\b(?:then|do|else|if|while|until|for|time)\b|!)(\s*)$"
)

_MAX_ALIASES = 64

_MAX_ALIAS_LEN = 512

def _alias_table(additions: list[str]) -> dict[str, str]:
    """``{name: expansion}`` for `alias` definitions among added lines."""
    table: dict[str, str] = {}
    for line in additions:
        match = _ALIAS_DEF_RE.match(line)
        if not match:
            continue
        rest = match.group(1)
        for name, value in _alias_pairs(rest):
            if len(table) >= _MAX_ALIASES:
                return table
            if value and len(value) <= _MAX_ALIAS_LEN:
                table[name] = value
    # An alias may be written in terms of another; bash resolves that at use
    # time.  Two passes covers the realistic depth without a fixpoint loop
    # over attacker-controlled text.
    for _ in range(2):
        for name, value in list(table.items()):
            head = value.split(None, 1)
            if head and head[0] in table and head[0] != name:
                tail = head[1] if len(head) > 1 else ""
                merged = (table[head[0]] + " " + tail).strip()
                if len(merged) <= _MAX_ALIAS_LEN:
                    table[name] = merged
    return table

def _alias_pairs(rest: str):
    """Yield ``(name, value)`` from an `alias` command's arguments."""
    i = 0
    while i < len(rest):
        eq = rest.find("=", i)
        if eq == -1:
            return
        name = rest[i:eq].strip()
        if not name or not re.fullmatch(r"[A-Za-z_][\w.-]*", name):
            return
        j = eq + 1
        if j < len(rest) and rest[j] in "'\"":
            quote = rest[j]
            end = rest.find(quote, j + 1)
            if end == -1:
                return
            yield name, rest[j + 1:end]
            i = end + 1
        else:
            end = rest.find(" ", j)
            if end == -1:
                yield name, rest[j:]
                return
            yield name, rest[j:end]
            i = end
        while i < len(rest) and rest[i] == " ":
            i += 1

def _expand_aliases(
    line: str, table: dict[str, str], limit: int = _MAX_LINE_LEN
) -> str:
    """Replace command-position alias names in *line* with their expansion.

    Alias values are small by construction (``_MAX_ALIAS_LEN``), but a line
    can invoke one many times: a 64 KiB line of ``; z`` with ``z`` expanding
    to 200 characters used to produce a 200 KiB result, and the size check
    only ran after the whole pass.  A6's line bound is enforced *before*
    each replacement instead, and an expansion that would cross it is
    refused whole - the original line is returned - rather than truncated
    or partially applied.  A truncated line would look fully resolved with
    its tail quietly removed, which is the failure the bound exists to
    prevent.
    """
    if not table:
        return line
    out = line
    for _ in range(3):
        changed = False
        for name, value in table.items():
            start = 0
            while True:
                idx = out.find(name, start)
                if idx == -1:
                    break
                after = idx + len(name)
                boundary_ok = (
                    (after >= len(out) or not (out[after].isalnum() or out[after] in "_.-"))
                    and _ALIAS_USE_PREFIX.search(out[:idx]) is not None
                )
                if boundary_ok and value.split(None, 1)[:1] != [name]:
                    if len(out) - len(name) + len(value) > limit:
                        return line
                    out = out[:idx] + value + out[after:]
                    changed = True
                    start = idx + len(value)
                else:
                    start = after
        if not changed or len(out) > limit:
            break
    return out
