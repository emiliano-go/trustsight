"""Extracted from structural.py: _hooks."""

import re
from ..persistence import (
    _HOME_PREFIX_RE,
    _raw_targets,
    _WW_DIR_RE,
)
from ...coverage import note_stage_failure
from ...findings import stamp
from ...line_lex import _printed_heredoc_body_indices, strip_comment, unwrap_shell_cexec
from ...recipedoc import parse_recipe
from ...diffdoc import parse_diff_lines
from ...rules import _blank_quoted, _printer_quote_body_indices, _PRINTER_LINE_RE
from ...tokenizer import split_lines

__all__ = ['_HOOK_INTERPRETER_RE', '_ROOT_HOME_RE', '_RUNTIME_USER_RE', '_XDG_PREFIX_RE', '_hook_names', '_user_writable_target', 'install_script_findings', 'partial_install_files']

_HOOK_INTERPRETER_RE = re.compile(
    r"(?:^|[;&|(])\s*(?:/(?:usr/)?bin/)?"
    r"(?:ba|z|da|k|a|mk|pdk|ya|po)?sh\b(?!\s*[=<])"
    r"|(?:^|[;&|(])\s*(?:/(?:usr/)?bin/)?"
    r"(?:python[23]?|perl|ruby|node|php)\b",
    re.IGNORECASE | re.MULTILINE,
)

_XDG_PREFIX_RE = re.compile(r"^\$?\{?XDG_[A-Z_]+\}?(?:/|$)")

_RUNTIME_USER_RE = re.compile(r"^/run/user/")

_ROOT_HOME_RE = re.compile(r"^/root(?:/|$)")

def _user_writable_target(target: str) -> bool:
    value = target.strip().strip("\"'")
    return bool(
        _HOME_PREFIX_RE.match(value)
        or _WW_DIR_RE.match(value)
        or _XDG_PREFIX_RE.match(value)
        or _RUNTIME_USER_RE.match(value)
        or _ROOT_HOME_RE.match(value)
    )

def _hook_names(recipe) -> list[str]:
    return [
        name for name in recipe.functions
        if name.endswith(("_install", "_upgrade", "_remove"))
    ]

def partial_install_files(diff_text: str) -> list[str]:
    """Install-script files whose diff is not the whole file.

    Added files are complete by construction.  A modified file counts as
    complete only when its first hunk starts at line 1 and no hunk was cut
    (``DiffDoc.cut_hunks``); anything else is a fragment, and the hook
    rules must not read it as a whole script.
    """
    try:
        doc = parse_diff_lines(split_lines(diff_text))
    except Exception:
        note_stage_failure("install-partial-check")
        return []
    cuts = {path for path, *_rest in doc.cut_hunks()}
    partial: list[str] = []
    for file in doc.files:
        if not file.path.endswith(".install") or file.status == "removed":
            continue
        if file.status == "added":
            continue
        if not file.hunks or file.hunks[0].new_start != 1 or file.path in cuts:
            partial.append(file.path)
    return partial

def install_script_findings(doc, dead_hooks: frozenset[str] = frozenset()) -> list[dict]:
    """C016/C017 over complete ``.install`` scripts (re-filed).

    The file's post-state text is read as a ``RecipeDoc``; every hook body
    is a function.  Findings attribute to the ``.install`` file and its own
    line numbers via the recipe's spans.  A partial file is skipped here:
    :func:`partial_install_files` declares it as a coverage gap instead.
    Hooks the recipe does not wire up (``install=`` never names the file)
    are dead: pacman never runs them, so behavior claims inside them stand
    down (C024 names the dead hook itself once).
    """
    cuts = {path for path, *_rest in doc.cut_hunks()}
    out: list[dict] = []
    #: C016 dedupe: the same effective body repeated across hooks of one
    #: file (Debian templates wrap every hook identically) is one finding.
    seen_c016: set[tuple[str, str]] = set()
    for file in doc.files:
        if not file.path.endswith(".install") or file.status == "removed":
            continue
        if file.path in dead_hooks:
            continue
        if (file.status != "added"
                and (not file.hunks or file.hunks[0].new_start != 1
                     or file.path in cuts)):
            continue
        text = "\n".join(
            line.content for line in doc.lines
            if line.file == file.path and line.side in ("add", "context")
        )
        origins = [
            (line.file, line.new_lineno or 0, line.side)
            for line in doc.lines
            if line.file == file.path and line.side in ("add", "context")
        ]
        try:
            recipe = parse_recipe(text, origins=origins)
        except Exception:
            note_stage_failure("install-script-parse")
            continue
        for name in _hook_names(recipe):
            body = recipe.functions.get(name, "")
            if not body:
                continue
            span = recipe.function_spans.get(name)
            body_lines = split_lines(body)
            # Lines inside a printed heredoc (`cat <<MSG`, no redirect, no
            # executor pipe) are output text, not executed shell: an
            # advisory body that *mentions* an interpreter must not fire
            # C016 (mautrix-signal's "upgraded from a <0.5.0 bridge
            # (python)" advisory).
            printed = _printed_heredoc_body_indices(body_lines)
            # A printer's quoted string spans lines the same way the printed
            # heredoc does: audirvana's `echo "` block carries mkdir/redirect
            # *text* into this rule.  Lines inside a string a printer opened
            # are output, not executed shell.
            message_spans = _printer_quote_body_indices(body_lines)
            # A single-line printer holds its text in quotes on the same
            # line: arctis-sound-manager prints a `curl … | bash` one-liner
            # inside `echo "…"`.  Bash's quote removal can also leave the
            # format argument unquoted (`printf %s\n 'text'`), so blank the
            # quoted literals of any printer line before reading it as code.
            scanned = "\n".join(
                "" if i in printed or i in message_spans
                else strip_comment(
                    _blank_quoted(raw_line)
                    if _PRINTER_LINE_RE.match(raw_line) else raw_line)
                for i, raw_line in enumerate(body_lines)
            )
            # A literal shell re-exec (`/bin/sh -c '#!/bin/sh …'`) executes
            # its inner literal, so scan the body it actually runs, not the
            # wrapper token.  A dynamic argument (`sh -c "$x"`) is not
            # unwrapped: the interpreter token stays and fires as before.
            unwrapped = unwrap_shell_cexec(scanned)
            match = _HOOK_INTERPRETER_RE.search(unwrapped)
            if match and (file.path, unwrapped.strip()) not in seen_c016:
                seen_c016.add((file.path, unwrapped.strip()))
                out.append(stamp({
                    "rule_id": "C016",
                    "name": "Interpreter Invocation In Install Hook",
                    "severity": "HIGH", "category": "execution",
                    "match": f"{name}() invokes '{match.group(0).strip()}'; "
                             "a hook runs as root at pacman time",
                    "file": span.file if span else file.path,
                    "line": span.line if span else None,
                    "params": {"hook": name, "interpreter": match.group(0).strip()[:40]},
                }))
            for i, raw_line in enumerate(body_lines):
                if i in printed or i in message_spans:
                    continue
                for target in _raw_targets(strip_comment(raw_line)):
                    if _user_writable_target(target):
                        out.append(stamp({
                            "rule_id": "C017",
                            "name": "Install Hook Writes To A User-Writable Location",
                            "severity": "HIGH", "category": "persistence",
                            "match": f"{name}() writes to {target.strip()}; "
                                     "the hook runs as root",
                            "file": span.file if span else file.path,
                            "line": span.line if span else None,
                            "params": {"hook": name, "path": target.strip()[:80]},
                        }))
                        break
    return out
