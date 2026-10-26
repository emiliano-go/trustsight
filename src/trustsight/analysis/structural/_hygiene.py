"""Extracted from structural.py: _hygiene."""

import re
from ...line_lex import strip_comment
from ...diffdoc import parse_diff_lines
from ...tokenizer import split_lines

__all__ = ['_ANSI_ESCAPE_RE', '_BUILD_CACHE_RE', '_CACHE_ENV_RE', '_DISGUISABLE_COMMANDS', '_EXECUTABLE_MODE', '_SPLICE_RE', '_added_raw_lines', '_ansi_decode', '_build_hygiene_findings', '_desplice', '_splicing_findings', 'capability_in_diff', 'diff_structure_findings']

_SPLICE_RE = re.compile(
    r"(?:^|[;&|(\s])("
    r"[A-Za-z_][\w.+-]*(?:\"[A-Za-z0-9_]\"|'[A-Za-z0-9_]'|\"\"|'')+[\w.+-]*"
    r"|[A-Za-z_][\w.+-]*\$'(?:\\x[0-9A-Fa-f]{2}|\\[0-7]{1,3})+'[\w.+-]*"
    r"|\w*\$\{[^}\n]*\bIFS\b[^}\n]*\}\w*"
    r")"
)

_BUILD_CACHE_RE = re.compile(
    r"(?:^|[;&|(\s])(?:go\s+(?:build|get|install|test)|cargo\s+(?:build|fetch|test)"
    r"|npm\s+(?:install|ci)|yarn\s+install|pnpm\s+install|bun\s+install)\b"
)

_CACHE_ENV_RE = re.compile(
    r"\b(?:GOFLAGS|GOMODCACHE|GOPATH|CARGO_HOME|npm_config_cache"
    r"|YARN_CACHE_FOLDER|PNPM_HOME)\s*="
)

_DISGUISABLE_COMMANDS = frozenset({
    "sudo", "su", "doas", "curl", "wget", "aria2c", "sh", "bash", "zsh",
    "dash", "fish", "python", "python3", "perl", "ruby", "node", "php",
    "base64", "xxd", "eval", "exec", "source", "nc", "ncat", "netcat",
    "socat", "ssh", "scp", "git", "npm", "npx", "bun", "deno", "cargo",
    "pip", "pip3", "dd", "rm", "chmod", "chown", "install", "systemctl",
    "busybox", "ld", "gcc", "make", "tar",
})

_ANSI_ESCAPE_RE = re.compile(r"\$'((?:\\.|[^'\\])*)'")

def _ansi_decode(body: str) -> str:
    out, i = [], 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "x" and i + 3 < len(body) + 1:
                try:
                    out.append(chr(int(body[i + 2:i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nxt in "01234567":
                out.append(chr(int(body[i + 1:i + 4], 8) & 0xFF))
                i += 4
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(body[i])
        i += 1
    return "".join(out)

def _desplice(text: str) -> str:
    """The bare word a spliced token resolves to, lowercased."""
    text = re.sub(r"\$\{[^}\n]*\bIFS\b[^}\n]*\}", "", text)
    text = _ANSI_ESCAPE_RE.sub(lambda m: _ansi_decode(m.group(1)), text)
    return text.replace('"', "").replace("'", "").lower()

def _added_raw_lines(diff_text) -> list[str]:

    return [line.raw for line in
            parse_diff_lines(split_lines(diff_text)).added_lines()]

def _splicing_findings(diff_text, add) -> None:
    """X032: a command name built from spliced quotes or ANSI-C escapes."""
    seen: set[str] = set()
    for line in _added_raw_lines(diff_text):
        match = _SPLICE_RE.search(line)
        if not match:
            continue
        shape = match.group(1)[:40]
        # Only fire when the disguised word resolves to a command worth
        # disguising: an ordinary quoted word (`scan.""` in a docstring) is
        # not the signal this rule exists for.
        if _desplice(shape) not in _DISGUISABLE_COMMANDS:
            continue
        if shape in seen:
            continue
        seen.add(shape)
        add("X032", "Command Name Assembled By Splicing", "HIGH", "evasion",
            f"a command name is built from spliced quotes/escapes: {shape}",
            line=None, shape=shape)

def _build_hygiene_findings(diff_text, add, current_text=None) -> None:
    """C028: a build tool caches outside the build trees (INFO, hygiene)."""
    lines = _added_raw_lines(diff_text)
    if not any(_BUILD_CACHE_RE.search(line) for line in lines):
        return
    haystack = current_text or diff_text
    if _CACHE_ENV_RE.search(haystack):
        return  # the cache was redirected; not a finding
    add("C028", "Build Cache Outside The Build Trees", "INFO", "staging",
        "a build tool caches outside $srcdir without an overridden cache "
        "directory",
        line=None)

_EXECUTABLE_MODE = "100755"

def diff_structure_findings(doc, add) -> None:
    """C-MODE / C-RENAME / C-EMPTY over typed ``DiffFile`` metadata.

    Three L1 projections of the parse, with no new walker: an added file
    with the executable bit, any declared rename, and an added file with no
    hunks (a marker or placeholder drop).  A finding carries the file it
    concerns; none of these three has a single line to attribute.
    """
    for file in doc.files:
        if file.status == "added" and file.new_mode == _EXECUTABLE_MODE:
            add("C018", "Executable File Committed", "MEDIUM", "integrity",
                f"{file.path} is added with the executable bit set",
                file=file.path)
        if file.renamed:
            add("C019", "File Renamed", "INFO", "integrity",
                f"{file.rename_from or '?'} renamed to "
                f"{file.rename_to or file.path}",
                file=file.path,
                old_path=file.rename_from, new_path=file.rename_to or file.path)
        if file.status == "added" and not file.hunks:
            add("C026", "Empty File Added", "INFO", "integrity",
                f"{file.path} is added with no content",
                file=file.path)

def capability_in_diff(diff_text: str, current_text: str | None = None) -> str | None:
    """A new fetch or non-source execution added in a critical function.

    F8's predicate: a version bump that also starts downloading or running
    something is not the benign checksum refresh C002 describes.  Returns a
    short description, or ``None`` when the diff adds no such capability.
    """
    import os

    from ..delivery import (
        _BUILD_FUNCTIONS,
        _H072_BENIGN_EXEC,
        _collect_executions,
        _declared_source_basenames,
        _FETCH_CLIENT_RE,
        _recipe_lines,
        resolve_added_lines,
    )
    from ...rules import ScopeResolver

    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text, current_text)
    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None:
            continue
        body = strip_comment(line[1:])
        client = _FETCH_CLIENT_RE.search(body)
        if client:
            return f"a network fetch ({client.group(0)[:40]})"
        for path in _collect_executions(body):
            # A standard system path is not a new capability: the system
            # binary is neither fetched by this diff nor part of the
            # package.  `electron44`'s launcher was read as a C001 signal.
            if path.startswith(("/usr/", "/bin/", "/sbin/", "/opt/")):
                continue
            # A command substitution's inner text is not a path.  The
            # `node -p "try { require('./package.json')… } catch …"` version
            # probe produced a "path" made of JavaScript, which C001 then
            # read as a new execution on an ordinary version bump.
            if any(ch in path for ch in " \t{}()?[]'\""):
                continue
            base = os.path.basename(path)
            # Only a *script-like* execution is a capability: `python -m
            # unittest` in a newly added check() is ordinary test
            # infrastructure, while `bash stage.sh` / `escript f.erl` is a
            # file being run.  A module name has no dot and no path.
            if "." not in base and "/" not in path:
                continue
            if base and base not in _H072_BENIGN_EXEC \
                    and base not in source_basenames:
                return f"an execution of {path}"
    return None
