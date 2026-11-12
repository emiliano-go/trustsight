"""Static runtime-surface analysis: H009-H013.

These rules read the surface a package *runs at runtime* - committed systemd
units and other shell/script carriers - and never execute anything.  They were
the reserved ``runtime`` ids; this module gives them a static meaning that is
consistent with the project's "nothing is executed" invariant:

- H009 network client in a service's Exec* line (a unit that phones home)
- H010 write to a sensitive runtime path from a unit's Exec* line
- H011 privilege-escalating binary in a unit's Exec* line
- H012 TracerPid / ptrace / strace detection in a runtime carrier
- H013 strace log truncation or removal (tracing blinded)

They ship anergic (weight 0) until the weekly calibration assigns a weight.
"""

from __future__ import annotations

import re

from ..findings import stamp
from ..tokenizer import split_lines

__all__ = ["runtime_surface_findings"]

_UNIT_SUFFIXES = (".service", ".timer", ".socket")
_SCRIPT_SUFFIXES = (".install", ".sh", ".bash", ".py")
_EXEC_LINE_RE = re.compile(r"^\s*Exec[A-Za-z]*\s*=", re.MULTILINE)
_NETWORK_CLIENT_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet)\b|/dev/tcp/", re.IGNORECASE)
_SENSITIVE_PREFIXES = ("/etc/", "/var/", "/run/", "$HOME", "~/", "/root/")
_ESCALATION_RE = re.compile(r"\b(?:sudo|pkexec|doas|su)\b")
_TRACE_DETECT_RE = re.compile(r"TracerPid|ptrace\s*\(\s*PTRACE_|\bstrace\s+-p\b")

#: Words that open a fresh command, so a ``tee`` or ``rm`` after one is in
#: command position.  Deliberately the small set the runtime carriers use;
#: the shared ``shell_words`` definition is for rule families that mask quotes
#: first, and H010/H013 need the quoted code inside ``sh -c '...'``.
_COMMAND_WRAPPERS = frozenset({
    "sudo", "doas", "run0", "env", "exec", "command", "builtin", "nohup",
    "then", "do", "else", "elif", "if", "while", "until", "!", "{",
})
_SEPARATORS = frozenset({";", "|", "||", "&&", "&", "(", ")"})
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"})
_STRAIGHT_REDIRECTS = frozenset({">", ">>", ">|"})
_TRUNCATING_COMMANDS = frozenset({"rm", "unlink", "shred", "truncate", "srm"})

#: One line is bounded before tokenising: a unit Exec* line is short, and the
#: bound keeps a package-supplied megabyte line from costing the scan.
_MAX_LINE_CHARS = 16_384
_MAX_WORDS = 512


def _is_test(path: str) -> bool:
    lower = path.lower()
    return ("/test" in lower or lower.startswith("test")
            or lower.endswith("_test.py") or "/tests/" in lower)


def _is_unit(path: str) -> bool:
    return path.lower().endswith(_UNIT_SUFFIXES)


def _shell_words(line: str) -> list[str]:
    """Split one line into shell words, keeping operators as their own word.

    Quotes are removed and their contents stay in the word, so the body of
    ``sh -c 'echo x > /etc/f'`` is one word that can be re-scanned as code.
    Operators inside quotes are data, not operators.  This is lexical: it
    resolves nothing and never executes anything.
    """
    tokens: list[str] = []
    buffer: list[str] = []
    quote: str | None = None
    index = 0
    line = line[:_MAX_LINE_CHARS]
    while index < len(line) and len(tokens) < _MAX_WORDS:
        char = line[index]
        if quote is not None:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"' and index + 1 < len(line):
                buffer.append(line[index + 1])
                index += 1
            else:
                buffer.append(char)
            index += 1
            continue
        if char in "'\"":
            quote = char
            index += 1
            continue
        if char == "\\" and index + 1 < len(line):
            buffer.append(line[index + 1])
            index += 2
            continue
        if char in " \t":
            if buffer:
                tokens.append("".join(buffer))
                buffer = []
            index += 1
            continue
        if char in ">|<;":
            if buffer:
                tokens.append("".join(buffer))
                buffer = []
            pair = line[index:index + 2]
            if pair in (">>", ">|"):
                tokens.append(pair)
                index += 2
                continue
            tokens.append(char)
            index += 1
            continue
        buffer.append(char)
        index += 1
    if buffer and len(tokens) < _MAX_WORDS:
        tokens.append("".join(buffer))
    return tokens


def _command_position(words: list[str], index: int) -> bool:
    if index == 0:
        return True
    previous = words[index - 1]
    return previous in _SEPARATORS or previous in _COMMAND_WRAPPERS


def _word_base(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def _sensitive_path(word: str) -> bool:
    word = word.strip("'\"")
    return bool(word) and any(word.startswith(p) for p in _SENSITIVE_PREFIXES)


def _sensitive_write(line: str, depth: int = 0) -> bool:
    """A runtime write to a sensitive path, checked from parsed words.

    A substring test read ``/usr/bin/steep`` as ``tee`` and ``/etc/passwd
    > README`` (printed text) as a write.  Here a redirect target must itself
    be sensitive, and ``tee`` must be the command word.
    """
    words = _shell_words(line)
    for index, word in enumerate(words):
        if word in _STRAIGHT_REDIRECTS and index + 1 < len(words):
            if _sensitive_path(words[index + 1]):
                return True
    for index, word in enumerate(words):
        if _word_base(word) != "tee" or not _command_position(words, index):
            continue
        for argument in words[index + 1:]:
            if argument in _SEPARATORS:
                break
            if not argument.startswith("-") and _sensitive_path(argument):
                return True
    if depth < 1:
        for index, word in enumerate(words):
            if _word_base(word) not in _SHELLS:
                continue
            for flag_index in range(index + 1, len(words)):
                flag = words[flag_index]
                if not flag.startswith("-"):
                    break
                if flag == "-c" or (len(flag) <= 4 and flag.endswith("c")):
                    body = words[flag_index + 1] if flag_index + 1 < len(words) else ""
                    if body and _sensitive_write(body, depth + 1):
                        return True
                    break
    return False


def _looks_like_strace_log(path: str) -> bool:
    return "strace" in _word_base(path).lower()


def _strace_output(words: list[str]) -> str | None:
    """The file ``strace -o``/``--output`` writes, or None."""
    for index, word in enumerate(words):
        if _word_base(word) != "strace":
            continue
        for position in range(index + 1, len(words)):
            argument = words[position]
            if argument in _SEPARATORS:
                break
            if argument == "-o":
                return words[position + 1] if position + 1 < len(words) else None
            if argument.startswith("-o") and len(argument) > 2:
                return argument[2:]
            if argument.startswith("--output="):
                return argument.split("=", 1)[1]
        break
    return None


def _trace_truncate(line: str) -> bool:
    """A strace log (or its output file) truncated or removed.

    Truncating, removing, or ``: >``-clobbering a path that names a strace log
    is the detection.  Capturing strace's stdout with a plain ``>`` is not:
    that is the normal way to keep the trace, and it was the false positive.
    """
    words = _shell_words(line)
    output = _strace_output(words)
    for index, word in enumerate(words):
        base = _word_base(word)
        if base in _TRUNCATING_COMMANDS and _command_position(words, index):
            for argument in words[index + 1:]:
                if argument in _SEPARATORS:
                    break
                if argument.startswith("-"):
                    continue
                if _looks_like_strace_log(argument) or argument == output:
                    return True
        if word == ":" and index + 2 < len(words) \
                and words[index + 1] in _STRAIGHT_REDIRECTS:
            if _looks_like_strace_log(words[index + 2]):
                return True
    if output is not None:
        for index, word in enumerate(words):
            if word in _STRAIGHT_REDIRECTS and index + 1 < len(words) \
                    and words[index + 1] == output:
                return True
    return False


def _finding(rule_id: str, name: str, path: str, line: int, match: str) -> dict:
    return stamp({
        "rule_id": rule_id,
        "name": name,
        "severity": "INFO",
        "category": "runtime",
        "match": match,
        "file": path,
        "line": line,
    })


def runtime_surface_findings(files) -> list[dict]:
    """H009-H013 over committed runtime carriers.

    *files* is ``[(path, head_bytes)]``.  Units (``.service``/``.timer``/
    ``.socket``) are read for Exec* surface; install hooks and shell/python
    scripts are read for tracing evasion.  Test fixtures are skipped.
    """
    findings: list[dict] = []
    for path, head in files:
        if _is_test(path):
            continue
        is_unit = _is_unit(path)
        is_script = path.lower().endswith(_SCRIPT_SUFFIXES)
        if not (is_unit or is_script):
            continue
        text = head.decode("utf-8", errors="replace") if isinstance(
            head, (bytes, bytearray)) else str(head)
        if not text:
            continue
        for number, line in enumerate(split_lines(text)):
            if is_unit and _EXEC_LINE_RE.match(line):
                if _NETWORK_CLIENT_RE.search(line):
                    findings.append(_finding(
                        "H009", "Network connection attempt", path,
                        number, line.strip()[:160]))
                if _sensitive_write(line):
                    findings.append(_finding(
                        "H010", "Suspicious file write", path,
                        number, line.strip()[:160]))
                if _ESCALATION_RE.search(line):
                    findings.append(_finding(
                        "H011", "Sensitive binary execution", path,
                        number, line.strip()[:160]))
            if _TRACE_DETECT_RE.search(line):
                findings.append(_finding(
                    "H012", "Strace detection attempt", path,
                    number, line.strip()[:160]))
            if _trace_truncate(line):
                findings.append(_finding(
                    "H013", "Strace log truncated", path,
                    number, line.strip()[:160]))
    return findings
