"""Extracted from crossfire.py: _x17_x25."""

from __future__ import annotations
import re
from ...config import (
    NETWORK_CLIENT as _NETWORK_CLIENT,
    SCRIPT_EXECUTOR,
)
from ._common import _EXEC_WRAPPER

__all__ = ['_x024_is_benign_path_suffix', '_x024_is_trusted_path_append', 'X017_RE', 'X021_RE', 'X024_RE', '_BUILD_MANIFEST_RE', '_CONTENT_WRITE_VERB_RE', '_FUNC_CONTINUATION_BODY_RE', '_FUNC_CONTINUATION_RE', '_HEREDOC_OPEN_RE', '_INDIRECT_VALUE_RE', '_MANIFEST_ARG_RE', '_MANIFEST_COMMAND_RE', '_SENSITIVE_VAR_RE', '_X017_FIND_RE', '_X017_SCRIPT_DANGER_RE', '_X021_RUN_POSITIONAL_RE', '_X021_SET_GLOB_RE', '_X022_CONFIG_FLAG_RE', '_X022_PAYLOAD_RE', '_X022_WRITE_RE', '_X024_VALUE_VAR_RE', '_multiline_function_shadow_lines', '_normalise_dest', '_redirect_target', '_x017_find_runs_a_script', '_x024_is_passthrough', '_x024_is_test_pythonpath', '_x024_is_git_provenance']

_X017_FIND_RE = re.compile(
    r"\bfind\b[^\n;&|]{0,200}?-(?:exec|ok)(?:dir)?\s+"
    r"(?:" + _EXEC_WRAPPER + r")?(?:/(?:usr/)?bin/)?"
    r"(?P<x017executor>" + SCRIPT_EXECUTOR + r")\b",
    re.IGNORECASE,
)

_X017_SCRIPT_DANGER_RE = re.compile(
    r"\b(?:" + SCRIPT_EXECUTOR + r")\b"
    r"|(?:" + _NETWORK_CLIENT + r")\b"
    r"|\beval\b|\bsource\b|\bbase64\b|\bxxd\b",
    re.IGNORECASE,
)

X017_RE = re.compile(
    r"--checkpoint-action\s*=\s*[\"']?exec"
    r"|--to-command\s*="
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)enable\s+(?:-\w+\s+)*-f\b"
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)hash\s+(?:-\w+\s+)*-p\b",
    re.IGNORECASE,
)

def _x017_find_runs_a_script(
    body: str, match: re.Match, lines: list[str], index: int
) -> bool:
    """Whether a `find ... -exec` hands the executor something that runs.

    Reads the command string after `-c`; a quoted argument is allowed to
    span lines (it is not a backslash continuation), so the following
    lines are read to the closing quote.  When the spelling is unreadable
    the rule fires toward looking.  Without `-c` the executor is running a
    file, which is the shape the rule names.
    """
    rest = body[match.end():]
    if not re.match(r"\s*-c\b", rest):
        return True
    quoted = re.match(r"\s*-c\s+'([^']*)'", rest, re.DOTALL) or \
        re.match(r'\s*-c\s+"([^"]*)"', rest, re.DOTALL)
    if quoted is not None:
        script = quoted.group(1)
    else:
        opener = re.match(r"\s*-c\s+(['\"])", rest)
        if opener is None:
            token = re.match(r"\s*-c\s+(\S+)", rest)
            if token is None:
                return True
            script = token.group(1)
        else:
            quote = opener.group(1)
            parts = [rest[opener.end():]]
            for follower in lines[index + 1:index + 41]:
                text = follower[1:] if follower[:1] in "+-" else follower
                end = text.find(quote)
                if end != -1:
                    parts.append(text[:end])
                    break
                parts.append(text)
            script = "\n".join(parts)
    return bool(_X017_SCRIPT_DANGER_RE.search(script))

_X021_SET_GLOB_RE = re.compile(r"(?:\A\s*|[;&|(]\s*|&&\s*)set\s+--\s+[^\n;&|]*\*")

_X021_RUN_POSITIONAL_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?[\"']?\$[@*]")

X021_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*|\b(?:do|then|else)\s+)"
    r"(?:" + _EXEC_WRAPPER + r")?(?:/(?:usr/)?bin/)?"
    r"(?:" + SCRIPT_EXECUTOR + r"|eval|source)\s+"
    r"[\"']?(?:"
    r"\$[@*]"                        # $@  $*
    r"|\$\{?[1-9]\}?"               # $1  ${1}
    r"|\$\{\w+\[[^\]]*\]\}"        # ${A[0]}  ${A[@]}
    r"|[\w./-]*\*[\w./-]*"          # *.sh  build/*.sh
    r")",
    re.IGNORECASE,
)

_X022_WRITE_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:printf|echo|cat|tee)\b")

def _redirect_target(body: str) -> tuple[int, str] | None:
    """``(index_of_redirect, destination)`` for the last unquoted `>`."""
    depth_s = depth_d = False
    cut = -1
    for i, ch in enumerate(body):
        if ch == "'" and not depth_d:
            depth_s = not depth_s
        elif ch == '"' and not depth_s:
            depth_d = not depth_d
        elif ch == ">" and not depth_s and not depth_d:
            cut = i
    if cut < 0:
        return None
    tail = body[cut + 1:].lstrip(">").strip()
    dest = re.split(r"[\s;&|<>]", tail, maxsplit=1)[0]
    return (cut, dest) if dest else None

_X022_PAYLOAD_RE = re.compile(r"\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/")

_X022_CONFIG_FLAG_RE = re.compile(
    r"--?(?:c|conf|config|configdir|conf-dir|config-dir|conf-file"
    r"|config-file|config-directory|configfile|rcfile|rc|include"
    r"|settings|profile|f|file)[=\s]", re.IGNORECASE)

def _normalise_dest(token: str) -> str:
    """A destination as it will be written on the line that uses it."""
    return token.replace('"', "").replace("'", "").strip()

_HEREDOC_OPEN_RE = re.compile(r"<<(-)?\s*['\"]?(\w+)['\"]?")

_CONTENT_WRITE_VERB_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:printf|echo|cat|tee)\b",
    re.IGNORECASE,
)

_BUILD_MANIFEST_RE = re.compile(
    r"(?:^|[\s\"'/])(?:build\.ninja|Makefile|makefile|GNUmakefile"
    r"|BUILD(?:\.bazel)?|WORKSPACE|meson\.build|CMakeLists\.txt"
    r"|SConstruct|SConscript|Justfile|justfile|Taskfile\.ya?ml"
    r"|[\w.-]+\.(?:mk|ninja|bazel|bzl|cmake))\b",
    re.IGNORECASE,
)

_MANIFEST_COMMAND_RE = re.compile(
    r"(?:^|[\s;])(?:command|cmd|COMMAND|recipe|script|run|args|entrypoint)"
    r"\s*(?:=|:)"
    # A tab-indented Makefile recipe line, in both spellings: a real tab
    # in a heredoc body, and the `\t` a `printf` writes to produce one.
    r"|^\s*\t|\\t\s*\S"
    r"|\bgenrule\s*\(",
)

_MANIFEST_ARG_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:g?make|ninja|samu|bazel|buck2?|pants|scons|waf|just|task)\b"
    r"[^\n;&|]*?\s-(?:f|-file|-makefile)[=\s]+[\"']?"
    r"([^\"'\s;&|]+)",
    re.IGNORECASE,
)

_SENSITIVE_VAR_RE = re.compile(
    r"(?P<x024var>DLAGENTS|COMPRESS(?:ZST|XZ|GZ|BZ2|LZ4|LRZ|LZO|LZ|Z)"
    r"|PACMAN_AUTH|CFLAGS|CXXFLAGS|LDFLAGS|MAKEFLAGS|RUSTFLAGS"
    r"|PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH)"
    r"\s*\+?=",
    re.IGNORECASE,
)

_INDIRECT_VALUE_RE = re.compile(
    r"\$\{?\w+[@\[\}]?|"   # ${var[@]}, ${var[}, ${var}, $var
    r"\$\(|"                # $(
    r"`"                     # backtick
)

X024_RE = re.compile(
    # Left boundary: the name must not be the tail of a longer word.
    # `CGO_CFLAGS` (underscore prefix) and `EXTRA_PATH` must still match,
    # but `unix:path=$runtime` inside a DBus address value is the string
    # 'path=', not the PATH assignment this rule hunts - the previous
    # boundary-less form fired on every `env unix:path=$x` payload.
    r"(?<![a-z0-9:])"
    r"(?:" + _SENSITIVE_VAR_RE.pattern + r")"
    r"(?:\s*[\"'\(]*\s*)"  # optional quotes/parens between = and value
    r"(?:" + _INDIRECT_VALUE_RE.pattern + r")",
    re.IGNORECASE,
)

_X024_VALUE_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")

def _x024_is_test_pythonpath(body: str, match: re.Match,
                            function: str | None) -> bool:
    """True for ``PYTHONPATH=...`` before a test runner inside ``check()``.

    `PYTHONPATH` names a module search path, not code the shell runs.  A
    package that points it at the staged test tree before running pytest is
    ordinary packaging; X012 still claims the dangerous shape (a library
    path pointed into the source tree).  A command substitution keeps the
    finding: the value is then produced by shell code, not a literal path.
    """
    var = match.groupdict().get("x024var", "")
    if var.upper() != "PYTHONPATH":
        return False
    value = match.group(0)
    if "$(" in value or "`" in value:
        return False
    tail = body[match.end():].lstrip(" \t\"';|&")
    token = tail.split(None, 1)[0].strip("\"'").lower() if tail else ""
    return token in {"python", "python3", "pypy3"} or token.startswith(
        ("pytest", "py.test", "tox", "nox", "nose", "unittest"))


#: Build-tool search paths that are configured by deriving them from other
#: variables.  They name where a compiler/pkg-config reads metadata, not code
#: the shell will load, so an indirect value is ordinary build plumbing.  The
#: sensitive-variable pattern has no left boundary and `_x024_is_passthrough`
#: only covers the same variable on both sides, so `CMAKE_PREFIX_PATH=` used
#: to match on its `PATH` tail.
_X024_BENIGN_BUILD_PATHS = frozenset({
    "CMAKE_PREFIX_PATH", "CMAKE_MODULE_PATH", "CMAKE_LIBRARY_PATH",
    "CMAKE_INCLUDE_PATH", "CMAKE_PROGRAM_PATH", "CMAKE_FRAMEWORK_PATH",
    "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "ACLOCAL_PATH", "GIT_EXEC_PATH",
})

#: The value half of a git-provenance assignment.  Anchored and linear: the
#: previous form started with an unbounded variable name, which backtracked
#: quadratically on a full-length line of `a.a.a...`.
_X024_GIT_VALUE_RE = re.compile(
    r"\$\(\s*git\s+(?:config|ls-tree|rev-parse|submodule)\b",
    re.IGNORECASE,
)


def _x024_is_git_provenance(body: str, match: re.Match) -> bool:
    """True when the indirect value comes from the recipe's own git metadata."""
    tail = body[match.start():match.start() + 256]
    eq = tail.find("=")
    if eq < 0:
        return False
    value = tail[eq + 1:].lstrip(" \t\"'(")
    return bool(_X024_GIT_VALUE_RE.match(value))


def _x024_is_benign_build_path(body: str, match: re.Match) -> bool:
    """True when the matched tail belongs to a benign build-config path."""
    start = match.start()
    i = start
    while i > 0 and (body[i - 1].isalnum() or body[i - 1] == "_"):
        i -= 1
    full = body[i:match.end()].split("=", 1)[0].strip().upper()
    # A cmake/compiler define carries a `-D`/`-U` prefix before the variable
    # name (`-DCMAKE_PREFIX_PATH=...`); the shell word starts at `D`, not at
    # `CMAKE_`.
    candidate = full.lstrip("-+")
    if candidate not in _X024_BENIGN_BUILD_PATHS and candidate.startswith("D"):
        candidate = candidate[1:]
    return candidate in _X024_BENIGN_BUILD_PATHS


def _x024_is_benign_path_suffix(body: str, match: re.Match) -> bool:
    """True when `PATH` is only the tail of a build-tool path variable.

    `_SENSITIVE_VAR_RE` has no left boundary, so `ELECTRON_OVERRIDE_DIST_PATH`
    matches its `PATH` tail.  That variable names where Electron's dist
    directory lives, not the shell search path.  `LD_LIBRARY_PATH` and the
    other real loader variables still match their whole name.
    """
    var = match.groupdict().get("x024var", "")
    if var.upper() != "PATH":
        return False
    start = match.start()
    i = start
    while i > 0 and (body[i - 1].isalnum() or body[i - 1] == "_"):
        i -= 1
    name = body[i:match.end()].split("=", 1)[0].strip().upper()
    return name != "PATH" and name.endswith("_PATH")


_X024_PATH_APPEND_RE = re.compile(
    r"\bPATH\s*=\s*[\"']?[^\n\"']*:\s*\$\{?PATH\}?",
    re.IGNORECASE,
)
_X024_PATH_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
_X024_TRUSTED_PATH_ROOTS = frozenset({
    "HOME", "SRCDIR", "STARTDIR", "PKGDIR", "PWD",
})
_X024_RUNTIME_PATH_PREFIX_RE = re.compile(
    r"^[\"']?(?:/tmp|/var/tmp|/dev/shm|/run)(?:/|$)"
)


def _x024_path_variable_is_trusted(
    lines: list[str], index: int, name: str
) -> bool:
    """Whether *name* was assigned a path under a trusted build root.

    The yarn/Electron helper builds `_yarnhome="${HOME}/.yarn/install"` and
    then prepends `${_yarnhome}/bin` to PATH.  That is a local toolchain
    path, not a value hidden from the reviewer.  Look back a bounded window
    for the assignment; an undefined variable keeps the finding.
    """
    assign = re.compile(
        rf"^\s*(?:local\s+|export\s+|declare\s+-\w+\s+)?"
        rf"{re.escape(name)}\s*=\s*(.+)$"
    )
    for previous in range(index - 1, max(-1, index - 50), -1):
        text = lines[previous]
        text = text[1:] if text[:1] in "+-" else text
        match = assign.match(text)
        if not match:
            continue
        value = match.group(1).strip().strip("\"'")
        return bool(re.search(
            r"\$\{?(?:HOME|srcdir|startdir|pkgdir|PWD)\}?|^~|^/(?:usr|opt)/",
            value,
        ))
    return False


def _x024_is_trusted_path_append(
    body: str, match: re.Match, lines: list[str], index: int,
) -> bool:
    """True for a PATH extension built from local/trusted paths.

    `PATH="${_yarnhome}/bin:${PATH}"` and
    `PATH="/usr/local/bin:${PATH}"` append to the existing search path
    without hiding where the new directory came from.  A command
    substitution, a runtime-writable literal prefix, or an undefined
    variable keeps X024's finding.
    """
    if match.groupdict().get("x024var", "").upper() != "PATH":
        return False
    value_match = _X024_PATH_APPEND_RE.search(body)
    if value_match is None:
        return False
    value = value_match.group(0)
    if "$(" in value or "`" in value:
        return False
    prefix = value.split(":", 1)[0]
    prefix = prefix.split("=", 1)[-1].strip().strip("\"'")
    if prefix and not prefix.startswith("$") and _X024_RUNTIME_PATH_PREFIX_RE.match(prefix):
        return False
    for name in _X024_PATH_VAR_RE.findall(value):
        if name.upper() == "PATH":
            continue
        if name.upper() in _X024_TRUSTED_PATH_ROOTS:
            continue
        if not _x024_path_variable_is_trusted(lines, index, name):
            return False
    return True


def _x024_is_passthrough(body: str, match: re.Match) -> bool:
    """True when the indirect value is the assigned variable's own name.

    `PATH="$PATH:$HOME/.cargo/bin"` appends to the existing value and
    `CGO_CFLAGS="${CFLAGS}"` forwards the standard flags: both are the
    value the reviewer already sees, not one hidden in another variable.
    The sensitive-variable pattern has no left boundary, so `CGO_CFLAGS`
    matches as `CFLAGS` and the comparison is against that tail name -
    which is what lets the CGO family through.
    """
    var = match.group("x024var")
    value = body[match.start():match.end()]
    expansion = _X024_VALUE_VAR_RE.search(value)
    return bool(expansion and expansion.group(1) == var)

_FUNC_CONTINUATION_RE = re.compile(
    r"^\s*(\w+)\s*\(\s*\)",
    re.IGNORECASE,
)

_FUNC_CONTINUATION_BODY_RE = re.compile(
    r"^\s*\{",
)

def _multiline_function_shadow_lines(lines):
    """Yield line numbers where a shadowed function is defined across lines."""
    from ..build import _SHADOWED_NAMES
    i = 0
    while i < len(lines) - 1:
        line = lines[i]
        if not line.startswith("+"):
            i += 1
            continue
        body = line[1:].strip()
        m = _FUNC_CONTINUATION_RE.match(body)
        if m and m.group(1) in _SHADOWED_NAMES:
            j = i + 1
            while j < len(lines) and not lines[j].startswith("+"):
                j += 1
            if j < len(lines) and _FUNC_CONTINUATION_BODY_RE.match(lines[j][1:]):
                yield i + 1  # 1-indexed
                i = j + 1
                continue
        i += 1
