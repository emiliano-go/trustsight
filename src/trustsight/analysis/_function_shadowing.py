# ruff: noqa: F405
from ._build_constants import *  # noqa: F401,F403


# ---------------------------------------------------------------------------
# H097 - function shadowing
# ---------------------------------------------------------------------------

_FUNCTION_DEF_RE = re.compile(
    r"^\s*(?:function\s+)?(\w+)\s*\(\s*\)\s*\{"
)
_FUNCTION_ASSIGN_RE = re.compile(
    r"^\s*(\w+)\s*=\s*\("
)

# Every shell builtin, makepkg helper, and common utility whose
# redefinition in a PKGBUILD is suspicious.  Legitimate packages never
# do this; an attacker who redefines msg() suppresses output, cd()
# hijacks the working directory, and source() redirects file inclusion.
# Note: "source" is included for function definitions (source() is
# suspicious) but excluded from array assignments via _PKGBUILD_ARRAY_VARS
# because source=() is a legitimate PKGBUILD array declaration.
_SHADOWED_NAMES = frozenset({
    # Shell builtins
    "cd", "echo", "printf", "read", "source", ".", "eval", "exec",
    "set", "unset", "export", "declare", "local", "typeset",
    "trap", "kill", "wait", "exit", "return", "break", "continue",
    "shift", "test", "[", "command", "builtin", "enable", "hash",
    "type", "which", "getopts", "false", "true",
    # Makepkg helpers
    "msg", "msg2", "warning", "error", "die", "plain",
    # Core utilities commonly called directly
    "cp", "mv", "rm", "ln", "cat", "grep", "sed", "awk",
    "find", "xargs", "chmod", "chown", "tar", "gzip", "gunzip",
    "make", "install", "mkdir", "rmdir", "touch", "head", "tail",
    "sort", "uniq", "wc", "tr", "cut", "paste", "diff", "patch",
    "curl", "wget", "git", "ssh", "scp", "rsync",
    "chgrp", "mktemp", "basename", "dirname",
    "realpath", "readlink", "stat", "file", "dd", "tee",
    "env", "nice", "timeout", "nohup", "script", "strace",
})

# PKGBUILD-specific variable names that are legitimately assigned with =()
# and must not trigger H097.
_PKGBUILD_ARRAY_VARS = frozenset({
    "source", "source_x86_64", "source_aarch64", "source_i686",
    "sha256sums", "sha512sums", "sha1sums", "md5sums", "b2sums",
    "sha256sums_x86_64", "sha512sums_x86_64",
    "depends", "makedepends", "checkdepends", "optdepends",
    "provides", "conflicts", "replaces",
    "backup", "options", "install", "changelog",
    "noextract", "validpgpkeys",
})


def _function_shadow_findings(diff_text, config, add) -> None:
    """A function or variable is redefined, suppressing or hijacking
    makepkg logic (H097).

    Redefining msg(), error(), or die() suppresses build output.
    Redefining cd() hijacks the working directory.  Redefining source()
    or .() redirects file inclusion.  No benign PKGBUILD does any of
    these.
    """
    lines = mask_to_pkgbuild(resolve_added_lines(diff_text))
    for i, line in enumerate(lines):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = _strip_comment(line[1:])
        # Check function definitions: name() { or function name() {
        m = _FUNCTION_DEF_RE.match(body)
        if m and m.group(1) in _SHADOWED_NAMES:
            add("H097", "Function Shadowing", "HIGH", "integrity",
                f"function '{m.group(1)}' is redefined",
                line=i + 1, body=body.strip()[:80],
                func_name=m.group(1),
                detail=f"redefinition of {m.group(1)} may suppress or "
                       f"hijack makepkg logic")
            return
        # Check array-style assignments: name=()
        # Exclude PKGBUILD-specific variables (source, sha256sums, etc.)
        # which are legitimately assigned with =().
        m = _FUNCTION_ASSIGN_RE.match(body)
        if m and m.group(1) in _SHADOWED_NAMES and m.group(1) not in _PKGBUILD_ARRAY_VARS:
            add("H097", "Function Shadowing", "HIGH", "integrity",
                f"variable '{m.group(1)}' is reassigned as an array",
                line=i + 1, body=body.strip()[:80],
                func_name=m.group(1),
                detail=f"reassignment of {m.group(1)} may suppress or "
                       f"hijack makepkg logic")
            return
