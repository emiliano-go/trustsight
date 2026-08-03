"""Phase 3 - install-path persistence rules (plan §5).

R077/R084/R085/R088/R114 share one question: where does a build/install
function put a file?  They are code rules because each needs write-target
resolution (install/cp/ln/redirect destinations) against a path taxonomy
($pkgdir staging, $srcdir build tree, $HOME, absolute runtime paths).

Heredoc bodies are data, not commands, so R077/R084/R088/R114 skip them;
R085 is the exception because a systemd unit's ExecStart line *is* the
content being written.

R088 is deliberately the quietest rule here so the persistence signals
never triple-fire on one piece of evidence: a hidden write that is later
executed belongs to R121/R124, one that lands in a world-writable dir
belongs to R084, and R088 only claims the hidden drop that neither rule
already owns.
"""

import os
import re

from ..deps import _strip_comment
from ..rules import _classify_enclosing_function
from ..tokenizer import resolve_added_lines
from .delivery import (
    _SCOPE_FUNCTIONS,
    _collect_executions,
    _heredoc_body_indices,
    _norm_path,
)

# ---------------------------------------------------------------------------
# Write-target extraction
# ---------------------------------------------------------------------------

_WRITE_CMD_START = r"(?:\A\s*|[;&|]\s*)"

# install/cp/mv/ln destinations: the ``-t DIR`` form first, else the last
# argument.  Command-position anchored so ``'cp ... ~/.zshrc'`` inside a
# quoted string never reads as a write.
_COPY_TARGET_RE = re.compile(
    _WRITE_CMD_START + r"(?:install|cp|mv|ln)\b[^;&|]*?-t\s+(\S+)"
    r"|" + _WRITE_CMD_START + r"(?:install|cp|mv|ln)\b([^;&|]*)$",
    re.IGNORECASE,
)

# Plain file redirects: ``> path`` / ``>> path``, not ``<<`` heredocs,
# ``&>``/``2>`` descriptor redirects, ``<( )``/``>( )`` process subs.
_REDIRECT_TARGET_RE = re.compile(r"(?<![<&0-9])(?:>>|>)\s*([^;&|>\s][^;&|>]*)")


def _raw_targets(body: str) -> list[str]:
    """Raw write destinations on *body* (quote characters preserved)."""
    targets: list[str] = []
    for m in _COPY_TARGET_RE.finditer(body):
        if m.group(1):
            targets.append(m.group(1))
        elif m.group(2):
            args = m.group(2).split()
            if args and not args[-1].startswith("-"):
                targets.append(args[-1])
    for m in _REDIRECT_TARGET_RE.finditer(body):
        t = m.group(1).strip().strip("\"'")
        if t and not t.startswith("("):
            targets.append(t)
    return targets


_STAGED_PREFIX_RE = re.compile(
    r"^\$(?:\{)?(?:pkgdir|srcdir|startdir|BUILDDIR)(?:\})?(?:/|$)"
)


def _is_staged(target: str) -> bool:
    """True for a write into the package/build trees ($pkgdir, $srcdir...)."""
    return bool(_STAGED_PREFIX_RE.match(target.strip().strip("\"'")))


# ---------------------------------------------------------------------------
# Path classification
# ---------------------------------------------------------------------------

_PACMAN_HOOK_RE = re.compile(r"^/?usr/share/libalpm/hooks(?:/|$)")

_HOME_PREFIX_RE = re.compile(r"^(?:\$?\{?HOME\}?|~)(?:/|$)")

_RC_BASENAME_RE = re.compile(
    r"^(?:\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zshenv|\.profile|"
    r"\.cshrc|\.tcshrc|\.config|\.gitconfig|\.netrc|\.ssh)$"
)

_WW_DIR_RE = re.compile(r"^/(?:tmp|var/tmp|dev/shm)(?:/|$)")
_WW_CD_RE = re.compile(r"\bcd\s+/(?:tmp|var/tmp|dev/shm)\b")
_MKTEMP_RE = re.compile(r"\bmktemp\b")

_HIDDEN_NAME_RE = re.compile(r"(?:^|/)\.[A-Za-z0-9_][^/]*$")
_HIDDEN_EXEMPT_RE = re.compile(r"(?:^|/)(?:\.git|\.github|\.gitignore|\.gitmodules)(?:/|$)")

_RUNTIME_WRITABLE_RE = re.compile(
    r"^\"?/(?:tmp|var/tmp|dev/shm|run|var/run)(?:/|$)"
    r"|^\$?\{?HOME\}?"
    r"|^~"
    r"|^%h",
)
_ES_RE = re.compile(r"^\s*Exec(?:Start|StartPre|StartPost|StopPost|Stop)=\s*(\S+)")


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _libalpm_hook_findings(diff_text, config, add) -> None:
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        for t in _raw_targets(_strip_comment(line[1:])):
            if _PACMAN_HOOK_RE.search(_norm_path(t)):
                add("R114", "Pacman Hook Installed", "MEDIUM", "persistence",
                    f"{enclosing[i]}() installs a pacman hook: {t}",
                    line=i + 1, position=enclosing[i], path=t)
                return


def _home_rc_findings(diff_text, config, add) -> None:
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        for t in _raw_targets(_strip_comment(line[1:])):
            t_clean = t.strip().strip("\"'")
            if _is_staged(t_clean):
                continue
            base = os.path.basename(t_clean)
            if _HOME_PREFIX_RE.search(t_clean) or _RC_BASENAME_RE.match(base):
                add("R077", "Write To User Home Or RC", "HIGH", "persistence",
                    f"{enclosing[i]}() writes into the user's home/rc: {t}",
                    line=i + 1, position=enclosing[i], path=t)
                return


def _worldwritable_staging_findings(diff_text, config, add) -> None:
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        if _MKTEMP_RE.search(body):
            continue
        for t in _raw_targets(body):
            if _WW_DIR_RE.search(t.strip().strip("\"'")):
                add("R084", "World-Writable Staging", "HIGH", "persistence",
                    f"{enclosing[i]}() stages work in a world-writable path: {t}",
                    line=i + 1, position=enclosing[i], path=t)
                return
        for t in _collect_executions(body):
            if _WW_DIR_RE.search(t):
                add("R084", "World-Writable Staging", "HIGH", "persistence",
                    f"{enclosing[i]}() executes from a world-writable path: {t}",
                    line=i + 1, position=enclosing[i], path=t)
                return
        if _WW_CD_RE.search(body):
            add("R084", "World-Writable Staging", "HIGH", "persistence",
                f"{enclosing[i]}() works from a world-writable directory: {body.strip()[:80]}",
                line=i + 1, position=enclosing[i], body=body.strip()[:80])
            return


def _hidden_drop_findings(diff_text, config, add) -> None:
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    heredoc_body = _heredoc_body_indices(lines)

    execs_by_fn: dict[str, set[str]] = {}
    for i, line in enumerate(lines):
        fn = enclosing.get(i)
        if not line.startswith("+") or fn not in _SCOPE_FUNCTIONS or i in heredoc_body:
            continue
        execs_by_fn.setdefault(fn, set()).update(
            os.path.basename(p) for p in _collect_executions(_strip_comment(line[1:]))
        )

    for i, line in enumerate(lines):
        fn = enclosing.get(i)
        if not line.startswith("+") or fn not in _SCOPE_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        for t in _raw_targets(_strip_comment(line[1:])):
            t_clean = t.strip().strip("\"'")
            if _is_staged(t_clean) or _HIDDEN_EXEMPT_RE.search(t_clean):
                continue
            if _WW_DIR_RE.search(t_clean) or _HOME_PREFIX_RE.search(t_clean):
                continue
            base = os.path.basename(t_clean)
            if not _HIDDEN_NAME_RE.search(base):
                continue
            if base in execs_by_fn.get(fn, set()):
                continue
            add("R088", "Hidden Drop", "HIGH", "persistence",
                f"{fn}() drops a hidden file outside the build trees: {t}",
                line=i + 1, position=fn, path=t)
            return


def _systemd_unit_findings(diff_text, config, add) -> None:
    """A systemd unit whose ExecStart points at a runtime-writable path.

    Scans unit *content* (the ExecStart line itself, which can live in a
    heredoc body), not the unit filename, per the plan's refinement.
    """
    for i, line in enumerate(resolve_added_lines(diff_text)):
        if not line.startswith("+"):
            continue
        m = _ES_RE.match(line[1:])
        if not m:
            continue
        target = m.group(1).strip("\"'")
        if _RUNTIME_WRITABLE_RE.search(target):
            add("R085", "Systemd ExecStart From Runtime-Writable Path", "HIGH",
                "persistence",
                f"systemd unit ExecStart points at runtime-writable path: {target}",
                line=i + 1, exec_target=target)
            return


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def _persistence_findings(diff_text, config, add) -> None:
    """Run the install-path persistence rules (R077/R084/R085/R088/R114)."""
    _systemd_unit_findings(diff_text, config, add)
    _libalpm_hook_findings(diff_text, config, add)
    _home_rc_findings(diff_text, config, add)
    _worldwritable_staging_findings(diff_text, config, add)
    _hidden_drop_findings(diff_text, config, add)
