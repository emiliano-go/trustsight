"""- install-path persistence rules.

H032/H038/H039/H042/H062 share one question: where does a build/install
function put a file?  They are code rules because each needs write-target
resolution (install/cp/ln/redirect destinations) against a path taxonomy
($pkgdir staging, $srcdir build tree, $HOME, absolute runtime paths).

Heredoc bodies are data, not commands, so H032/H038/H042/H062 skip them;
H039 is the exception because a systemd unit's ExecStart line *is* the
content being written.

H042 is deliberately the quietest rule here so the persistence signals
never triple-fire on one piece of evidence: a hidden write that is later
executed belongs to H069/H072, one that lands in a world-writable dir
belongs to H038, and H042 only claims the hidden drop that neither rule
already owns.
"""

import os
import re
import shlex

from ..deps import _strip_comment
from .delivery import (
    _SCOPE_FUNCTIONS,
    _collect_executions,
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

# The other ways a shell names a destination.  Without these the whole
# write-target family is bypassed by substituting a verb: ``tee /etc/x``,
# ``dd of=/etc/x`` and ``mkdir -p /opt/x`` do what ``cp`` does.  Each is
# command-position anchored like _COPY_TARGET_RE, and each names its
# destination explicitly rather than by position, except rsync (last
# argument, same shape as cp).
_TEE_TARGET_RE = re.compile(_WRITE_CMD_START + r"tee\s+(?:-\S+\s+)*(\S+)", re.IGNORECASE)
_DD_TARGET_RE = re.compile(_WRITE_CMD_START + r"dd\b[^;&|]*?\bof=(\S+)", re.IGNORECASE)
_MKDIR_TARGET_RE = re.compile(
    _WRITE_CMD_START + r"(?:mkdir|touch|mkfifo|mknod)\s+(?:-\S+\s+)*(\S+)", re.IGNORECASE
)
# sed -i edits its last argument in place.  The expression itself routinely
# contains ``|`` as the s/// delimiter, so unlike the other verbs this one
# cannot stop at a pipe: it takes the last token on the line.
_SED_INPLACE_RE = re.compile(
    _WRITE_CMD_START + r"sed\s+(?:-\S+\s+)*-i\S*\s.*?(\S+)\s*$", re.IGNORECASE
)
_RSYNC_TARGET_RE = re.compile(_WRITE_CMD_START + r"rsync\b([^;&|]*)$", re.IGNORECASE)

_NAMED_TARGET_RES = (
    _TEE_TARGET_RE, _DD_TARGET_RE, _MKDIR_TARGET_RE, _SED_INPLACE_RE,
)


def _inside_quotes(line: str, pos: int) -> bool:
    """True when *pos* falls inside a single- or double-quoted span.

    A redirect spelled inside a quoted string is message text, not a write:
    ``echo "append 'export X >> ~/.bashrc'"`` prints the string and writes
    nothing, but the naive redirect scan read ``>> ~/.bashrc`` out of it and
    C017 fired.
    """
    quote = ""
    i = 0
    while i < pos:
        ch = line[i]
        if quote:
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"':
                i += 1
        elif ch in "\"'":
            quote = ch
        elif ch == "\\":
            i += 1
        i += 1
    return bool(quote)


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
    for m in _RSYNC_TARGET_RE.finditer(body):
        args = m.group(1).split()
        if args and not args[-1].startswith("-"):
            targets.append(args[-1])
    for regex in _NAMED_TARGET_RES:
        for m in regex.finditer(body):
            if m.group(1) and not m.group(1).startswith("-"):
                targets.append(m.group(1))
    for m in _REDIRECT_TARGET_RE.finditer(body):
        # The command-position verbs above cannot fire inside a quoted string;
        # a redirect can, so it is the one that needs the quote test.
        if _inside_quotes(body, m.start()):
            continue
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

#: pacman runs these as root.
_INSTALL_SCRIPTLETS = (
    "post_install", "post_upgrade", "pre_install",
    "pre_upgrade", "pre_remove", "post_remove",
)

_WW_DIR_RE = re.compile(r"^/(?:tmp|var/tmp|dev/shm)(?:/|$)")
_WW_CD_RE = re.compile(r"\bcd\s+/(?:tmp|var/tmp|dev/shm)\b")
_MKTEMP_RE = re.compile(r"\bmktemp\b")

#: An interpreter editing a live-system file in place.  `sed -i` is read by
#: the write-target scan, but `perl -pi`/`ruby -i` are not, so the same edit
#: through them walked past H076.
_INPLACE_EDIT_RE = re.compile(
    r"\b(?:perl|ruby)\b[^\n;&|]*?-[A-Za-z]*i[A-Za-z]*\b.*?(\S+)\s*$")
#: An inline interpreter `open(..., "a"/"w")` against an absolute path - a
#: write the shell-command target scan cannot see.
_INLINE_OPEN_WRITE_RE = re.compile(
    r"\bopen\s*\(\s*[\"'](/[^\"']+)[\"']\s*,\s*[\"'][wa]")


def collapse_path_slashes(text: str) -> str:
    """Collapse ``//`` runs and ``/.`` segments a shell path also collapses.

    The kernel treats `//tmp`, `/./tmp` and `//.//tmp` as `/tmp`, so a
    literal `/tmp` match misses the same directory written another way - the
    harness walked `cd //tmp` and `cd /./tmp` straight past H038.  Only runs
    of slashes and `/.` segments are folded; `http://` becomes `http:/`,
    which matches none of the world-writable patterns.
    """
    out = re.sub(r"/{2,}", "/", text)
    previous = None
    while previous != out:
        previous = out
        out = re.sub(r"/\.(?=/|$)", "", out)
    return out


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


def edge_hidden_drop(ctx, add) -> None:
    """H042 predicate over the shared graph context.

    A hidden file dropped outside the build trees.  A file the same function
    later executes is the payload of another rule, not a hidden drop.
    """
    lines = ctx.lines
    scopes = ctx.scopes
    heredoc_body = ctx.heredoc_body

    execs_by_fn: dict[str, set[str]] = {}
    for i, line in enumerate(lines):
        fn = scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        execs_by_fn.setdefault(fn, set()).update(
            os.path.basename(p) for p in _collect_executions(_strip_comment(line[1:]))
        )

    for i, line in enumerate(lines):
        fn = scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None:
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
            add("H042", "Hidden Drop", "HIGH", "persistence",
                f"{fn}() drops a hidden file outside the build trees: {t}",
                line=i + 1, position=fn, path=t)
            return


# H076 - a build function's only legitimate write destinations.  Devices are
# not filesystem state ( ``> /dev/null`` is how a build stays quiet), and a
# target carrying shell metacharacters is a fragment of an awk program or a
# parameter expansion that the extractor picked up, not a path.
_DEVICE_TARGET_RE = re.compile(r"^/dev/")
_PLAIN_ABS_PATH_RE = re.compile(r"^/(?:[\w.+@-]+/)*[\w.+@-]+$")
_BUILD_TIME_FUNCTIONS = frozenset({"prepare", "build", "check", "package"})


# ---------------------------------------------------------------------------
# R054 stand-down: staging a committed file is not writing persistence
# ---------------------------------------------------------------------------

#: R054's verbs whose leading operands are sources.  `cat`/`printf`/`echo`/
#: `tee`/`dd`/`mkdir`/`>` create or transform the file in the recipe, so a
#: match on those is never stood down.
_R054_STAGING_VERBS = frozenset({"install", "cp", "mv", "ln", "rsync"})


def _stages_only_committed(match: str, committed: frozenset[str]) -> bool:
    """True when every source operand is a file committed in the tree.

    R054 claims a unit dropped outside the package root by the build.  A
    committed file staged into `$pkgdir` is the ordinary way a package
    ships its own unit, and the file itself is read by H039/R054's own
    unit analysis.  The stand-down is deliberately narrow: a heredoc, a
    redirect, `/dev/stdin`, an absolute or `$srcdir` source, a non-staging
    verb, or any argument that does not parse keeps the finding.
    """
    body = match.lstrip("+-").lstrip()
    if "<<" in body or ">" in body:
        return False
    try:
        tokens = shlex.split(body)
    except ValueError:
        return False
    if not tokens:
        return False
    verb = tokens[0].rsplit("/", 1)[-1]
    if verb not in _R054_STAGING_VERBS:
        return False
    operands = [t for t in tokens[1:] if not t.startswith("-")]
    if len(operands) < 2:
        return False
    sources = operands[:-1]
    for source in sources:
        cleaned = source.strip("\"'").strip("./")
        if not cleaned or cleaned.startswith(("/", "$", "~", "{")) or "$" in cleaned:
            return False
        if cleaned not in committed and not any(
            c.startswith(cleaned + "/") for c in committed
        ):
            return False
    return True


def stand_down_committed_staging(
    triggered: list[dict],
    tree_manifest: list[tuple[str, bytes]] | None,
) -> list[dict]:
    """Drop R054 findings that stage a file committed in the recipe's tree.

    ``tree_manifest`` is the repo tree ``(path, head_bytes)``.  A missing
    tree (an incomplete read, the corpus path with no snapshot) leaves
    every finding in place: an unread tree cannot stand a rule down.
    """
    if not triggered or not tree_manifest:
        return triggered
    committed = frozenset(
        path.lstrip("./") for path, _head in tree_manifest
    )
    return [
        finding
        for finding in triggered
        if finding.get("rule_id") != "R054"
        or not _stages_only_committed(finding.get("match") or "", committed)
    ]


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def _persistence_findings(diff_text, config, add, current_text=None, ctx=None) -> None:
    """Run the install-path persistence rules (H032/H038/H039/H062/H042/H076)."""
    from .edges import build_context, run_edge_instances
    from .persistence_engine import run_persistence_instances

    if ctx is None:
        ctx = build_context(diff_text, config, current_text=current_text)
    # the write-classification predicates share the graph context.
    run_persistence_instances(
        ctx, add, only=frozenset({"H039", "H062", "H032", "H038"}))
    run_edge_instances(ctx, add, only=frozenset({"H042"}))
    run_persistence_instances(ctx, add, only=frozenset({"H076"}))
    run_persistence_instances(ctx, add, only=frozenset({"C031"}))
