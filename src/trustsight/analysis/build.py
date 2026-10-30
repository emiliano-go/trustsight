# ruff: noqa: F401,F405
from ._build_constants import *  # noqa: F401,F403
from ._build_flags import (
    _BUILD_FLAG_ASSIGN_RE,
    _HARDENING_OFF_RE,
    _build_flag_findings,
)
from ._build_reconstruction import (
    _OBFUSCATION_MARKER_RE,
    _REVEALED_RUN_RE,
    _reconstruction_findings,
)
from ._function_shadowing import (
    _FUNCTION_ASSIGN_RE,
    _FUNCTION_DEF_RE,
    _PKGBUILD_ARRAY_VARS,
    _SHADOWED_NAMES,
    _function_shadow_findings,
)


def _address_in(text: str) -> str | None:
    """The first remote address in *text*, scheme-bearing or scp-style.

    Token-anchored for both forms.  Searching *inside* a line for either
    shape is a quadratic scan - the leading character run is retried from
    every position, and possessive quantifiers make that worse rather than
    better, because each attempt then consumes to the end before failing.
    A full-length hostile line measured 304 ms. Splitting on whitespace is
    one pass and each anchored match is linear in its own token.
    """
    for token in text.split():
        candidate = token.strip("\"'()<>,")
        if not candidate:
            continue
        # The URL is not always the whole token: an interpreter one-liner
        # writes `urlretrieve("https://...","x.sh")`, where the address sits
        # inside a call.  `://` is a fixed marker, so finding it and walking
        # back over the scheme is linear - unlike letting the regex retry
        # its leading character run from every position.
        # A content address has no `://` to find: `magnet:?xt=urn:btih:…`
        # names bytes rather than a host. The marker walk below can never
        # reach one, so it is tested first - anchored, so it costs one
        # match per token.
        content = _CONTENT_ADDRESS_RE.match(candidate)
        if content:
            return content.group(0)
        marker = candidate.find("://")
        while marker != -1:
            start = marker
            while start > 0 and (candidate[start - 1].isalnum()
                                 or candidate[start - 1] in "+.-"):
                start -= 1
            scheme = _SCHEME_ADDRESS_RE.match(candidate[start:])
            if scheme:
                return scheme.group(0)
            marker = candidate.find("://", marker + 3)
        # No `@` precondition: the user part is optional, and requiring it
        # here re-introduced the gap the regex above was widened to close.
        if ":" in candidate and _SCP_ADDRESS_RE.match(candidate):
            return candidate
        # A CVS root names a remote in its own notation:
        # `:pserver:user@host:/path`, `:ext:host:/path`.
        if candidate.startswith(":") and _CVS_ROOT_RE.match(candidate):
            return candidate
    return None


#: Clients whose command line names a remote host with no URL scheme at
#: all: `sftp -b - u@h`, `ftp -n h`, `nc h 4444`, `ssh u@h cmd`.  The list
#: is deliberately narrow: `git fetch origin` names a *remote*, not a host,
#: and `rsync`/`lftp` put the host among positional arguments the naive
#: scan cannot tell from flags.
_HOST_FORM_CLIENTS = re.compile(
    r"\A(?:sftp|ssh|scp|ftp|tftp|nc|ncat|netcat|telnet)\b", re.IGNORECASE)

_HOST_TOKEN_RE = re.compile(
    r"\A(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+(?::\d{1,5})?\Z")


def _host_address_in(client_text: str, tail: str) -> str | None:
    """The bare host a host-form client on this line names, or ``None``.

    Flags and their digits are skipped; a token that begins a redirect ends
    the scan (`ftp -n < cmds.txt` names a command file, not a host); a
    token with no letter (`22`) is an argument, not a host.
    """
    if not _HOST_FORM_CLIENTS.match(client_text):
        return None
    for token in tail.split():
        raw = token.strip("\"'(),")
        if raw.startswith("<") or raw.startswith(">"):
            break
        if not raw or raw.startswith("-") or raw in ("-", "|", "&", ";"):
            continue
        if raw.isdigit() or not any(ch.isalpha() for ch in raw):
            continue
        if any(ch in raw for ch in "/$`{}'\"()<>&;|=,"):
            continue
        if _HOST_TOKEN_RE.match(raw):
            return raw
    return None


def fetch_addresses(body: str):
    """Yield addresses on *body* that a network client on the same line names.

    "Same command" is approximated by position: the client has to appear
    before the address and no pipeline separator may sit between them, which
    is the same boundary the single regex expressed with `[^|;&]`.
    """
    interpreter_re = re.compile(r"\A(?:python[23]?|perl|ruby|node|php|lua)\b",
                                re.IGNORECASE)
    for client in _FETCH_CLIENT_ONLY_RE.finditer(body):
        tail = body[client.end():]
        # A shell command ends at `;`, so the span from a client to its
        # address must not cross one - but an interpreter's script is a
        # *quoted argument*, and `python3 -c 'import urllib;urlopen(url)'`
        # puts a semicolon between the client and the URL as a matter of
        # Python syntax.  Cutting there dropped the address entirely.
        separators = ("|", "&") if interpreter_re.match(client.group(0)) \
            else ("|", ";", "&")
        cut = len(tail)
        for sep in separators:
            found = tail.find(sep)
            if found != -1:
                cut = min(cut, found)
        # The client match may itself contain the remote: `cvs -d ROOT
        # checkout` puts the root *between* the verb and the command, so
        # the matched text swallows it and looking only at the tail found
        # nothing.
        # A host-form client's operand is its remote even when the tail
        # also carries a scheme URL: `sftp -b - u@evil.example
        # https://declared/...` fetches from evil.example, and the URL is
        # a decoy argument.  Yielding the scheme address first let the
        # declared decoy silence H016 entirely (reopened bypass
        # list2-b/987b9ebd), so the host operand is reported first and the
        # scheme URL after it.  scp keeps the old order: its tail's first
        # host-like token can be a local source or destination, and
        # scp-form addresses (`u@h:/p`) are claimed by `_address_in`.
        host_first = bool(_HOST_FORM_CLIENTS.match(client.group(0))) \
            and not client.group(0).lower().startswith("scp")
        host = (_host_address_in(client.group(0), tail[:cut])
                if host_first else None)
        if host:
            yield host
        address = _address_in(client.group(0)) or _address_in(tail[:cut])
        if address:
            yield address
            continue
        # No scheme anywhere: a host-form client still names a remote.
        if host:
            continue
        host = _host_address_in(client.group(0), tail[:cut])
        if host:
            yield host


def _network_fetch_url(body: str) -> str | None:
    """The first address a network client on *body* fetches, if any."""
    return next(iter(fetch_addresses(body)), None)


def _foreign_pkg_re(config=None) -> re.Pattern:
    """Compile the H035 foreign-package-manager regex from patterns.toml."""
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("foreign_pkg_managers") or DEFAULT_FOREIGN_PKG_MANAGERS
    return re.compile("|".join(frags), re.IGNORECASE)


# H106: an override that points a package manager at a different registry.
# The override line is suspicious; a resolution in the same function makes
# it a delivery chain rather than a configuration mention.
_REGISTRY_OVERRIDE_RE = re.compile(
    r"\b(?:npm_config_registry|PIP_INDEX_URL|UV_INDEX|GOPROXY|GONOSUMDB|"
    r"GOPRIVATE|CARGO_REGISTRIES_[A-Z0-9_]+)\s*="
    r"|\bnpm\s+[^\n;|]*--registry\b"
    r"|\b(?:npm|pnpm|yarn)\s+config\s+set\s+registry\b"
    r"|(?:^|\s)registry\s*=\s*\S+"
    r"|\bpip3?\s+[^\n;|]*--(?:index-url|extra-index-url)\b"
    r"|\buv\s+[^\n;|]*--index(?:-url)?\b"
    r"|\bgem\s+sources\s+--add\b"
    r"|\bcomposer\s+config\s+repositories\b",
    re.IGNORECASE,
)

_SERVICE_ENABLE_RE = re.compile(
    r"\bsystemctl\s+(?:--user\s+)?enable\b"
    r"|\bloginctl\s+enable-linger\b"
    r"|\bcrontab\b(?!\s+-l\b)"
    r"|\bat\s+(?!-l\b)"
    r"|\bsystemd-run\s+--unit\b"
    r"|\bupdate-rc\.d\b"
    r"|\bchkconfig\b",
    re.IGNORECASE,
)


_REGISTRY_INSTALL_RE = re.compile(
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:install|add|ci|exec)\b"
    r"|\b(?:pip|pip3|uv|poetry|pipenv|conda)\s+(?:install|add|sync|run)\b"
    r"|\bpython3?\s+-m\s+pip3?\s+install\b"
    r"|\bcargo\s+(?:install|fetch|update)\b"
    r"|\bgo\s+(?:install|get|mod\s+download)\b"
    r"|\bgem\s+install\b"
    r"|\bcomposer\s+(?:install|require|update)\b",
    re.IGNORECASE,
)



def _service_enable_findings(ctx, add) -> None:
    """H108: build/install code enables a service or cron job."""
    lines = ctx.lines
    scopes = ctx.scopes
    for i, line in enumerate(lines):
        if not line.startswith("+"):
            continue
        scope = scopes.within(i, _CRITICAL_FUNCTIONS + _INSTALL_HOOKS)
        if scope is None:
            continue
        body = _strip_comment(line[1:])
        if _PRINTER_LINE_RE.match(body):
            body = _blank_quoted(body)
        if _SERVICE_ENABLE_RE.search(body):
            add("H108", "Service Or Cron Enable Command", "HIGH", "persistence",
                f"{scope}() enables a service or cron job: {body.strip()[:90]}",
                position=scope, body=body.strip()[:90])

def _registry_override_findings(ctx, add) -> None:
    """H106: build/install code redirects a package manager's registry."""
    lines = ctx.lines
    scopes = ctx.scopes
    for i, line in enumerate(lines):
        if not line.startswith("+"):
            continue
        scope = scopes.within(i, _CRITICAL_FUNCTIONS + _INSTALL_HOOKS)
        if scope is None:
            continue
        body = _strip_comment(line[1:])
        if not _REGISTRY_OVERRIDE_RE.search(body):
            continue
        resolves = any(
            _REGISTRY_INSTALL_RE.search(_strip_comment(other[1:]))
            for j, other in enumerate(lines)
            if j != i and other.startswith("+")
            and scopes.within(j, (scope,)) is not None
        )
        add("H106", "Registry Or Index Override",
            "HIGH" if resolves else "MEDIUM", "dependency",
            f"{scope}() overrides a package-manager registry: {body.strip()[:90]}",
            position=scope, body=body.strip()[:90])


def _obfuscation_indicators(config=None) -> list[re.Pattern]:
    """Compile the H036 obfuscation indicators from patterns.toml."""
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("obfuscation_indicators") or DEFAULT_OBFUSCATION_INDICATORS
    return [re.compile(p) for p in frags]


# H036 composition: a dense obfuscated line that reconstructs to an
# executable action is HIGH, not MEDIUM.  The action shapes mirror what
# H035 (foreign package manager), R003/R043 (decode-and-pipe) and R039
# (eval of dynamic content) detect on reconstructed text.
def _reconstructs_to_action_re(config=None) -> re.Pattern:
    foreign = _foreign_pkg_re(config)
    return re.compile(
        foreign.pattern
        + r"|"
        r"(?:base64|xxd|uudecode)\b[^|]*\|[^|]*(?:bash|sh|zsh|dash)\b"
        + r"|"
        r"\beval\b"
        + r"|"
        r"(?:curl|wget)\b[^|;]*\|(?:bash|sh|zsh|dash)\b",
        re.IGNORECASE,
    )


def _obfuscation_density_threshold(config) -> int:
    """Return the H036 density threshold from thresholds.toml."""
    thresholds = load_thresholds().get("h036", {})
    return thresholds.get("obfuscation_density", 3)


def _reconstructs_to_action(body: str, config=None) -> bool:
    """True when *body* (already resolved and reconstructed) reveals an
    executable action rather than inert obfuscation."""
    return bool(_reconstructs_to_action_re(config).search(body))


def reconstructs_to_js_pm_install(text: str) -> bool:
    return bool(_foreign_pkg_re().search(text))


def reconstructs_to_decode_pipe_sh(text: str) -> bool:
    return bool(
        re.search(
            r"(?:base64|xxd|uudecode)\b[^|]*\|[^|]*(?:bash|sh|zsh|dash)\b",
            text, re.IGNORECASE,
        )
    )


def reconstructs_to_eval_of_decoded(text: str) -> bool:
    return bool(re.search(r"\beval\b", text, re.IGNORECASE))

_ENV_SUBVERSION_HIGH_RE = re.compile(
    r"\b(?:LD_PRELOAD|LD_LIBRARY_PATH)\s*(?:\+?=)",
)
#: The variable must be the one being assigned, not a suffix of a cmake cache
#: type.  ``-DCMAKE_INSTALL_PREFIX:PATH=/usr`` and ``:FILEPATH=`` are type
#: annotations, not PATH assignments, so a ``:`` before the name excludes it.
_ENV_SUBVERSION_MED_RE = re.compile(
    r"(?<!:)\b(?:CFLAGS|LDFLAGS|MAKEFLAGS|PATH)\s*(?:\+?=)",
)

# H004 - sudo at a command position.  `sudo` is executed, not mentioned,
# only when it starts a command: line start, after `;`/`&&`/`||`/`|`, or
# inside `$(...)`.  The suffix allows the closing `)` so ``$(sudo)`` (an
# invocation form an earlier test missed) is caught too.  Backtick
# substitution (`` `sudo` ``) is handled separately because a backtick
# inside single quotes is literal, not executed.  That single test excludes
# the plan's must-not-fire surface - optdepends names, path segments and
# echo strings - all of which place `sudo` at an argument position.
# One `\s*`, not two. `\A\s*` followed by `\s*` lets the engine split a
# whitespace run between them in as many ways as the run is long, which is
# quadratic: 8192 leading spaces took 1.1 seconds. Collapsing the pair is
# behaviour-preserving - both spellings mean "start of line, optional
# whitespace, sudo" - and costs 0.6ms.
#
# `sudo` was the whole rule, and it is one of four ways to say the same
# thing. `doas` is the OpenBSD-derived replacement many Arch users install
# instead; `pkexec` is polkit's and is present on every desktop; `run0` is
# systemd's, shipped since v256. A recipe reaching for any of them is
# reaching for root, and naming only the first meant the rule tested which
# tool the writer preferred rather than what it does.
_PRIVILEGE_TOOL = r"sudo|doas|pkexec|run0"

_SUDO_CMD_START_RE = re.compile(
    r"(?:\A|[;&|]|\$\()\s*(?:" + _PRIVILEGE_TOOL + r")(?=[\s)&|`;]|$)",
    re.IGNORECASE,
)

# `` `sudo` `` - backtick command substitution (`` `sudo -n true` ``).
_SUDO_BACKTICK_RE = re.compile(
    r"`\s*(?:" + _PRIVILEGE_TOOL + r")\b", re.IGNORECASE)

# A `-u`/`--user`/`-g`/`--group` option, then the target token.  Matched by
# hand rather than with a wildcard-bearing regex: the target is one shell
# word, and a regex with `[^)]*`/`[^`]*`/`[^}]*` alternations measured
# superlinear on full-length adversarial lines (the adversarial regex audit
# refuses it).  String ops are linear and the shape is simple.
#
# The `sudo -u "$SUDO_USER"` idiom is how an install hook runs a per-user
# daemon as that user after a root install; it *drops* privilege, so scoring
# it as an escalation was backwards.  Only a dynamic target stands down: a
# literal `sudo -u root` (or `-u 0`, or any named user) still runs a command
# as another account, and the payload that hides there is real.
_USER_OPTIONS = ("-u", "--user", "-g", "--group")

# A target that names a *variable* rather than a literal account: `$SUDO_USER`,
# `${SUDO_USER}`, any `${...}` expansion, a `$(...)` or backtick substitution.
def _is_dynamic_account(target: str) -> bool:
    token = target.strip().strip("\"'")
    if not token:
        return False
    if token.startswith("$(") or token.startswith("`"):
        return True
    if token.startswith("${"):
        return True
    if token.startswith("$"):
        # `$SUDO_USER`, `$user`, `$UID` - a variable, not a named account.
        return True
    return False


def _drops_to_a_variable(after: str) -> bool:
    """True when the option directly after the tool names a dynamic account.

    *after* is the body from just past the tool name.  The first option must
    be `-u`/`--user`/`-g`/`--group` (either `-u x` or `--user=x`) and its
    target must be a variable/substitution; a literal account keeps the
    invocation an escalation.
    """
    rest = after.lstrip()
    if rest[:1] == '"' or rest[:1] == "'":
        # A quoted tool name (`"sudo"`); drop the quote before the option.
        rest = rest[1:].lstrip("\"'")
    if not rest.startswith("-"):
        return False
    option, _, remainder = rest.partition(" ")
    name, eq, inline = option.partition("=")
    if name not in _USER_OPTIONS:
        return False
    if eq:
        return _is_dynamic_account(inline)
    target = remainder.strip()
    # The target may itself be a quoted expansion; take the whole leading
    # word up to the next unquoted space or separator.
    for i, ch in enumerate(target):
        if ch in " \t;&|)":
            target = target[:i]
            break
    return _is_dynamic_account(target)


def _backtick_sudo_executes(body: str) -> bool:
    """True when *body* runs ``sudo`` through a backtick substitution.

    A backtick inside a single-quoted string is literal (``echo '`sudo`'``
    prints, it does not run), so the quote parity before the backtick tells
    execution from mention.
    """
    for m in _SUDO_BACKTICK_RE.finditer(body):
        if body[:m.start()].count("'") % 2 == 0:
            return True
    return False


def _sudo_escalates(body: str) -> bool:
    """True when *body* runs a privilege tool as root (not a user drop).

    Scans every command-position ``sudo``/``doas``/``pkexec``/``run0`` and
    ignores the ones whose first option target is the dynamic
    ``sudo -u "$SUDO_USER"`` idiom: that *drops* to the invoking user and is
    the ordinary shape of an install hook that starts a per-user daemon.  A
    second, real escalation on the same line still fires.
    """
    for match in _SUDO_CMD_START_RE.finditer(body):
        # Inspect the option directly after the tool name (`match.end()`),
        # so `sudo -u $SUDO_USER` stands down and `sudo cmd -u x` does not.
        if _drops_to_a_variable(body[match.end():]):
            continue
        return True
    return _backtick_sudo_executes(body)

_SCOPE_FUNCTIONS = frozenset(_CRITICAL_FUNCTIONS) | frozenset(_INSTALL_HOOKS)


def _added_line_number(diff_text: str, fragment: str) -> int | None:
    """Return the 1-based number of the first added line containing
    *fragment* (a tiny local analogue of delivery's ``_find_line``, kept
    here because ``delivery`` imports this module)."""
    pattern = re.compile(r"\+.*" + re.escape(fragment[:60]), re.IGNORECASE)
    for i, line in enumerate(parse_diff_lines(split_lines(diff_text)).lines):
        if pattern.search(line.raw):
            return i + 1
    return None


def _recipe_lines(current_text: str | None) -> list[str] | None:
    """The current PKGBUILD as diff-shaped lines, for the call graph.

    A diff shows a hunk.  The ``build()`` that calls an added helper may sit
    entirely outside it, in which case the call is invisible and the helper
    resolves to no scope - the evasion would survive by being small.  The
    graph is therefore built over the whole recipe where the caller has it,
    while findings still come only from added lines.  Marked as context
    (`" "`), never `"+"`, so nothing here can itself become a finding.
    """
    if not current_text:
        return None
    return [" " + ln for ln in split_lines(current_text)]


# H075 - a fetched script reaches a shell through an indirect path the
# pipe-to-shell regexes (R001/R002) and the R039/R040 eval / sh -c rules do
# not see: process substitution (``bash <(curl ...)``), xargs (``curl ... |
# xargs bash``), and a here-string fed by command substitution
# (``bash <<< "$(curl ...)"``).  Each still executes remote code at build
# time, so it must not be left at R010/R011's "uses curl/wget" LOW.
_REMOTE_PROC_SUBST_RE = re.compile(
    r"(?:\b(?:" + _SHELL_EXEC + r")\b|\bsource\b|\.)\s*<\s*\(\s*(?:curl|wget)\b",
    re.IGNORECASE,
)
_REMOTE_XARGS_SHELL_RE = re.compile(
    # The bar must be an operative pipe: an escaped one is an argument
    # and starts no pipeline.  Same guard as R001-R003 and R045.
    r"\b(?:curl|wget)\b[^|;]*(?<!\\)\|\s*xargs\s+(?:\S+\s+)*(?:"
    + _SHELL_EXEC + r")\b",
    re.IGNORECASE,
)
# A fetch piped into a command that *fans out* to a shell through an output
# process substitution: `curl url | tee >(bash) >/dev/null`.  R001 looks for
# a shell directly after the bar and finds `tee`; the input-side pattern
# above looks for `<(curl ...)` and finds nothing.  The shell still runs the
# fetched bytes.
_REMOTE_PROC_SUBST_OUT_RE = re.compile(
    r"\b(?:curl|wget|aria2c|axel)\b[^|;&]*(?<!\\)\|[^|;&]*>\(\s*"
    r"(?:" + _EXEC_WRAPPER_RE + r")?(?:/(?:usr/)?bin/)?(?:" + _SHELL_EXEC + r")\b",
    re.IGNORECASE,
)
_REMOTE_HERESTRING_RE = re.compile(
    r"\b(?:" + _SHELL_EXEC + r")\s+(?:<<<|<<)\s*[^\n]*(?:\$\{?\(|`|\$\{)",
    re.IGNORECASE,
)


def edge_indirect_remote_execution(ctx, add) -> None:
    """H075 predicate over the shared graph context.

    A fetched script is executed through an indirect shell path (process
    substitution, xargs, here-string).
    """
    diff_text = ctx.diff_text
    for line in ctx.lines:
        if not line.startswith("+"):
            continue
        body = _strip_comment(line[1:])
        if _REMOTE_PROC_SUBST_RE.search(body):
            add("H075", "Remote Script Via Process Substitution", "CRITICAL",
                "execution",
                f"process substitution feeds a fetched script to a shell: {body.strip()[:80]}",
                line=_added_line_number(diff_text, body.strip()[:30]),
                body=body.strip()[:80])
            return
        if _REMOTE_PROC_SUBST_OUT_RE.search(body):
            add("H075", "Remote Script Via Process Substitution", "CRITICAL",
                "execution",
                f"a fetch fans out to a shell through >(...): {body.strip()[:80]}",
                line=_added_line_number(diff_text, body.strip()[:30]),
                body=body.strip()[:80])
            return
        if _REMOTE_XARGS_SHELL_RE.search(body):
            add("H075", "Remote Script Via xargs", "CRITICAL", "execution",
                f"fetched script piped to a shell through xargs: {body.strip()[:80]}",
                line=_added_line_number(diff_text, body.strip()[:30]),
                body=body.strip()[:80])
            return
        if _REMOTE_HERESTRING_RE.search(body):
            add("H075", "Remote Script Via Here-String", "CRITICAL", "execution",
                f"shell fed a here-string carrying command substitution: {body.strip()[:80]}",
                line=_added_line_number(diff_text, body.strip()[:30]),
                body=body.strip()[:80])
            return


# ---------------------------------------------------------------------------
# H080 - a command or shell is named through indirect variable expansion
# ---------------------------------------------------------------------------

# ``${!C}`` expands to the value of the variable whose *name* is held in C, so
# ``C=curl; ${!C} url | bash`` runs curl while the recipe carries no literal
# curl and no literal shell on the line R001/R002/H077/H069 read.  The
# tokenizer refuses to evaluate indirection (it cannot know the target
# statically), so the obfuscated line reaches the rules verbatim and every
# literal-matching rule steps over it.  Flagging the indirection itself is
# what closes that whole family at once.
#
# Only the plain ``${!name}`` form is indirection.  ``${!arr[@]}`` and
# ``${!arr[*]}`` list an array's keys, and ``${!prefix*}`` lists variable
# names by prefix - all common and benign - so the trailing ``}`` after the
# bare name is required, which excludes every subscripted or globbing form.
_INDIRECT_EXPANSION_RE = re.compile(r"\$\{!\w+\}")
_COMMAND_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||[;|&()\n]")
_ASSIGNMENT_TOKEN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_COMMAND_WRAPPER_WORDS = frozenset(
    {"env", "sudo", "command", "exec", "nohup", "time", "builtin"}
)


def _indirect_in_command_position(body: str) -> bool:
    """True when a ``${!name}`` expands to the *command word* of a segment.

    H080 is about the program the recipe runs being chosen indirectly.  The
    same expansion is ordinary data as an argument: ``printf '%s=%s' "$k"
    "${!k}" >> file`` names no command.  Split the line at the shell's
    separators, skip leading assignments and wrappers, and test the first
    remaining word.
    """
    for segment in _COMMAND_SEGMENT_SPLIT_RE.split(body):
        words = segment.split()
        index = 0
        while index < len(words):
            word = words[index]
            if _ASSIGNMENT_TOKEN_RE.match(word):
                index += 1
                continue
            if word.rsplit("/", 1)[-1] in _COMMAND_WRAPPER_WORDS:
                index += 1
                while index < len(words) and words[index].startswith("-"):
                    index += 1
                continue
            break
        if index >= len(words):
            continue
        if _INDIRECT_EXPANSION_RE.match(words[index].strip("\"'")):
            return True
    return False


def edge_indirect_expansion(ctx, add) -> None:
    """H080 predicate over the shared graph context.

    A command or shell is reached through indirect variable expansion.
    """
    diff_text = ctx.diff_text
    for line in parse_diff_lines(join_line_continuations(split_lines(diff_text))).lines:
        if line.side != "add" or line.raw.startswith("+++"):
            continue
        body = _strip_comment(line.content)
        m = _INDIRECT_EXPANSION_RE.search(body)
        if not m or not _indirect_in_command_position(body):
            continue
        add("H080", "Indirect Command Expansion", "CRITICAL", "obfuscation",
            f"a command or shell is named through indirect expansion "
            f"{m.group(0)}: {body.strip()[:80]}",
            line=_added_line_number(diff_text, body.strip()[:30]),
            body=body.strip()[:80],
            detail=f"indirect expansion {m.group(0)} hides the command it runs")
        return


def edge_hidden_fetch(ctx, add) -> None:
    """H016 predicate over the shared graph context.

    A fetch in a critical build function to a URL the ``source=()`` array
    does not declare.  Stands down for H041 (upload) and R001/R002 (pipe to
    shell) so one command is scored once.
    """
    config = ctx.config
    from .network import claims_pipe_to_shell, claims_upload_line, is_metadata_fetch

    declared = ctx.declared_urls_full
    declared_hosts = ctx.declared_hosts
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _CRITICAL_FUNCTIONS):
            continue
        body = _strip_comment(line[1:])
        if claims_upload_line(body, config):
            continue
        if claims_pipe_to_shell(body):
            continue
        if is_metadata_fetch(body):
            continue
        for url in fetch_addresses(body):
            if "://" in url:
                undeclared = normalize_url(url) not in declared
            else:
                undeclared = canonical_host(url) not in declared_hosts
            if undeclared:
                add("H016", "Hidden Network Fetch In Build", "HIGH", "network",
                    f"{ctx.scopes.label(i, _CRITICAL_FUNCTIONS)}() downloads {url}, which is not in source=()",
                    position=ctx.scopes.direct(i), url=url)
                break
        else:
            continue
        break


def edge_foreign_pkg(ctx, add) -> None:
    """H035 predicate over the shared graph context.

    An install hook invokes a foreign package manager.
    """
    context = ctx.line_context
    printed_heredoc = ctx.printed_heredoc
    foreign_re = _foreign_pkg_re(ctx.config)
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _INSTALL_HOOKS):
            continue
        if context.get(i) == "message" or i in printed_heredoc:
            continue
        body = _strip_comment(line)
        # A printer line's quoted arguments are printed, not run.  Playwright
        # prints `paru -S …` inside a `printf '%s\n' '…'`; bash's quote
        # removal leaves the format argument bare, so the message-line test
        # above misses it.  Blank the quoted literals on a printer line so
        # only a real invocation still matches.
        if _PRINTER_LINE_RE.match(line):
            body = _blank_quoted(body)
        if foreign_re.search(body):
            add("H035", "Foreign Package Manager In Install Hook", "HIGH", "installer",
                f"{ctx.scopes.label(i, _INSTALL_HOOKS)}() invokes foreign package manager: {body.strip()[:80]}",
                position=ctx.scopes.direct(i), body=body.strip()[:80])
            break


def _build_findings(diff_text, config, add, current_text=None, ctx=None) -> None:
    from .edges import build_context, run_edge_instances

    if ctx is None:
        ctx = build_context(diff_text, config, current_text=current_text)
    lines = ctx.lines
    enclosing = _classify_enclosing_function(lines)
    scopes = ctx.scopes

    high_found = False
    med_found = False
    for i, line in enumerate(lines):
        if not line.startswith("+") or not scopes.within(i, _CRITICAL_FUNCTIONS):
            continue
        body = _strip_comment(line)
        if _ENV_SUBVERSION_HIGH_RE.search(body):
            high_found = True
        if _ENV_SUBVERSION_MED_RE.search(body):
            med_found = True
    if high_found:
        add("H025", "Build Environment Subversion", "HIGH", "build",
            "LD_PRELOAD or LD_LIBRARY_PATH set inside a build function",
            detail="LD_PRELOAD or LD_LIBRARY_PATH set inside a build function")
    elif med_found:
        add("H025", "Build Environment Subversion", "MEDIUM", "build",
            "CFLAGS, LDFLAGS, MAKEFLAGS, or PATH modified inside a build function",
            detail="CFLAGS, LDFLAGS, MAKEFLAGS, or PATH modified inside a build function")

    if _code_rule_enabled(config, "H106"):
        _registry_override_findings(ctx, add)
    if _code_rule_enabled(config, "H108"):
        _service_enable_findings(ctx, add)

    wanted = ({r for r in ("H015", "H016", "H017", "H018", "H019")
               if _code_rule_enabled(config, r)}
              | {"H035", "H036"})
    if not wanted:
        return
    wants_060 = "H015" in wanted
    wants_061 = "H016" in wanted

    touched = sorted({
        fn for i, line in enumerate(lines)
        if line[:1] in ("+", "-")
        and (fn := enclosing.get(i)) in _CRITICAL_FUNCTIONS
    })
    if wants_060 and touched:
        add("H015", "Critical Build Function Modified", "INFO", "build",
            f"diff modifies {', '.join(f'{f}()' for f in touched)}",
            touched=", ".join(touched))

    if wants_061:
        run_edge_instances(ctx, add, only=frozenset({"H016"}))

    if "H017" in wanted:
        from .persistence_engine import run_persistence_instances

        run_persistence_instances(ctx, add, only=frozenset({"H017"}))

    if "H018" in wanted:
        from ..differ import urls_from_pkgbuild_text

        declared_src = (
            urls_from_pkgbuild_text(current_text)
            if current_text
            else extract_source_array_urls(diff_text)
        )
        declared_urls = {normalize_url(u) for u in declared_src}
        for i, line in enumerate(lines):
            if not line.startswith("+") or not scopes.within(i, _CRITICAL_FUNCTIONS):
                continue
            match = _UNTRUSTED_PATCH_RE.search(_strip_comment(line))
            if match:
                patch_src = match.group(1).strip()
                # Skip URL-based patches that are also declared in source=()
                if patch_src.startswith("http") and normalize_url(patch_src) in declared_urls:
                    continue
                add("H018", "Patch Applied From Outside The Build Tree", "HIGH", "integrity",
                    f"{scopes.label(i, _CRITICAL_FUNCTIONS)}() applies a patch from {patch_src[:70]}",
                    position=enclosing[i], patch_src=patch_src[:70])
                break

    if "H019" in wanted:
        from .url_engine import URLContext, run_url_instances

        run_url_instances(URLContext(diff_text, config), add,
                          only=frozenset({"H019"}))

    if "H035" in wanted:
        run_edge_instances(ctx, add, only=frozenset({"H035"}))

    if "H036" in wanted:
        # Density is measured on the raw line: reconstruction removes the
        # markers, so counting on resolved text would miss the campaign.
        # The composed HIGH requires the reconstructed line to reveal an
        # executable action (H065 composition).
        raw_lines = join_line_continuations(split_lines(diff_text))
        raw_blocks = joined_indexed(split_lines(diff_text))
        starts = [start for start, _text in raw_blocks]
        texts = [text for _start, text in raw_blocks]
        indicators = _obfuscation_indicators(config)
        density = _obfuscation_density_threshold(config)
        action_re = _reconstructs_to_action_re(config)
        for i, line in enumerate(lines):
            if not line.startswith("+") or not scopes.within(i, _CRITICAL_FUNCTIONS):
                continue
            block = bisect.bisect_right(starts, i) - 1
            raw_body = _strip_comment(texts[block] if block >= 0 else raw_lines[i])
            body = _strip_comment(line)
            count = sum(1 for p in indicators if p.search(raw_body))
            if count >= density:
                severity = "HIGH" if action_re.search(body) else "MEDIUM"
                add("H036", "Shell Obfuscation Density", severity, "obfuscation",
                    f"{scopes.label(i, _CRITICAL_FUNCTIONS)}() line has {count} obfuscation indicators: {body.strip()[:80]}",
                    position=enclosing[i], count=count, body=body.strip()[:80])
                break
