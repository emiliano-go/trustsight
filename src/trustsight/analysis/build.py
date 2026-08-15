import re

from ..config import (
    DEFAULT_FOREIGN_PKG_MANAGERS,
    DEFAULT_OBFUSCATION_INDICATORS,
    load_patterns,
    load_thresholds,
)
from ..deps import _strip_comment
from ..differ import extract_source_array_urls
from ..novelty import normalize_url
from ..rules import _classify_enclosing_function
from ..tokenizer import (
    join_line_continuations,
    reconstruct_literals,
    resolve_added_lines,
)
from .base import _experimental_enabled, mask_to_recipe


_CRITICAL_FUNCTIONS = ("build", "prepare", "check", "package")

_INSTALL_HOOKS = (
    "post_install", "post_upgrade", "pre_install",
    "pre_upgrade", "pre_remove", "post_remove",
)

_HOOK_EXEC_RE = re.compile(
    r"\b(?:eval|bash\s+-c|sh\s+-c|source\s+/|systemctl\s+enable|"
    r"chmod\s+[0-7]*[2467][0-7]{3}|chmod\s+[ugoa]*\+s|useradd|usermod|visudo)\b",
    re.IGNORECASE,
)

_UNTRUSTED_PATCH_RE = re.compile(
    r"(?:patch\b|git\s+apply\b)[^|;&]*?"
    r"(<\([^)]*\)"
    r"|https?://[^\s'\"]+"
    r"|[<\s-][ip]?\s*['\"]?/(?!usr/bin/patch)[^\s'\"$]+\.(?:patch|diff))",
    re.IGNORECASE,
)

_NETWORK_FETCH_RE = re.compile(
    r"(?:curl|wget|aria2c|git\s+clone|svn\s+(?:co|checkout)|"
    r"python\s+-c\s+.*urllib|python\s+-m\s+http)\b[^|;&]*?"
    r"(https?://[^\s|;&'\"\)]+)",
    re.IGNORECASE,
)

def _foreign_pkg_re(config=None) -> re.Pattern:
    """Compile the R081 foreign-package-manager regex from patterns.toml."""
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("foreign_pkg_managers") or DEFAULT_FOREIGN_PKG_MANAGERS
    return re.compile("|".join(frags), re.IGNORECASE)


def _obfuscation_indicators(config=None) -> list[re.Pattern]:
    """Compile the R082 obfuscation indicators from patterns.toml."""
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("obfuscation_indicators") or DEFAULT_OBFUSCATION_INDICATORS
    return [re.compile(p) for p in frags]


# R082 composition: a dense obfuscated line that reconstructs to an
# executable action is HIGH, not MEDIUM.  The action shapes mirror what
# R081 (foreign package manager), R003/R043 (decode-and-pipe) and R039
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
    """Return the R082 density threshold from thresholds.toml."""
    thresholds = load_thresholds().get("r082", {})
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
_ENV_SUBVERSION_MED_RE = re.compile(
    r"\b(?:CFLAGS|LDFLAGS|MAKEFLAGS|PATH)\s*(?:\+?=)",
)

# R009 - sudo at a command position.  `sudo` is executed, not mentioned,
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
_SUDO_CMD_START_RE = re.compile(
    r"(?:\A|[;&|]|\$\()\s*sudo(?=[\s)&|`;]|$)",
    re.IGNORECASE,
)

# `` `sudo` `` - backtick command substitution (`` `sudo -n true` ``).
_SUDO_BACKTICK_RE = re.compile(r"`\s*sudo\b", re.IGNORECASE)


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

_SCOPE_FUNCTIONS = frozenset(_CRITICAL_FUNCTIONS) | frozenset(_INSTALL_HOOKS)


def _added_line_number(diff_text: str, fragment: str) -> int | None:
    """Return the 1-based number of the first added line containing
    *fragment* (a tiny local analogue of delivery's ``_find_line``, kept
    here because ``delivery`` imports this module)."""
    pattern = re.compile(r"\+.*" + re.escape(fragment[:60]), re.IGNORECASE)
    for i, line in enumerate(diff_text.splitlines()):
        if pattern.search(line):
            return i + 1
    return None


def _sudo_findings(diff_text, config, add) -> None:
    """A build/install function executes ``sudo`` (R009, CRITICAL).

    Replaces the old ``\\bsudo\\b`` regex rule: that fired on any mention
    inside a function body, including optdepends names, path segments and
    unquoted echo strings.  The command-position test fires only when sudo
    is actually invoked, and only inside build/install functions.
    """
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
            continue
        body = _strip_comment(line[1:])
        if _SUDO_CMD_START_RE.search(body) or _backtick_sudo_executes(body):
            add("R009", "Privilege Escalation", "CRITICAL", "privilege",
                f"{enclosing[i]}() runs sudo: {body.strip()[:80]}",
                line=_added_line_number(diff_text, body.strip()[:30]),
                position=enclosing[i], body=body.strip()[:80])
            return


# R127 - a fetched script reaches a shell through an indirect path the
# pipe-to-shell regexes (R001/R002) and the R039/R040 eval / sh -c rules do
# not see: process substitution (``bash <(curl ...)``), xargs (``curl ... |
# xargs bash``), and a here-string fed by command substitution
# (``bash <<< "$(curl ...)"``).  Each still executes remote code at build
# time, so it must not be left at R010/R011's "uses curl/wget" LOW.
_REMOTE_PROC_SUBST_RE = re.compile(
    r"(?:\b(?:bash|sh|zsh|dash|source)\b|\.)\s*<\s*\(\s*(?:curl|wget)\b",
    re.IGNORECASE,
)
_REMOTE_XARGS_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|;]*\|\s*xargs\s+(?:\S+\s+)*(?:bash|sh|zsh|dash)\b",
    re.IGNORECASE,
)
_REMOTE_HERESTRING_RE = re.compile(
    r"\b(?:bash|sh|zsh|dash)\s+(?:<<<|<<)\s*[^\n]*(?:\$\{?\(|`|\$\{)",
    re.IGNORECASE,
)


def _indirect_remote_execution_findings(diff_text, config, add) -> None:
    """A fetched script is executed through an indirect shell path (R127)."""
    for line in resolve_added_lines(diff_text):
        if not line.startswith("+"):
            continue
        body = _strip_comment(line[1:])
        if _REMOTE_PROC_SUBST_RE.search(body):
            add("R127", "Remote Script Via Process Substitution", "CRITICAL",
                "execution",
                f"process substitution feeds a fetched script to a shell: {body.strip()[:80]}",
                line=_added_line_number(diff_text, body.strip()[:30]),
                body=body.strip()[:80])
            return
        if _REMOTE_XARGS_SHELL_RE.search(body):
            add("R127", "Remote Script Via xargs", "CRITICAL", "execution",
                f"fetched script piped to a shell through xargs: {body.strip()[:80]}",
                line=_added_line_number(diff_text, body.strip()[:30]),
                body=body.strip()[:80])
            return
        if _REMOTE_HERESTRING_RE.search(body):
            add("R127", "Remote Script Via Here-String", "CRITICAL", "execution",
                f"shell fed a here-string carrying command substitution: {body.strip()[:80]}",
                line=_added_line_number(diff_text, body.strip()[:30]),
                body=body.strip()[:80])
            return


# ---------------------------------------------------------------------------
# R132 - a command or shell is named through indirect variable expansion
# ---------------------------------------------------------------------------

# ``${!C}`` expands to the value of the variable whose *name* is held in C, so
# ``C=curl; ${!C} url | bash`` runs curl while the recipe carries no literal
# curl and no literal shell on the line R001/R002/R129/R121 read.  The
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


def _indirect_expansion_findings(diff_text, config, add) -> None:
    """A command or shell is reached through indirect expansion (R132)."""
    for line in join_line_continuations(diff_text.splitlines()):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = _strip_comment(line[1:])
        m = _INDIRECT_EXPANSION_RE.search(body)
        if not m:
            continue
        add("R132", "Indirect Command Expansion", "CRITICAL", "obfuscation",
            f"a command or shell is named through indirect expansion "
            f"{m.group(0)}: {body.strip()[:80]}",
            line=_added_line_number(diff_text, body.strip()[:30]),
            body=body.strip()[:80],
            detail=f"indirect expansion {m.group(0)} hides the command it runs")
        return


def _build_findings(diff_text, config, add) -> None:
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)

    high_found = False
    med_found = False
    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
            continue
        body = _strip_comment(line)
        if _ENV_SUBVERSION_HIGH_RE.search(body):
            high_found = True
        if _ENV_SUBVERSION_MED_RE.search(body):
            med_found = True
    if high_found:
        add("R070", "Build Environment Subversion", "HIGH", "build",
            "LD_PRELOAD or LD_LIBRARY_PATH set inside a build function",
            detail="LD_PRELOAD or LD_LIBRARY_PATH set inside a build function")
    elif med_found:
        add("R070", "Build Environment Subversion", "MEDIUM", "build",
            "CFLAGS, LDFLAGS, MAKEFLAGS, or PATH modified inside a build function",
            detail="CFLAGS, LDFLAGS, MAKEFLAGS, or PATH modified inside a build function")

    wanted = ({r for r in ("R060", "R061", "R062", "R063", "R064")
               if _experimental_enabled(config, r)}
              | {"R081", "R082"})
    if not wanted:
        return
    wants_060 = "R060" in wanted
    wants_061 = "R061" in wanted

    touched = sorted({
        fn for i, line in enumerate(lines)
        if line[:1] in ("+", "-")
        and (fn := enclosing.get(i)) in _CRITICAL_FUNCTIONS
    })
    if wants_060 and touched:
        add("R060", "Critical Build Function Modified", "INFO", "build",
            f"diff modifies {', '.join(f'{f}()' for f in touched)}",
            touched=", ".join(touched))

    if wants_061:
        # Imported here rather than at module scope: network imports this
        # module for the function-name tuples, so the dependency only runs
        # one way at import time.
        from .network import claims_upload_line, claims_pipe_to_shell

        declared = {normalize_url(u) for u in extract_source_array_urls(diff_text)}
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
                continue
            # An upload to a paste/file-drop host is R087's finding, and
            # "downloads {url}" would describe it wrongly as well as score
            # the same command twice.  The same double-count applies when
            # the fetch is piped into a shell: executing remote code is
            # R001/R002's claim, and R061 standing down keeps one command
            # scored once no matter how many rules could describe it.
            if claims_upload_line(_strip_comment(line[1:]), config):
                continue
            if claims_pipe_to_shell(_strip_comment(line[1:])):
                continue
            for match in _NETWORK_FETCH_RE.finditer(line):
                url = match.group(1)
                if normalize_url(url) not in declared:
                    add("R061", "Hidden Network Fetch In Build", "HIGH", "network",
                        f"{enclosing[i]}() downloads {url}, which is not in source=()",
                        position=enclosing[i], url=url)
                    break
            else:
                continue
            break

    if "R062" in wanted:
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _INSTALL_HOOKS:
                continue
            body = _strip_comment(line)
            if _NETWORK_FETCH_RE.search(body) or _HOOK_EXEC_RE.search(body):
                add("R062", "Install Hook Fetches Or Executes", "HIGH", "installer",
                    f"{enclosing[i]}() runs as root and contains: {body.strip()[:80]}",
                    position=enclosing[i], body=body.strip()[:80])
                break

    if "R063" in wanted:
        declared_urls = {normalize_url(u) for u in extract_source_array_urls(diff_text)}
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
                continue
            match = _UNTRUSTED_PATCH_RE.search(_strip_comment(line))
            if match:
                patch_src = match.group(1).strip()
                # Skip URL-based patches that are also declared in source=()
                if patch_src.startswith("http") and normalize_url(patch_src) in declared_urls:
                    continue
                add("R063", "Patch Applied From Outside The Build Tree", "HIGH", "integrity",
                    f"{enclosing[i]}() applies a patch from {patch_src[:70]}",
                    position=enclosing[i], patch_src=patch_src[:70])
                break

    if "R064" in wanted:
        before = extract_source_array_urls(diff_text, side="before")
        after = extract_source_array_urls(diff_text, side="after")
        for url in sorted(before):
            if not url.startswith("https://"):
                continue
            if url.replace("https://", "http://", 1) in after:
                add("R064", "Source URL Downgraded To HTTP", "MEDIUM", "network",
                    f"source URL downgraded from https to http: {url[:70]}",
                    url=url[:70])
                break

    if "R081" in wanted:
        foreign_re = _foreign_pkg_re(config)
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _INSTALL_HOOKS:
                continue
            body = _strip_comment(line)
            if foreign_re.search(body):
                add("R081", "Foreign Package Manager In Install Hook", "HIGH", "installer",
                    f"{enclosing[i]}() invokes foreign package manager: {body.strip()[:80]}",
                    position=enclosing[i], body=body.strip()[:80])
                break

    if "R082" in wanted:
        # Density is measured on the raw line: reconstruction removes the
        # markers, so counting on resolved text would miss the campaign.
        # The composed HIGH requires the reconstructed line to reveal an
        # executable action (R117 composition).
        raw_lines = join_line_continuations(diff_text.splitlines())
        indicators = _obfuscation_indicators(config)
        density = _obfuscation_density_threshold(config)
        action_re = _reconstructs_to_action_re(config)
        for i, line in enumerate(lines):
            if not line.startswith("+") or enclosing.get(i) not in _CRITICAL_FUNCTIONS:
                continue
            raw_body = _strip_comment(raw_lines[i])
            body = _strip_comment(line)
            count = sum(1 for p in indicators if p.search(raw_body))
            if count >= density:
                severity = "HIGH" if action_re.search(body) else "MEDIUM"
                add("R082", "Shell Obfuscation Density", severity, "obfuscation",
                    f"{enclosing[i]}() line has {count} obfuscation indicators: {body.strip()[:80]}",
                    position=enclosing[i], count=count, body=body.strip()[:80])
                break


# ---------------------------------------------------------------------------
# R117 - obfuscated literal reconstructed
# ---------------------------------------------------------------------------

# A revealed run this long is a word - a command name, a host, a flag.  A
# shorter one is punctuation, and ``$'\n'``/``$'\t'`` in a sed or awk program
# is ordinary shell, not a campaign marker.
_REVEALED_RUN_RE = re.compile(r"[!-~]{3,}")

# Ordinary quoted data (``depends=('glibc' 'foo')``) is not obfuscation, but
# quote stripping would make it look as if something was hidden.  Only report
# R117 when the original line carried one of the reconstruction targets.
_OBFUSCATION_MARKER_RE = re.compile(
    r"(?<=\w)(?:''|\"\")(?=\w)"          # empty-quote concat: b''u''n
    r"|\$\(\s*printf\s+['\"]"           # $(printf 'literal')
    r"|\$'"                                # ANSI-C quote (also: fully=False)
    r"|\w['\"][^'\"\s]*['\"]"          # partial quoting, left-glued
    r"|['\"][^'\"\s]*['\"]\w",        # partial quoting, right-glued
    re.IGNORECASE,
)


def _reconstruction_findings(diff_text, config, add) -> None:
    """Report that a line was read in reconstructed form (R117).

    The tokenizer already rebuilds the four obfuscation forms so that
    R081/R003/R039 match on what the line *means* rather than on how it is
    spelled.  Doing that silently would leave the report describing text the
    file does not contain, so the reconstruction is itself a reported fact:
    weight 0, no score, but the reviewer is told which line was rewritten and
    into what before any other rule quoted it.

    A literal that could *not* be rebuilt (a malformed ``$'``) is reported
    too, and as the inconclusive case - unreconstructable input is never
    read as clean (plan §3.1).
    """
    raw_lines = join_line_continuations(diff_text.splitlines())
    for line in raw_lines:
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = _strip_comment(line[1:])
        rebuilt, fully = reconstruct_literals(body)
        if not fully:
            # An ANSI-C quote that survived reconstruction is the
            # inconclusive case, whether or not anything else on the line
            # was rebuilt - so this is tested before the "nothing changed"
            # exit, which a wholly unreconstructable line also takes.
            add("R117", "Obfuscated Literal Reconstructed", "INFO", "obfuscation",
                f"line carries a literal that could not be reconstructed: {body.strip()[:80]}",
                detail="obfuscated literal could not be fully reconstructed",
                reconstructed=False, body=body.strip()[:80])
            return
        if rebuilt == body:
            continue
        if not _OBFUSCATION_MARKER_RE.search(body):
            continue
        revealed = [
            token for token in _REVEALED_RUN_RE.findall(rebuilt)
            if token not in body
        ]
        if not revealed:
            continue
        add("R117", "Obfuscated Literal Reconstructed", "INFO", "obfuscation",
            f"obfuscated literal reconstructs to {revealed[0][:40]!r}: {body.strip()[:80]}",
            detail=f"obfuscated literal reconstructs to {revealed[0][:40]!r}",
            reconstructed=True, revealed=revealed[0][:40], body=body.strip()[:80])
        return


# ---------------------------------------------------------------------------
# R131 - the recipe overrides the distribution build flags
# ---------------------------------------------------------------------------

_BUILD_FLAG_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+|declare\s+-x\s+)?"
    r"(CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|RUSTFLAGS|MAKEFLAGS)\s*(\+?=)\s*(.*)$"
)

# Turning one of these off removes a mitigation makepkg.conf turned on.
# ``-D_FORTIFY_SOURCE=0``/``-U_FORTIFY_SOURCE`` are the disabling spellings;
# a package raising the level is not weakening anything.
_HARDENING_OFF_RE = re.compile(
    r"-fno-stack-protector|-U_FORTIFY_SOURCE|-D_FORTIFY_SOURCE\s*=\s*0"
    r"|-fno-PIE\b|-fno-pie\b|-no-pie\b|-fno-PIC\b|-fno-pic\b"
    r"|-fcf-protection\s*=\s*none|-fno-stack-clash-protection"
    r"|-z\s*execstack|-z\s*norelro|-Wl,-z,execstack|-Wl,-z,norelro",
    re.IGNORECASE,
)


def _build_flag_findings(diff_text, config, add) -> None:
    """The recipe replaces or weakens the distribution's build flags (R131).

    makepkg exports a hardened flag set (stack protector, FORTIFY_SOURCE,
    PIE, RELRO).  A recipe that *appends* to it keeps those; one that
    assigns over it silently drops every mitigation the distribution
    configured, and one that spells out a disabling flag drops a named one.
    Either way the binary a user installs is built with weaker mitigations
    than the same source built through the normal path, and nothing in the
    package metadata says so.

    Only the recipe's own lines count: a vendored Makefile or configure
    fragment inside a shipped patch is not the packager's assignment.

    Kept off R070's evidence: R070 reports that a build function *modified*
    the environment, which is the weaker claim and already covers the
    in-function case.  R131 adds the two things R070 does not say - a named
    mitigation being switched off (HIGH, wherever it appears) and a
    top-level replacement of the whole set (MEDIUM), which R070 cannot see
    because it is scoped to build functions and which also runs at parse
    time, before any build step.
    """
    lines = mask_to_recipe(join_line_continuations(diff_text.splitlines()))
    enclosing = _classify_enclosing_function(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = _strip_comment(line[1:])
        match = _BUILD_FLAG_ASSIGN_RE.match(body)
        if not match:
            continue
        variable, operator, value = match.group(1), match.group(2), match.group(3)
        if _HARDENING_OFF_RE.search(value):
            add("R131", "Build Flags Weakened", "HIGH", "integrity",
                f"{variable} disables a hardening default: {value.strip()[:70]}",
                line=i + 1, variable=variable, value=value.strip()[:70],
                detail=f"{variable} disables a hardening default")
            return
        # A value that carries no literal flag token (``CFLAGS="${_cflags[@]}"``)
        # is a set this rule cannot read: whether it still contains the
        # distribution's flags is not visible here, and claiming a
        # replacement would be claiming more than the diff shows.
        if (
            enclosing.get(i) is None
            and operator == "="
            and not re.search(r"\$\{?" + variable + r"\b", value)
            and re.search(r"(?:^|\s|[\"'])-[A-Za-z]", value)
        ):
            add("R131", "Build Flags Weakened", "MEDIUM", "integrity",
                f"{variable} is replaced at the top level rather than "
                f"extended, dropping the makepkg.conf set: {value.strip()[:70]}",
                line=i + 1, variable=variable, value=value.strip()[:70],
                detail=f"{variable} replaces the distribution flag set at parse time")
            return
