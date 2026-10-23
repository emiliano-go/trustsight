"""Extracted from delivery.py: _write_exec."""

import os
import re
from ...config import (
    NETWORK_CLIENT as _NETWORK_CLIENT,
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ..build import (
    _INTERPRETER_FETCH,
)
from ._common import _BUILD_FUNCTIONS, _CMD_START, _EXECUTION_RE, _IMPLICIT_BUILD_INPUTS, _is_directory_path, _norm_path

__all__ = ['_CLONE_DEST_RE', '_COMMAND_ARG_DRIVER_RE', '_DEFAULT_DEST_RE', '_DRIVER_CHDIR_RE', '_DRIVER_INPUT_FLAG_RE', '_FETCH_CLIENT_RE', '_FETCH_OUTPUT_RE', '_NON_FILE_FETCH_CLIENTS', '_PACKAGE_MANAGER_FETCH_RE', '_FETCH_SCOPE_FUNCTIONS', '_INTERPRETER_OUTPUT_RE', '_LINE_URL_RE', '_OPERAND_DRIVER_RE', '_OUTPUT_FLAG_CLIENTS', '_PHASE_RANK', '_PKGDIR_LINE_RE', '_PROC_SUBST_STDIN_RE', '_SOURCE_EXEC_RE', '_body_references', '_body_under_dir', '_clone_destinations', '_collect_executions', '_collect_fetch_outputs', '_declared_source_urls', '_driver_commands']

_DRIVER_CHDIR_RE = re.compile(
    r"\b(?:g?make|cmake|ninja|meson)\b[^;&|\n]*?\s-(?:C|S)\s*"
    r"((?:\"[^\"]+\"|'[^']+'|[^\s;&|]+))",
    re.IGNORECASE,
)

_DRIVER_INPUT_FLAG_RE = re.compile(
    r"\b(?:g?make|cmake|ninja|meson|makepkg|ansible-playbook)\b"
    r"[^;&|\n]*?\s-(?:f|p|P|-file|-makefile)[=\s]+"
    r"((?:\"[^\"]*\"|'[^']*'|[^\s;&|])+)",
    re.IGNORECASE,
)

_COMMAND_ARG_DRIVER_RE = re.compile(
    r"\b(?:expect|script|tmux|screen|su|runuser|setpriv|systemd-run|at|batch"
    r"|watch|entr|xdotool|ssh|dtach|abduco|flock|torify|torsocks)\b"
    r"[^;&|\n]*?"
    r"(?:\"(?P<dq>[^\"]{1,400})\"|'(?P<sq>[^']{1,400})')",
    re.IGNORECASE,
)

_OPERAND_DRIVER_RE = re.compile(
    r"\bfind\b[^;&|\n]*?-(?:i?name|path)\s+[\"']?(?P<pattern>[^\"'\s;&|]+)"
    r"[^;&|\n]*?-exec(?:dir)?\s+(?P<findcmd>[^;\n]*?)(?:\\;|\+|$)"
    # The flags are captured as a run rather than matched optionally: a
    # lazy span happily skipped `-I{}` and left it inside the command,
    # which then had no command position to start from.
    r"|\bxargs\b(?P<flags>(?:\s+-\S+)*)\s+(?P<xargscmd>[^;\n|]+)",
    re.IGNORECASE,
)

def _driver_commands(body: str) -> list[str]:
    """Command text a driver on *body* will run.

    Returned as strings for the caller to re-scan, so one execution
    vocabulary answers for both the direct and the driver-invoked spelling
    rather than a second list that can drift from the first.
    """
    found: list[str] = []
    for match in _COMMAND_ARG_DRIVER_RE.finditer(body):
        inner = match.group("dq") or match.group("sq")
        if inner:
            # `spawn bash s.sh` - expect's own verb wraps the command again.
            found.append(re.sub(r"^\s*spawn\s+", "", inner))
    for match in _OPERAND_DRIVER_RE.finditer(body):
        command = match.group("findcmd") or match.group("xargscmd")
        if not command:
            continue
        flags = match.groupdict().get("flags") or ""
        replace_token = re.search(r"-I\s*(\S+)", flags)
        token = replace_token.group(1) if replace_token else "{}"
        pattern = match.group("pattern")
        if pattern is None:
            # `xargs` reads its operands from the pipeline, so the names are
            # on the *left* of the bar: `printf "s.sh" | xargs -I{} bash {}`
            # runs `bash s.sh`.  Substituting a bare `*` would name every
            # file, which is a claim about none of them.
            left = body.split("|", 1)[0]
            pattern = next(
                (w.strip("\"'") for w in reversed(left.split())
                 if "." in w and not w.startswith("-")),
                None,
            )
        if pattern is None:
            continue
        found.append(command.replace(token, pattern).replace("{}", pattern))
    return found

def _collect_executions(body: str) -> list[str]:
    """Return normalised paths executed or compiled on *body*.

    A build driver is an execution of its input file.  `curl -o Makefile
    URL` followed by `make` fetches a script and runs it, and neither half
    was paired with the other: `make` matched no execution pattern, so H082
    saw a download and nothing more.  The driver's *implicit* input is
    resolved the same way `_implicit_build_input` resolves it for committed
    files - the difference is only where the file came from.
    """
    paths: list[str] = []
    for match in _DRIVER_INPUT_FLAG_RE.finditer(body):
        path = _norm_path(match.group(1))
        if path and not _is_directory_path(path):
            paths.append(path)
    # `-C dir` moves the driver's implicit input into that directory, which
    # is how `git clone ... r` followed by `make -C r` builds the cloned
    # tree without ever naming a file in it.
    directory = _DRIVER_CHDIR_RE.search(body)
    prefix = (_norm_path(directory.group(1)).rstrip("/") + "/") if directory else ""
    for pattern, candidates in _IMPLICIT_BUILD_INPUTS:
        if pattern.search(body):
            paths.extend(prefix + name for name in candidates)
    for m in _EXECUTION_RE.finditer(body):
        for g in m.groups():
            if g and not _is_directory_path(g):
                paths.append(_norm_path(g))
    # A driver's command is scanned with the same vocabulary, once.  Bounded
    # to one level: a driver running a driver is not a shape worth the
    # recursion, and unbounded re-entry on attacker text is not a bound.
    for command in _driver_commands(body):
        for m in _EXECUTION_RE.finditer(command):
            for g in m.groups():
                if g and not _is_directory_path(g):
                    paths.append(_norm_path(g))
    return paths

_FETCH_CLIENT_RE = re.compile(
    r"\b(?:" + _NETWORK_CLIENT + r")\b|(?:" + _INTERPRETER_FETCH + r")",
    re.IGNORECASE,
)

#: A package manager resolving its own registry.  W002 reports the
#: registry-dependency gap; pairing `cargo fetch` with a build script as an
#: "unattributed fetch then execute" doubles the claim and was a live
#: false positive (ankaios).
_PACKAGE_MANAGER_FETCH_RE = re.compile(
    r"\b(?:cargo|npm|yarn|pnpm|pip|pip3|poetry|python\s+-m\s+pip|go|"
    r"composer|gem|bundle|mix|dotnet|mvn|gradle|cabal|stack|opam|conan)"
    r"\s+(?:fetch|install|download|sync|ci|get|tidy)\b",
    re.IGNORECASE,
)

#: DNS/metadata clients.  They resolve a name; they do not download a file
#: that a later line can execute.  `host` also matches inside `host-tuple`.
_NON_FILE_FETCH_CLIENTS = frozenset({
    "host", "dig", "nslookup", "drill", "kdig", "whois", "ping",
    "traceroute", "tracepath", "mtr",
})

_INTERPRETER_OUTPUT_RE = re.compile(
    r"(?:urlretrieve|getstore|open|File\.write|writeFileSync|copyfileobj)"
    r"\s*\([^)]{0,200}?"
    # A path shape, not "anything between quotes": the closing quote of the
    # URL argument and the opening quote of the next one are separated by a
    # comma, which read as a one-character filename.
    r"[\"\']((?!https?://)[\w./~$@+-]{1,120})[\"\']",
    re.IGNORECASE,
)

_OUTPUT_FLAG_CLIENTS = (
    r"curl|wget2?|aria2c|axel|lftp|ncftp(?:get)?|snarf"
    # Store clients that take an output flag too.  `ipfs get CID -o x.sh`
    # names its destination the same way curl does; the address it fetched
    # from is a content identifier rather than a URL, which is why nothing
    # else in the chain could attribute it.
    r"|ipfs|b2|swift|restic|borg"
)

_LINE_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]{0,20}://[^\s;&|'\"]+",
                          re.IGNORECASE)

_FETCH_OUTPUT_RE = re.compile(
    # Lower-case `-o` takes an argument for every client here, glued
    # (`-o"f"`, `-o$f`) or spaced.  `(?![-\s])` keeps `-o-` (stdout) and a
    # bare flag from being read as a filename.  `(?-i:o)` matters: the
    # pattern is compiled IGNORECASE, so a plain `o` also matched curl's
    # argument-less capital `-O` and captured the *address* as a filename -
    # `curl -O "$(cat u)"` read as "the fetch wrote $(cat u)", which
    # suppressed the unattributed arm and the pairing with the file the
    # command actually fetched.
    r"\b(?:" + _OUTPUT_FLAG_CLIENTS + r")\b"
    r"[^;&|]*?"
    r"\s-[A-Za-z]*(?-i:o)(?:=?\s*)"
    r"(?P<path>(?!-)(?:\"[^\"]*\"|'[^']*'|\\.|[^\s;&|])+)"
    # wget's capital `-O` is an output document (lower-case `-o` is its log
    # file).  curl's capital `-O` takes no argument (save as the URL
    # basename) and `-OJ` is its cluster, so curl is deliberately absent
    # from this arm.  `(?-i:O)` keeps wget's log file out of it.
    r"|\bwget2?\b[^;&|]*?"
    r"\s-[A-Za-z]*(?-i:O)(?:=?\s*)"
    r"(?P<wget_path>(?!-)(?:\"[^\"]*\"|'[^']*'|\\.|[^\s;&|])+)"
    r"|\b(?:" + _OUTPUT_FLAG_CLIENTS + r")\b"
    r"[^;&|]*?\s--output(?:\s+|=)"
    r"(?P<long_path>(?!-)(?:\"[^\"]*\"|'[^']*'|\\.|[^\s;&|])+)"
    r"|\bwget2?\b[^;&|]*?\s--output-document(?:\s+|=)"
    r"(?P<doc_path>(?!-)(?:\"[^\"]*\"|'[^']*'|\\.|[^\s;&|])+)"
    r"|\b(?:" + _OUTPUT_FLAG_CLIENTS + r")\b"
    r"[^;&|]*?>\s*"
    r"(?P<redir_path>(?:\"[^\"]*\"|'[^']*'|\\.|[^\s;&|])+)"
    # A redirect that belongs to a later stage of the same pipeline:
    # `printf … | openssl s_client … | sed … > stage` writes the fetch's
    # bytes through the pipeline into the file, but the `>` sits after a
    # pipe, which the close-coupled arm above refuses to cross.  The
    # caller already gated on a fetch client being on the line at all.
    # Only a redirect reaching end-of-line counts: a `>` inside a quoted
    # argument (`printf 'a > b'`) is data.
    r"|(?:\A|[^0-9>&])>+\s*"
    r"(?P<pipeline_redir>(?:\"[^\"]*\"|'[^']*'|\\.|[^\s;&|])+)\s*$"
    # A stdout-dash fetch piped to tee names its file there:
    # `wget -qO- URL | tee stage.sh` and `curl -o- URL | tee f`.
    r"|\b(?:curl|wget2?|aria2c|axel)\b[^;&|]*?"
    r"(?:-[A-Za-z]*[oO]-|/dev/stdout)"
    r"[^;&|]*?\|\s*tee\s+(?:-\S+\s+)*"
    r"(?P<tee_path>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)"
    # Directory-only flags.  The file keeps the URL's basename inside the
    # directory; with an indirect URL the basename is not derivable, and
    # the unattributed arm (H082) pairs the later execution instead.
    r"|\bcurl\b[^;&|]*?\s--output-dir(?:\s+|=)"
    r"(?P<outdir>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)"
    r"|\bwget2?\b[^;&|]*?(?:\s-P\s+|\s--directory-prefix(?:\s+|=))"
    r"(?P<wget_dir>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)"
    r"|\baria2c\b[^;&|]*?\s-d\s+"
    r"(?P<aria_dir>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)"
    # `scp host:/x.sh s.sh` and `rsync URL s.sh` name the destination
    # positionally - there is no output flag to key on, and the last
    # argument is the file the next line runs.
    r"|\b(?:scp|rsync|sftp)\b(?:\s+-\S+)*\s+\S+\s+"
    r"(?P<dest>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)\s*$"
    # Object stores name source and destination positionally, like scp.
    # `moveto`/`move`/`bisync`/`copyurl` were the verbs the harness proved
    # missing: each still lands bytes on the machine.
    r"|\b(?:s3cmd" + _SUBCOMMAND_OPTS + r"\s+(?:get|cp|sync)"
    r"|aws\s+s3" + _SUBCOMMAND_OPTS + r"\s+(?:cp|sync|mv)"
    r"|gsutil" + _SUBCOMMAND_OPTS + r"\s+(?:cp|rsync)"
    r"|rclone" + _SUBCOMMAND_OPTS + r"\s+(?:copy|copyto|sync|moveto|move|bisync|copyurl))\b"
    r"(?:\s+-\S+)*\s+(?P<store_src>\S+)\s+"
    r"(?P<store_dest>(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>])+)\s*$"
    # `ipfs get CID` writes a directory named for the CID.
    r"|\bipfs" + _SUBCOMMAND_OPTS + r"\s+get\b(?:\s+-\S+)*\s+"
    r"(?P<ipfs_cid>[A-Za-z0-9]+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_FETCH_SCOPE_FUNCTIONS = frozenset(_BUILD_FUNCTIONS) | {"pkgver"}

_PHASE_RANK = {"pkgver": 0, "prepare": 1, "build": 2, "check": 3, "package": 4}

_PKGDIR_LINE_RE = re.compile(r"\$\{?pkgdir\}?")

_PROC_SUBST_STDIN_RE = re.compile(
    r"\b(?:python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|fish|julia"
    r"|Rscript|bun|deno|escript|fennel|zx|guile|racket|pwsh|elixir"
    r"|ts-node|gjs|csi|bb|babashka|clj|janet)\b"
    r"(?:\s+-{1,2}[A-Za-z-]*)*\s*<\s*<\(([^)]*)\)",
    re.IGNORECASE,
)

_CLONE_DEST_RE = re.compile(
    r"\b(?:git\s+clone|hg\s+clone|bzr\s+branch|svn\s+(?:co|checkout|export)"
    r"|fossil\s+clone|darcs\s+get)\b"
    r"(?:\s+--?\S+)*"
    r"\s+(?P<url>[a-z][a-z0-9+.-]*://\S+|\S+@\S+:\S+|\S+\.git)"
    r"(?:\s+(?P<dir>\"[^\"]+\"|'[^']+'|[^\s;&|<>-][^\s;&|<>]*))?",
    re.IGNORECASE,
)

def _clone_destinations(body: str) -> list[str]:
    """Directories a VCS checkout on *body* fills from a remote.

    Without an explicit operand the directory is the remote's basename, the
    same one the client itself uses.
    """
    destinations: list[str] = []
    for match in _CLONE_DEST_RE.finditer(body):
        raw_dir = match.group("dir")
        if raw_dir:
            destinations.append(_norm_path(raw_dir).rstrip("/"))
            continue
        url = match.group("url").rstrip("/")
        name = url.rsplit("/", 1)[-1]
        if "@" in url and "://" not in url:
            # `git@host:owner/repo.git` - the path follows the colon.
            name = url.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
        name = name.split("#", 1)[0].split("?", 1)[0]
        if name.endswith(".git"):
            name = name[:-4]
        if name:
            destinations.append(_norm_path(name))
    return destinations

_DEFAULT_DEST_RE = re.compile(
    r"\b(?:wget2?|aria2c|axel)\b(?![^;&|\n]*\s-(?:[A-Za-z]*[oO]\s|-output))"
    r"[^;&|\n]*?([a-z][a-z0-9+.-]*://[^\s;&|'\"]+)"
    # `(?-i:O)`: compiled IGNORECASE, a plain `O` also matched curl's
    # lowercase `-o`, so an explicit output was also read as a default one.
    r"|\bcurl\b[^;&|\n]*?\s-[A-Za-z]*(?-i:O)\b"
    r"[^;&|\n]*?([a-z][a-z0-9+.-]*://[^\s;&|'\"]+)",
    re.IGNORECASE,
)

def _declared_source_urls(diff_text: str) -> frozenset[str]:
    """Scheme URLs declared in ``source=()`` on the post-diff side.

    A scheme URL on a fetch line that is *also* a declared source is a
    decoy argument: makepkg fetches declared sources itself, so a recipe has
    no ordinary reason to download one by hand and then execute a file the
    grammar did not name.  Such a URL must not produce a derived output
    path, or the fetch is attributed to the decoy instead of its real
    address.
    """
    from ...differ import extract_source_array_urls

    return frozenset(extract_source_array_urls(diff_text))

def _collect_fetch_outputs(body: str,
                           declared_urls: frozenset[str] = frozenset()) -> list[str]:
    """Normalised paths a network client on *body* writes to a file.

    A path derived from a URL is discarded when that URL is declared in
    ``source=()`` (see :func:`_declared_source_urls`): the decoy names no
    output of *this* fetch.
    """
    from ...differ import _clean_url

    paths: list[str] = []
    if not _FETCH_CLIENT_RE.search(body):
        return paths
    line_url = _LINE_URL_RE.search(body)
    if line_url and _clean_url(line_url.group(0)) in declared_urls:
        line_url = None
    for m in _FETCH_OUTPUT_RE.finditer(body):
        raw = (m.group("path") or m.group("wget_path")
               or m.group("long_path") or m.group("doc_path")
               or m.group("redir_path") or m.group("pipeline_redir")
               or m.group("tee_path")
               or m.group("dest") or m.group("store_dest") or "")
        # A URL is a source, not a destination.  `curl -O URL` takes no
        # argument, so whatever follows it is the address being fetched.
        if raw and "://" not in raw and not raw.startswith("/dev/"):
            path = _norm_path(raw)
            if path:
                paths.append(path)
        # A directory-only flag keeps the URL's basename; with an indirect
        # URL the name is unknown and the unattributed arm pairs instead.
        outdir = (m.group("outdir") or m.group("wget_dir")
                  or m.group("aria_dir"))
        if outdir and line_url:
            base = (line_url.group(0).rstrip("/").rsplit("/", 1)[-1]
                    .split("?")[0])
            if base:
                paths.append(_norm_path(
                    outdir.rstrip("/").strip("\"'") + "/" + base))
        # A store destination that is a directory keeps the source's
        # basename: `aws s3 cp s3://b/s.sh .` writes ./s.sh, and the old
        # capture recorded only "." so the later `bash s.sh` never paired.
        store_src, store_dest = m.group("store_src"), m.group("store_dest")
        if (store_src and store_dest
                and not ("://" in store_src
                         and _clean_url(store_src) in declared_urls)):
            dest = store_dest.strip("\"'")
            if dest in (".", "./") or dest.endswith("/"):
                base = (store_src.rstrip("/").rsplit("/", 1)[-1]
                        .split("?")[0].split("#")[0])
                if base:
                    paths.append(_norm_path(base))
        cid = m.group("ipfs_cid")
        if cid:
            paths.append(cid)
    for m in _INTERPRETER_OUTPUT_RE.finditer(body):
        path = _norm_path(m.group(1))
        if path:
            paths.append(path)
    for m in _DEFAULT_DEST_RE.finditer(body):
        url = m.group(1) or m.group(2) or ""
        if "://" in url and _clean_url(url) in declared_urls:
            continue
        base = url.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
        if base and "." in base:
            paths.append(_norm_path(base))
    return paths

def _body_references(body: str, names) -> bool:
    """True when *body* names one of *names* as a whole token."""
    for name in names:
        base = os.path.basename(name)
        if base and re.search(rf"(?<![\w.-]){re.escape(base)}(?![\w.-])",
                              body):
            return True
    return False

def _body_under_dir(body: str, directories) -> bool:
    """True when *body* names a path under one of *directories*."""
    for directory in directories:
        if directory and re.search(
                rf"(?<![\w.-]){re.escape(directory)}/", body):
            return True
    return False

_SOURCE_EXEC_RE = re.compile(
    _CMD_START + r"(?:"
    # `(?![<>])`: a redirect is not a filename argument. Without it this
    # arm captured the `<` of `sh < file` and the redirect arm below never
    # got a turn - the same trap `_EXECUTION_RE` documents.
    r"(?:/(?:usr/)?bin/)?(?:bash|sh|zsh|dash|ksh|python3?|perl|ruby|node|php|lua(?:jit)?"
    r"|tclsh|wish|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh"
    r"|julia|Rscript|bun|deno|escript|fennel|zx|guile|racket|pwsh|elixir"
    r"|ts-node|gjs|csi|bb|babashka|clj|janet)\s+(?![<>])"
    # A quoted path may contain a space (`bash "$srcdir/stage .sh"`,
    # where the declared source URL itself carries the space): the quote
    # bounds the argument, so the space is part of the filename.  A quote
    # may also close before the path ends (`"$srcdir"/stage.sh`), and the
    # glued suffix belongs to the same token.
    r"(\"[^\s;&|]*\"[^\s;&|]*|'[^'\s;&|]*'[^\s;&|]*|[^\s;&|]+)"
    r"|source\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))"
    r"|\.\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))"
    r")"
    # A bare `./script` is a command, so it must be at a command position.
    # Without the anchor the bare `\./` matched anywhere, capturing `647.patch`
    # from the argument `../647.patch` (and `./src` from `grep ./src`).
    r"|" + _CMD_START + r"\./(\S+)"
    # `sh < file` - the interpreter reads the script from its stdin.
    # `(?!\(|<)` keeps process substitution and here-strings out: those are
    # different constructs that H075 owns.
    r"|" + _CMD_START + r"(?:/(?:usr/)?bin/)?(?:bash|sh|zsh|dash|ksh|python3?|perl|ruby"
    r"|node|php|lua(?:jit)?|tclsh|wish|fish|tcsh|csh|rc|es|elvish"
    r"|xonsh|nu|osh|julia|Rscript|bun|deno|escript|fennel|zx|guile"
    r"|racket|pwsh|elixir|ts-node|gjs|csi|bb|babashka|clj|janet)"
    r"\s*<\s*(?!\(|<)(\S+)"
    # A bare `"$srcdir/x"` in command position: the file is the command.
    r"|(?:\A\s*+|[;&|]\s*+)[\"']?(\$\{?(?:srcdir|startdir)\}?/[^\"'\s;&|]+)"
    # `make -f downloaded.mk` runs the recipes in a downloaded file.
    r"|" + _CMD_START + r"(?:g?make|cmake)\s+(?:-\S+\s+)*-f\s+(\S+)",
    re.IGNORECASE,
)
