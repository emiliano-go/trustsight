"""- network-surface rules.

H031/H033/H034/H071 share one question: does the PKGBUILD's declared or
executed network surface carry an injection or a covert channel?  H031 now
lives in :mod:`trustsight.analysis.url_engine`; the remaining rules here are
code rules because each needs more than a regex:

- H033 needs both sides of the diff: which commit a repository ref resolved
  to before, and which one it resolves to now;
- H034 needs the raw source array with its scheme tokens (``git+https://``,
  ``svn://``, ...);
- H071 needs config-driven endpoint and client lists plus command position.

H034 is additive evidence for H043's ``foreign_fetch`` stage and H071 for
its ``exfil`` stage; all four are deliberately quiet so the benign corpus
never cries wolf.
"""

import re

from ..config import (
    ANY_EXECUTOR,
    DEFAULT_COVERT_EGRESS_CLIENTS,
    DEFAULT_COVERT_EGRESS_ENDPOINTS,
    DEFAULT_PARSE_TIME_FETCH,
    DEFAULT_PASTE_HOSTS,
    DEFAULT_UPLOAD_FLAGS,
    DEFAULT_SOURCE_SCHEMES,
    load_hosts,
    load_patterns,
)
from ..deps import _strip_comment
from ..line_lex import lex_lines
from ..tokenizer import join_line_continuations, resolve_added_lines
from .base import compile_configured_patterns, iter_scheme_urls, mask_to_recipe
from .version import any_version_scalar_moved
from .build import _SCOPE_FUNCTIONS
from .delivery import _SRCINFO_SOURCE_RE, _find_line
from ..diffdoc import parse_diff_lines
from ..tokenizer import split_lines

_SOURCE_ARRAY_RE = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*\(")
# URL tokens are found by scanning for "://" (see base.iter_scheme_urls);
# the regex form was quadratic on a line with no scheme at all.
_URL_STOP_CHARS = frozenset(" \t\r\n'\")")

# ---------------------------------------------------------------------------
# Shared: source-array URL tokens
# ---------------------------------------------------------------------------


def _source_url_tokens(diff_text):
    """Yield ``(scheme, url)`` for every scheme:// token on an added source
    array line.  The per-line ``source = value`` spelling is read only
    inside a ``.SRCINFO`` section, where it is a real generated
    declaration; in PKGBUILD text makepkg never reads it."""
    from ..file_kinds import files_at_line, is_srcinfo_file

    raw = split_lines(diff_text)
    files = files_at_line(raw)
    in_array = False
    for line in parse_diff_lines(raw).lines:
        raw_line = line.raw
        if raw_line.startswith(("+++", "---", "@@")):
            continue
        if line.side == "remove":
            if in_array and ")" in raw_line:
                in_array = False
            continue
        body = line.content if line.side == "add" else raw_line
        opens_array = bool(_SOURCE_ARRAY_RE.match(body))
        scalar_source = (
            is_srcinfo_file(files.get(line.index, ""))
            and bool(_SRCINFO_SOURCE_RE.match(body))
        )
        if not in_array and not opens_array and not scalar_source:
            continue
        for scheme, url in iter_scheme_urls(body, _URL_STOP_CHARS):
            yield scheme, url
        if ")" in body:
            in_array = False
        elif opens_array:
            # No closing paren on the opener: continuation lines carry the
            # rest of the array's URLs.
            in_array = True


def _hosts(config) -> dict:
    if config and "hosts" in config:
        return config["hosts"]
    return load_hosts().get("hosts", {})


# ---------------------------------------------------------------------------
# H034 - exotic source protocol
# ---------------------------------------------------------------------------


def _source_schemes(config=None) -> frozenset[str]:
    schemes = _hosts(config).get("source_schemes") or DEFAULT_SOURCE_SCHEMES
    return frozenset(s.lower() for s in schemes)


def _exotic_protocol_findings(diff_text, config, add) -> None:
    """A source URL uses a scheme outside the configured allowlist (H034)."""
    allowed = _source_schemes(config) | _declared_dlagent_schemes(diff_text)
    for scheme, url in _source_url_tokens(diff_text):
        base = scheme.rsplit("+", 1)[-1].lower()
        if base not in allowed:
            add("H034", "Exotic Source Protocol", "MEDIUM", "network",
                f"source URL uses non-allowlisted scheme {scheme}: {url[:70]}",
                url=url[:70], scheme=scheme)
            return


# ---------------------------------------------------------------------------
# H033 - moved git ref
# ---------------------------------------------------------------------------

# A git source token, with or without a ``name::`` rename in front of it.
_GIT_URL_RE = re.compile(r"(?:git\+[a-z][a-z0-9+.\-]*://|git://)[^\s\"')]+", re.IGNORECASE)
_GIT_REF_RE = re.compile(r"#(tag|commit|branch|revision)=([^\s\"')&]+)", re.IGNORECASE)
_COMMIT_HEX_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)

# ``_commit=``/``_gitrev=``/``_sha``... - the idiom for pinning a checkout to
# one revision.  The name family is what marks it as a pin; the value must be
# a digest, so ``_revision=3`` (a packaging counter) is not one.
_PIN_VAR_RE = re.compile(
    r"^\s*(_[A-Za-z0-9_]*(?:commit|rev|revision|sha|hash)[A-Za-z0-9_]*)"
    r"\s*=\s*[\"']?([0-9a-fA-F]{7,40})[\"']?\s*(#.*)?$",
    re.IGNORECASE,
)
def _repo_base(url: str) -> str:
    return url.split("#", 1)[0].rstrip("/").lower()


def _git_refs_by_side(diff_text: str) -> dict[str, dict[str, set[tuple[str, str]]]]:
    """Map ``side -> repo -> {(ref_kind, ref_value)}`` for every git source
    token in the diff, where side is ``+``, ``-`` or ``" "`` (context)."""
    sides: dict[str, dict[str, set[tuple[str, str]]]] = {"+": {}, "-": {}, " ": {}}
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        raw = line.raw
        if raw.startswith(("+++", "---", "@@", "diff ", "index ")):
            continue
        if line.is_content:
            side = {"add": "+", "remove": "-", "context": " "}[line.side]
            body = line.content
        else:
            side = " "
            body = raw
        for url in _GIT_URL_RE.findall(body):
            match = _GIT_REF_RE.search(url)
            if match:
                sides[side].setdefault(_repo_base(url), set()).add(
                    (match.group(1).lower(), match.group(2))
                )
    return sides


def _pin_vars_by_side(diff_text: str) -> dict[str, dict[str, tuple[str, str]]]:
    """Map ``side -> variable -> (digest, trailing comment)`` for pin
    assignments on changed lines."""
    sides: dict[str, dict[str, tuple[str, str]]] = {"+": {}, "-": {}}
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        if line.raw.startswith(("+++", "---")) or line.side not in ("add", "remove"):
            continue
        match = _PIN_VAR_RE.match(line.content)
        if match:
            sides["+" if line.side == "add" else "-"][match.group(1).lower()] = (
                match.group(2).lower(), (match.group(3) or "").strip()
            )
    return sides


def _pin_is_a_git_ref(var: str, haystack: str) -> bool:
    """True when *var* is interpolated into a git ref fragment.

    A digest-shaped variable used anywhere else (a checksum, an upstream
    release id) is not a checkout pin, and moving it is not this rule's
    business.
    """
    return bool(
        re.search(
            r"#(?:tag|commit|branch|revision)=\$\{?" + re.escape(var) + r"\}?",
            haystack, re.IGNORECASE,
        )
    )


def _moved_git_ref_findings(diff_text, config, add, current_text=None) -> None:
    """The commit a package builds moved while the version it declares did
    not (H033).

    A tag is a name upstream can repoint at will, so "same tag" is not the
    same code twice.  Two shapes say so from declared facts alone:

    - **the ref moved under a stable version** - the repository's commit
      pin (in the source fragment or in the ``_commit`` variable feeding it)
      changed while ``pkgver``/``pkgrel``/``epoch`` and the declared tag did
      not.  Anyone who already built this version gets different code than
      anyone who builds it now, under one version string.
    - **the pin was loosened** - a fixed ``#commit=<digest>`` became a
      ``#tag=``/``#branch=``, which upstream can move afterwards.  This one
      is not gated on the version: dropping a pin during a version bump is
      still dropping the pin.

    HIGH when a tag anchor is provably unchanged (the diff or the current
    file still declares the same ``#tag=``, or the pin line carries the same
    trailing annotation): that is literally "this tag now resolves to a
    different commit".  MEDIUM otherwise.  C003 reports the same edit as a
    neutral fact at weight 0; this rule is the git-specific reading of it.
    """
    refs = _git_refs_by_side(diff_text)
    pins = _pin_vars_by_side(diff_text)
    haystack = current_text or diff_text

    # --- pin loosened: a digest ref replaced by a movable one --------------
    for repo in set(refs["+"]) & set(refs["-"]):
        old_pinned = {v for k, v in refs["-"][repo] if k in ("commit", "revision")
                      and _COMMIT_HEX_RE.match(v)}
        new_pinned = {v for k, v in refs["+"][repo] if k in ("commit", "revision")
                      and _COMMIT_HEX_RE.match(v)}
        movable = sorted(
            f"{k}={v}" for k, v in refs["+"][repo]
            if k in ("tag", "branch") or not _COMMIT_HEX_RE.match(v)
        )
        if old_pinned and not new_pinned and movable:
            add("H033", "Moved Git Ref", "MEDIUM", "integrity",
                f"commit pin replaced by a movable ref for {repo}: {movable[0]}",
                line=_find_line(diff_text, movable[0][:40]),
                repo=repo[:70], detail=f"commit pin dropped for {movable[0]}")
            return

    # "Did the maintainer declare a new build?" - judged by the *value* of
    # pkgver, pkgrel or epoch, resolving the recipe's own variables.  This
    # used to be a lexical match for any of those token names on a changed
    # line, which disagrees with the engine both ways: an added no-op
    # `+epoch=0` silenced H033 on a real pin move, and a variable-driven bump
    # (`-_gtkver=1.2.3/+_gtkver=1.2.4`, context `pkgver=${_gtkver}`) fired it
    # on a version that did move.  Resolution, not text, is what decides.
    if any_version_scalar_moved(diff_text, current_text):
        return

    # --- ref moved under a stable version ---------------------------------
    for repo in sorted(set(refs["+"]) & set(refs["-"])):
        old_commits = {v for k, v in refs["-"][repo] if k in ("commit", "revision")
                       and _COMMIT_HEX_RE.match(v)}
        new_commits = {v for k, v in refs["+"][repo] if k in ("commit", "revision")
                       and _COMMIT_HEX_RE.match(v)}
        if not (old_commits and new_commits) or old_commits == new_commits:
            continue
        tags = (
            {v for k, v in refs["-"][repo] if k == "tag"}
            & {v for k, v in refs["+"][repo] if k == "tag"}
        ) or {v for k, v in refs[" "].get(repo, set()) if k == "tag"}
        moved = sorted(new_commits - old_commits)[0]
        if tags:
            tag = sorted(tags)[0]
            add("H033", "Moved Git Ref", "HIGH", "integrity",
                f"tag {tag} now resolves to a different commit for {repo}: "
                f"{sorted(old_commits)[0][:12]} -> {moved[:12]}",
                line=_find_line(diff_text, moved[:12]), repo=repo[:70], tag=tag[:40],
                detail=f"tag {tag} now resolves to {moved[:12]}")
        else:
            add("H033", "Moved Git Ref", "MEDIUM", "integrity",
                f"commit pin moved with no version change for {repo}: "
                f"{sorted(old_commits)[0][:12]} -> {moved[:12]}",
                line=_find_line(diff_text, moved[:12]), repo=repo[:70],
                detail=f"commit pin moved to {moved[:12]} with no version change")
        return

    # --- the same move expressed through a pin variable -------------------
    for var in sorted(set(pins["+"]) & set(pins["-"])):
        old_value, old_note = pins["-"][var]
        new_value, new_note = pins["+"][var]
        if old_value == new_value or not _pin_is_a_git_ref(var, haystack):
            continue
        anchored = bool(old_note) and old_note == new_note
        add("H033", "Moved Git Ref", "HIGH" if anchored else "MEDIUM", "integrity",
            (f"{var} moved under an unchanged {old_note.lstrip('#').strip()} annotation: "
             if anchored else f"{var} moved with no version change: ")
            + f"{old_value[:12]} -> {new_value[:12]}",
            line=_find_line(diff_text, new_value[:12]), variable=var,
            detail=f"{var} moved to {new_value[:12]}")
        return


# ---------------------------------------------------------------------------
# H071 - covert egress
# ---------------------------------------------------------------------------

_ONION_HOST_RE = re.compile(r"\b[a-z0-9-]+\.(?:onion|i2p)\b", re.IGNORECASE)
_DOH_QUERY_RE = re.compile(r"https?://[^\s'\"\)]*dns-query", re.IGNORECASE)
# DNS hostnames are at most 253 characters; bounding this avoids unbounded
# backtracking when a URL-like prefix has no path separator.
_DOH_HOST_RE = re.compile(r"https?://([a-z0-9.-]{1,253})/", re.IGNORECASE)


def _covert_clients(config) -> list[re.Pattern]:
    frags = _hosts(config).get("covert_egress_clients") or DEFAULT_COVERT_EGRESS_CLIENTS
    return [
        re.compile(r"(?:\A\s*|[;&|]\s*)(?:" + f + r")", re.IGNORECASE)
        for f in frags
    ]


def _covert_endpoints(config) -> frozenset[str]:
    endpoints = (
        _hosts(config).get("covert_egress_endpoints")
        or DEFAULT_COVERT_EGRESS_ENDPOINTS
    )
    return frozenset(e.lower() for e in endpoints)


def edge_covert_egress(ctx, add) -> None:
    """H071 predicate over the shared graph context.

    .onion/.i2p hosts, DoH endpoints or tunneling clients anywhere they have
    no packaging purpose.
    """
    diff_text = ctx.diff_text
    lines = ctx.lines
    clients = _covert_clients(ctx.config)
    endpoints = _covert_endpoints(ctx.config)

    for line in lines:
        if not line.startswith("+"):
            continue
        body = _strip_comment(line[1:])
        if _ONION_HOST_RE.search(body):
            add("H071", "Covert Egress", "HIGH", "network",
                f"source or command references an onion/i2p host: {body.strip()[:80]}",
                line=_find_line(diff_text, ".onion"), detail=".onion/.i2p host referenced")
            return
        if _DOH_QUERY_RE.search(body):
            add("H071", "Covert Egress", "HIGH", "network",
                f"DoH (DNS-over-HTTPS) query issued: {body.strip()[:80]}",
                line=_find_line(diff_text, "dns-query"), detail="DoH endpoint queried")
            return
        match = _DOH_HOST_RE.search(body)
        if match and match.group(1).lower() in endpoints:
            add("H071", "Covert Egress", "HIGH", "network",
                f"DoH endpoint {match.group(1)} queried: {body.strip()[:80]}",
                line=_find_line(diff_text, match.group(1)[:40]),
                detail=f"DoH endpoint {match.group(1)} queried")
            return

    for i, line in enumerate(lines):
        fn = ctx.scopes.direct(i)
        if not line.startswith("+") or fn not in _SCOPE_FUNCTIONS:
            continue
        body = _strip_comment(line[1:])
        for client in clients:
            if client.search(body):
                add("H071", "Covert Egress", "HIGH", "network",
                    f"{fn}() invokes a tunneling/covert client: "
                    f"{body.strip()[:80]}",
                    position=fn, body=body.strip()[:80])
                return

# ---------------------------------------------------------------------------
# H077 - network fetch at parse time
# ---------------------------------------------------------------------------


def _parse_time_fetch_patterns(config=None) -> list[re.Pattern]:
    patterns = load_patterns().get("patterns", {})
    # The config file extends the shipped list rather than replacing it:
    # it is written once at install, and a shipped client added later
    # (elinks, rsync, …) must still be recognised in existing configs.
    # `sync_rules` appends missing rules the same way.
    frags = list(dict.fromkeys(
        (patterns.get("parse_time_fetch") or []) + DEFAULT_PARSE_TIME_FETCH))
    # Each fragment already carries its own command-position prefix.  It
    # must hold exactly one ``\s*``: two adjacent unbounded spaces let the
    # engine split a whitespace run at every position, which is quadratic on
    # a full line (A5/A14).  The shipped defaults are written that way; an
    # operator's fragment is audited by ``scripts/regex_audit.py``.
    return [re.compile(f, re.IGNORECASE) for f in frags]


# Assignments whose value happens to name a downloader: `DLAGENTS=(...)`,
# `_curl=curl`, `DLAGENTS+=('http::/usr/bin/curl ...')`.  makepkg's own
# download-agent configuration is a declaration, not an invocation, and it
# is the single largest benign use of these names at the top level.
_ASSIGNMENT_LINE_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*\+?=")
_ARRAY_CONTINUATION_RE = re.compile(r"^\s*['\"]")

# A fetch piped straight into a shell is R001/R002's evidence, and theirs is
# the heavier claim (remote code executes, not merely a download).  H077
# yields rather than scoring the same line twice.
_PIPE_TO_SHELL_RE = re.compile(
    # The bar must be an operative pipe: an escaped one is an argument
    # and starts no pipeline.  Same guard as R001-R003 and R045.
    # The executor list is the shared one.  This regex decides when H016
    # *stands down* in favour of R001, so a name here that R001 does not
    # know is not a wider net - it is a hole: H016 yields and R001 never
    # catches.  `curl url | ksh -s` was exactly that.
    r"\b(?:curl|wget|aria2c|axel)\b[^|;&]*(?<!\\)\|\s*(?:\S+\s+)?(?:"
    + ANY_EXECUTOR + r")",
    re.IGNORECASE,
)

# Function calls inside command substitutions: $(_latest_commit) or `_ver`.
_CMDSUB_CALL_RE = re.compile(r"(?:\$\(|`)\s*(\w+)\b")


def _array_member_indices(raw_lines: list[str]) -> set[int]:
    """Indices of lines that are entries in a variable array.

    H077 reads the tokenizer's *resolved* lines, where a quoted array entry
    has already lost its quotes.  ``depends=("curl")`` therefore looked like
    a top-level ``curl`` command.  The raw diff lines still carry the
    assignment shape, so array membership is decided here and the resolved
    text is used only for the fetch pattern.
    """
    members: set[int] = set()
    in_array = False
    depth = 0
    for i, raw in enumerate(raw_lines):
        if not raw or raw.startswith(("+++", "---", "@@")):
            continue
        prefix = raw[:1]
        body = _strip_comment(raw[1:] if prefix in "+- " else raw)
        if not body.strip():
            continue
        if not in_array:
            if not _ASSIGNMENT_LINE_RE.match(body):
                continue
            depth = body.count("(") - body.count(")")
            if depth > 0:
                in_array = True
            continue
        members.add(i)
        depth += body.count("(") - body.count(")")
        if depth <= 0:
            in_array = False
    return members


def _fetch_function_names(diff_text: str, config) -> set[str]:
    """Return names of added functions whose bodies contain a parse-time fetch.

    Used to detect parse-time command substitutions that invoke a function
    hiding the downloader, e.g. ``_pin=$(_latest_commit)`` where
    ``_latest_commit()`` calls ``curl``.
    """
    patterns = _parse_time_fetch_patterns(config)
    lines = resolve_added_lines(diff_text)
    fetchers: set[str] = set()
    current: str | None = None
    depth = 0
    for line in lines:
        if not line.startswith("+"):
            continue
        body = line[1:]
        if current is None:
            m = re.match(r"^\s*(\w+)\s*\(\s*\)\s*\{", body)
            if not m:
                continue
            current = m.group(1)
            depth = body.count("{") - body.count("}")
            # Strip the function signature so the command-position fetch patterns
            # see the body content, not the wrapping ``_name() {``.
            body = body[body.find("{") + 1:]
            if depth <= 0:
                # One-line function: test the remainder before the closing brace.
                body = body.split("}", 1)[0]
                if any(p.search(body) for p in patterns):
                    fetchers.add(current)
                current = None
                depth = 0
                continue
        depth += body.count("{") - body.count("}")
        if any(p.search(body) for p in patterns):
            fetchers.add(current)
        if depth <= 0:
            current = None
            depth = 0
    return fetchers


def edge_parse_time_fetch(ctx, add) -> None:
    """H077 predicate over the shared graph context.

    A network client runs when the PKGBUILD is merely *sourced*.  Quiet on
    declarations; an assignment that runs a client through a command
    substitution is not a declaration.
    """
    diff_text = ctx.diff_text
    config = ctx.config
    lines = mask_to_recipe(ctx.lines)
    raw_lines = [
        parsed.raw for parsed in parse_diff_lines(
            join_line_continuations(split_lines(diff_text))).lines
    ]
    array_members = _array_member_indices(raw_lines)
    lexed = lex_lines(lines, fragment=True)
    patterns = _parse_time_fetch_patterns(config)
    fetch_funcs = _fetch_function_names(diff_text, config)
    from .crossfire import _split_commands
    in_array = False
    for i, line in enumerate(lines):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        if lexed[i].heredoc_body:
            continue
        body = _strip_comment(line[1:])
        stripped = body.strip()
        if not stripped:
            continue
        substitutes = "$(" in body or "`" in body
        if i in array_members and not substitutes:
            continue
        opens_array = (
            _ASSIGNMENT_LINE_RE.match(body) and "(" in body and ")" not in body
        )
        if not substitutes and (
            in_array or opens_array or _ARRAY_CONTINUATION_RE.match(body)
            # `x=3#; rsync URL` is an assignment *and* a command: only a
            # line that is nothing but the assignment is a declaration.
            or (_ASSIGNMENT_LINE_RE.match(body)
                and len(_split_commands(body)) <= 1)
        ):
            if opens_array:
                in_array = True
            elif in_array and ")" in body:
                in_array = False
            continue
        if ctx.scopes.direct(i) is not None or _PIPE_TO_SHELL_RE.search(body):
            continue
        if fetch_funcs & set(_CMDSUB_CALL_RE.findall(body)):
            add("H077", "Parse-time Network Fetch", "HIGH", "network",
                f"top-level command substitution invokes a function that "
                f"fetches over the network: {stripped[:80]}",
                line=_find_line(diff_text, stripped[:40]),
                body=stripped[:80],
                detail="network fetch runs at parse time via a function call")
            return
        for pattern in patterns:
            if pattern.search(body):
                add("H077", "Parse-time Network Fetch", "HIGH", "network",
                    f"top-level line fetches over the network when the "
                    f"PKGBUILD is sourced: {stripped[:80]}",
                    line=_find_line(diff_text, stripped[:40]),
                    body=stripped[:80],
                    detail="network fetch runs at parse time, outside every function")
                return


# ---------------------------------------------------------------------------
# H041 - upload to a paste or file-drop host
# ---------------------------------------------------------------------------

# The client, then anything up to the end of the command.  The upload flags
# are matched inside that span, so `curl -sf -F file=@x https://0x0.st` and
# `curl https://0x0.st -T x` both read as uploads.
_HTTP_CLIENT_RE = re.compile(
    r"(?:\A\s*|[;&|]\s*|\$\(\s*)((?:curl|wget)\b[^;&|]*)", re.IGNORECASE
)


def _upload_flags(config=None) -> list[re.Pattern]:
    return compile_configured_patterns("upload_flags", DEFAULT_UPLOAD_FLAGS)


def _paste_hosts(config) -> frozenset[str]:
    hosts = _hosts(config).get("paste_hosts") or DEFAULT_PASTE_HOSTS
    return frozenset(h.lower().lstrip(".") for h in hosts)


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    authority = rest.split("/", 1)[0].split("?")[0].split("#")[0]
    return authority.rsplit("@", 1)[-1].split(":")[0].lower()


#: A path an upload reads that no build artifact lives at.  Anything the
#: recipe produced is under `$srcdir`/`$pkgdir` or relative to them; these
#: are the reader's machine.
_OUTSIDE_TREE_UPLOAD_RE = re.compile(
    r"[@=\s\"']"
    r"(?:~/|\$HOME/|\$\{HOME\}/"
    r"|/etc/|/root/|/home/|/var/(?:log|lib|spool)/|/proc/|/sys/"
    r"|/usr/lib/systemd/|/boot/)"
)


def _uploads_from_outside_the_tree(command: str) -> bool:
    """True when *command* sends a file that is not a build artifact."""
    return bool(_OUTSIDE_TREE_UPLOAD_RE.search(command))


def edge_paste_egress(ctx, add) -> None:
    """H041 predicate over the shared graph context.

    A build or install function uploads to a paste or file-drop host, or
    sends a file from outside the build tree.  H016 yields on a line this
    rule claims.
    """
    diff_text = ctx.diff_text
    config = ctx.config
    lines = mask_to_recipe(ctx.lines)
    flags = _upload_flags(config)
    hosts = _paste_hosts(config)

    for i, line in enumerate(lines):
        fn = ctx.scopes.direct(i)
        if not line.startswith("+") or fn not in _SCOPE_FUNCTIONS:
            continue
        body = _strip_comment(line[1:])
        for match in _HTTP_CLIENT_RE.finditer(body):
            command = match.group(1)
            if not any(flag.search(command) for flag in flags):
                continue
            for _, url in iter_scheme_urls(command, _URL_STOP_CHARS):
                host = _host_of(url)
                if not host:
                    continue
                drop_host = host in hosts or any(
                    host.endswith("." + h) for h in hosts
                )
                outside = _uploads_from_outside_the_tree(command)
                if not drop_host and not outside:
                    continue
                name = ("Upload To Paste Or File-Drop Host" if drop_host
                        else "Upload Of A File From Outside The Build Tree")
                where = f"a drop host ({host})" if drop_host else host
                add("H041", name, "HIGH", "exfil",
                    f"{fn}() uploads to {where}: "
                    f"{command.strip()[:80]}",
                    line=_find_line(diff_text, command.strip()[:40]),
                    position=fn, host=host,
                    body=command.strip()[:80],
                    detail=f"{fn}() uploads to {where}")
                return


def claims_upload_line(body: str, config=None) -> bool:
    """True when H041 owns this line, so H016 can stand down.

    H016 describes an undeclared *download*; when the same invocation is an
    upload to a drop host, H041's description is the accurate one and two
    HIGH findings for one command would be a cascade.
    """
    flags = _upload_flags(config)
    hosts = _paste_hosts(config)
    for match in _HTTP_CLIENT_RE.finditer(body):
        command = match.group(1)
        if not any(flag.search(command) for flag in flags):
            continue
        outside = _uploads_from_outside_the_tree(command)
        for _, url in iter_scheme_urls(command, _URL_STOP_CHARS):
            host = _host_of(url)
            if not host:
                continue
            if outside or host in hosts or any(
                host.endswith("." + h) for h in hosts
            ):
                return True
    return False


def claims_pipe_to_shell(body: str) -> bool:
    """True when R001/R002 own this line, so H016 can stand down.

    H016 reports an undeclared *download*; when that same download is
    piped straight into a shell it is not merely fetch-but-undeclared but
    remote code execution, which is R001/R002's heavier claim.  Firing
    both would score one command twice, which is why H077 already yields
    to this signal.
    """
    return bool(_PIPE_TO_SHELL_RE.search(body))


# ---------------------------------------------------------------------------
# H096 - DLAGENTS override redirects source downloads
# ---------------------------------------------------------------------------

_DLAGENTS_VAR_RE = re.compile(
    r"^\s*(?:export\s+|declare\s+-x\s+)?DLAGENTS\s*\+?=",
    re.IGNORECASE,
)
_DLAGENT_SCHEME_RE = re.compile(r"['\"]?([A-Za-z][A-Za-z0-9+.-]{0,31})::")
_DLAGENT_NETWORK_RE = re.compile(
    r"\b(?:curl|wget2?|aria2c|axel|lftp|git|svn|hg|ssh|scp|sftp|rsync|"
    r"nc|ncat|socat|telnet|ftp|tftp)\b", re.IGNORECASE)
_DLAGENT_MANUAL_RE = re.compile(
    r"\b(?:echo|printf|exit|true|false)\b", re.IGNORECASE)


def _declared_dlagent_schemes(diff_text: str) -> frozenset[str]:
    """Schemes a recipe declares a DLAGENT for.

    A package that uses `hib://` for a manual, vendor-gated download also
    declares the `hib::` agent that tells the user how to obtain it.  That
    declaration is the packaging contract, not an exotic network protocol.
    """
    schemes: set[str] = set()
    for line in mask_to_recipe(resolve_added_lines(diff_text)):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = _strip_comment(line[1:])
        if _DLAGENTS_VAR_RE.match(body):
            schemes.update(s.lower() for s in _DLAGENT_SCHEME_RE.findall(body))
    return frozenset(schemes)


def _dlagents_override_findings(diff_text, config, add) -> None:
    """DLAGENTS is reassigned, redirecting source downloads (H096).

    DLAGENTS controls how makepkg fetches sources for each protocol.
    Overriding it in a PKGBUILD redirects all source downloads through
    the attacker's chosen binary.  Any change to DLAGENTS is flagged:
    legitimate recipes do not modify it.
    """
    lines = mask_to_recipe(resolve_added_lines(diff_text))
    for i, line in enumerate(lines):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = _strip_comment(line[1:])
        if _DLAGENTS_VAR_RE.match(body):
            # A manual-download agent (`hib::/usr/bin/echo "fetch it
            # yourself"; exit 1`) redirects nothing: it declines the fetch.
            # The override only becomes a download redirection when the
            # agent runs a network client.
            if _DLAGENT_MANUAL_RE.search(body) and not _DLAGENT_NETWORK_RE.search(body):
                continue
            add("H096", "Download Agent Override", "MEDIUM", "network",
                "DLAGENTS is assigned, redirecting source downloads",
                line=i + 1, body=body.strip()[:80],
                detail="DLAGENTS override redirects all protocol fetches")
            return
