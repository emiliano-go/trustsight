"""Phase 3 - network-surface rules (plan §5).

H031/H033/H034/H071 share one question: does the PKGBUILD's declared or
executed network surface carry an injection or a covert channel?  All four
are code rules because each needs more than a regex:

- H031 needs the literal ``pkgver``/``_pkgver`` value and its interpolation
  into a source URL;
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
from ..rules import _classify_enclosing_function
from ..tokenizer import resolve_added_lines
from .base import iter_scheme_urls, mask_to_recipe
from .build import _CRITICAL_FUNCTIONS, _INSTALL_HOOKS
from .delivery import _find_line
from ..tokenizer import split_lines

_SCOPE_FUNCTIONS = frozenset(_CRITICAL_FUNCTIONS) | frozenset(_INSTALL_HOOKS)

_SOURCE_ARRAY_RE = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*\(")
_SOURCE_SCALAR_RE = re.compile(r"^\s*source(?:_[a-z0-9_]+)?\s*=\s*(\S+)")
# URL tokens are found by scanning for "://" (see base.iter_scheme_urls);
# the regex form was quadratic on a line with no scheme at all.
_URL_STOP_CHARS = frozenset(" \t\r\n'\")")

# ---------------------------------------------------------------------------
# Shared: source-array URL tokens
# ---------------------------------------------------------------------------


def _source_url_tokens(diff_text):
    """Yield ``(scheme, url)`` for every scheme:// token on an added source
    line (array or scalar / .SRCINFO form)."""
    in_array = False
    for line in split_lines(diff_text):
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith("-"):
            if in_array and ")" in line:
                in_array = False
            continue
        body = line[1:] if line[:1] == "+" else line
        is_source = bool(_SOURCE_ARRAY_RE.match(body) or _SOURCE_SCALAR_RE.match(body))
        if not in_array and not is_source:
            continue
        for scheme, url in iter_scheme_urls(body, _URL_STOP_CHARS):
            yield scheme, url
        if ")" in body:
            in_array = False


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
    allowed = _source_schemes(config)
    for scheme, url in _source_url_tokens(diff_text):
        base = scheme.rsplit("+", 1)[-1].lower()
        if base not in allowed:
            add("H034", "Exotic Source Protocol", "MEDIUM", "network",
                f"source URL uses non-allowlisted scheme {scheme}: {url[:70]}",
                url=url[:70], scheme=scheme)
            return


# ---------------------------------------------------------------------------
# H031 - version-in-URL injection
# ---------------------------------------------------------------------------

_PKGVER_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:local|export|readonly)\s+)?(_?pkgver)\s*=\s*(.+)"
)
# Version characters, per plan §5: anything else in an interpolated value is
# an injection candidate.
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._+\-]+$")


def _version_in_url_findings(diff_text, config, add) -> None:
    """``pkgver``/``_pkgver`` interpolated into a source URL with a value
    carrying characters outside ``[A-Za-z0-9._+-]`` (H031).

    A literal version like ``1.2.3`` or ``2026.08.01`` is safe.  A value
    containing ``;``, whitespace, ``/`` or other delimiters that is then
    substituted into a fetched URL is an injection vector.
    """
    bad_values: dict[str, str] = {}
    for line in resolve_added_lines(diff_text):
        if not line.startswith("+"):
            continue
        match = _PKGVER_ASSIGN_RE.match(line[1:])
        if not match:
            continue
        name, value = match.group(1), match.group(2).strip()
        value = value.strip("\"'")
        if not _SAFE_VERSION_RE.match(value):
            bad_values[name] = value

    if not bad_values:
        return
    for _, url in _source_url_tokens(diff_text):
        for name, value in bad_values.items():
            braced = re.search(r"\$\{" + re.escape(name) + r"\}", url)
            bare = re.search(r"\$" + re.escape(name) + r"(?![\w])", url)
            if not (braced or bare):
                continue
            add("H031", "Version-In-URL Injection", "MEDIUM", "network",
                f"{name}={value!r} carries injection chars and is "
                f"interpolated into a source URL: {url[:70]}",
                url=url[:70], variable=name, value=value[:40])
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
# The version the package *claims*.  If any of these moved, the maintainer
# declared a new version and a new commit is what a new version means.
_VERSION_TOKEN_RE = re.compile(
    r"^\s*(pkgver|pkgrel|epoch|_pkgver|_tag|_gittag|_version|_gitver)\s*=", re.IGNORECASE
)


def _repo_base(url: str) -> str:
    return url.split("#", 1)[0].rstrip("/").lower()


def _git_refs_by_side(diff_text: str) -> dict[str, dict[str, set[tuple[str, str]]]]:
    """Map ``side -> repo -> {(ref_kind, ref_value)}`` for every git source
    token in the diff, where side is ``+``, ``-`` or ``" "`` (context)."""
    sides: dict[str, dict[str, set[tuple[str, str]]]] = {"+": {}, "-": {}, " ": {}}
    for line in split_lines(diff_text):
        if line.startswith(("+++", "---", "@@", "diff ", "index ")):
            continue
        side = line[0] if line[:1] in ("+", "-", " ") else " "
        body = line[1:] if line[:1] in ("+", "-", " ") else line
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
    for line in split_lines(diff_text):
        if line.startswith(("+++", "---")) or line[:1] not in ("+", "-"):
            continue
        match = _PIN_VAR_RE.match(line[1:])
        if match:
            sides[line[0]][match.group(1).lower()] = (
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

    if any(
        _VERSION_TOKEN_RE.match(line[1:])
        for line in split_lines(diff_text)
        if line[:1] in ("+", "-") and not line.startswith(("+++", "---"))
    ):
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


def _covert_egress_findings(diff_text, config, add) -> None:
    """.onion/.i2p hosts, DoH endpoints or tunneling clients anywhere they
    have no packaging purpose (H071)."""
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    clients = _covert_clients(config)
    endpoints = _covert_endpoints(config)

    for i, line in enumerate(lines):
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
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
            continue
        body = _strip_comment(line[1:])
        for client in clients:
            if client.search(body):
                add("H071", "Covert Egress", "HIGH", "network",
                    f"{enclosing[i]}() invokes a tunneling/covert client: "
                    f"{body.strip()[:80]}",
                    position=enclosing[i], body=body.strip()[:80])
                return

# ---------------------------------------------------------------------------
# H077 - network fetch at parse time
# ---------------------------------------------------------------------------


def _parse_time_fetch_patterns(config=None) -> list[re.Pattern]:
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("parse_time_fetch") or DEFAULT_PARSE_TIME_FETCH
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


def _parse_time_fetch_findings(diff_text, config, add) -> None:
    """A network client runs when the PKGBUILD is merely *sourced* (H077).

    Everything outside a function body executes as soon as makepkg reads the
    file, which happens on ``makepkg --printsrcinfo``, on an AUR helper's
    metadata refresh and on any review that sources the recipe - before a
    single build step, and before the checksum array has covered anything.
    R010/R011 report a downloader inside a build function at LOW; running
    one at parse time is a different claim, so it is a different rule.

    Quiet on declarations: ``DLAGENTS=(...)`` and any other assignment whose
    *value* names a downloader configures makepkg, it does not fetch.  An
    assignment that *runs* one through a command substitution
    (``_ver=$(curl ...)``) is not a declaration and is not exempt.
    """
    lines = mask_to_recipe(resolve_added_lines(diff_text))
    enclosing = _classify_enclosing_function(lines)
    patterns = _parse_time_fetch_patterns(config)
    fetch_funcs = _fetch_function_names(diff_text, config)
    in_array = False
    for i, line in enumerate(lines):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = _strip_comment(line[1:])
        stripped = body.strip()
        if not stripped:
            continue
        substitutes = "$(" in body or "`" in body
        opens_array = (
            _ASSIGNMENT_LINE_RE.match(body) and "(" in body and ")" not in body
        )
        if not substitutes and (
            in_array or opens_array or _ASSIGNMENT_LINE_RE.match(body)
            or _ARRAY_CONTINUATION_RE.match(body)
        ):
            if opens_array:
                in_array = True
            elif in_array and ")" in body:
                in_array = False
            continue
        if enclosing.get(i) is not None or _PIPE_TO_SHELL_RE.search(body):
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
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("upload_flags") or DEFAULT_UPLOAD_FLAGS
    return [re.compile(f, re.IGNORECASE) for f in frags]


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


def _paste_egress_findings(diff_text, config, add) -> None:
    """A build or install function *uploads* to a paste or file-drop host (H041).

    The paste-host list also feeds the ``raw_hosting`` source bucket, and a
    rule that fired on a declared `source=` URL would double-count that
    weight.  This rule reads the other direction, which no bucket can see:
    a request carrying a body, sent from inside a function, to a host whose
    entire purpose is to accept an anonymous drop and hand back a link.

    Direction is the distinction that makes it a separate claim.  Fetching
    from a gist is an undeclared download, which is H016's finding; posting
    to one is data leaving the machine that is building the package, which is
    H043's ``exfil`` stage. On a line this rule claims, H016 yields, so one
    upload is not scored twice.
    """
    lines = mask_to_recipe(resolve_added_lines(diff_text))
    enclosing = _classify_enclosing_function(lines)
    flags = _upload_flags(config)
    hosts = _paste_hosts(config)

    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
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
                # Two auditable conditions, not one guess.  The host list
                # is the original: a host whose entire purpose is to accept
                # an anonymous drop.  The second is the *file*: a build
                # sends nothing off the machine, and one that reads from
                # outside its own tree - `/etc/passwd`, `~/.ssh/id_rsa`,
                # `$HOME/...` - is not uploading a build artifact.
                #
                # `curl -F file=@report.json https://ci.example.com` stays
                # quiet under both: a relative path inside the build tree,
                # to a host nobody can call a drop site. That case is
                # pinned in tests/test_gap_rules.py, and the principle it
                # states - "defined by an auditable host list, not by a
                # guess about what an endpoint is for" - is why this adds a
                # second list rather than dropping the first.
                outside = _uploads_from_outside_the_tree(command)
                if not drop_host and not outside:
                    continue
                name = ("Upload To Paste Or File-Drop Host" if drop_host
                        else "Upload Of A File From Outside The Build Tree")
                where = f"a drop host ({host})" if drop_host else host
                add("H041", name, "HIGH", "exfil",
                    f"{enclosing[i]}() uploads to {where}: "
                    f"{command.strip()[:80]}",
                    line=_find_line(diff_text, command.strip()[:40]),
                    position=enclosing[i], host=host,
                    body=command.strip()[:80],
                    detail=f"{enclosing[i]}() uploads to {where}")
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
            add("H096", "Download Agent Override", "MEDIUM", "network",
                "DLAGENTS is assigned, redirecting source downloads",
                line=i + 1, body=body.strip()[:80],
                detail="DLAGENTS override redirects all protocol fetches")
            return
