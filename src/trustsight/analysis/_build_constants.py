"""Imports and constants shared by the build rule module."""

import bisect
import re

from ..buckets import canonical_host
from ..config import (
    DEFAULT_FOREIGN_PKG_MANAGERS,
    DEFAULT_OBFUSCATION_INDICATORS,
    EXEC_WRAPPER as _EXEC_WRAPPER_RE,
    NETWORK_CLIENT as _NETWORK_CLIENT,
    SHELL_EXECUTOR as _SHELL_EXEC,
    load_patterns,
    load_thresholds,
)
from ..deps import _strip_comment
from ..differ import extract_source_array_urls
from ..diffdoc import parse_diff_lines
from ..novelty import normalize_url
from ..rules import (
    _blank_quoted,
    _classify_enclosing_function,
    _PRINTER_LINE_RE,
)
from ..tokenizer import (
    join_line_continuations,
    joined_indexed,
    reconstruct_lines_stateful,
    resolve_added_lines,
)
from .base import _code_rule_enabled, mask_to_pkgbuild, mask_to_recipe
from ..tokenizer import split_lines


_CRITICAL_FUNCTIONS = ("build", "prepare", "check", "package")

_INSTALL_HOOKS = (
    "post_install", "post_upgrade", "pre_install",
    "pre_upgrade", "pre_remove", "post_remove",
)

# H017's high-severity arm: a hook that *executes* dynamic code.  A fetch
# (``_network_fetch_url``) is the other high arm.  These two are what the rule
# name ("Install Hook Fetches Or Executes") actually claims.
_HOOK_EXEC_RE = re.compile(
    r"(?<![\w-])(?:eval|bash\s+-c|sh\s+-c|source\s+/)\b",
    re.IGNORECASE,
)

# Privileged setup an install hook does that is *not* fetch-or-execute:
# enabling a service, creating or altering an account, editing sudoers, or
# setting a setuid/setgid bit.  Still reported (no gap), but at MEDIUM: it is
# the ordinary shape of a legitimate hook, and treating every
# `systemctl enable` as "runs as root" overscored the common case.
_HOOK_ADMIN_RE = re.compile(
    r"\b(?:systemctl\s+enable|useradd|usermod|visudo|"
    r"chmod\s+[0-7]*[2467][0-7]{3}|chmod\s+[ugoa]*\+s)\b",
    re.IGNORECASE,
)

_UNTRUSTED_PATCH_RE = re.compile(
    r"(?:patch\b|git\s+apply\b)[^|;&]*?"
    r"(<\([^)]*\)"
    r"|https?://[^\s'\"]+"
    r"|[<\s-][ip]?\s*['\"]?/(?!usr/bin/patch)[^\s'\"$]+\.(?:patch|diff))",
    re.IGNORECASE,
)

# A network client, and separately the address it names.
#
# These were one regex: `CLIENT ... (ADDRESS)` with a lazy span between them.
# That span is a quadratic search - on a line with a client and no address it
# retried every split point looking for one - and the cost grew with the
# address alternation until the safety audit refused the pattern outright.
# Two anchored searches and a position comparison do the same job in one
# pass each, and neither can backtrack into the other.
#
# The interpreter arm is not decoration: `curl` and `wget` are what a
# reviewer greps for, so an author avoiding the grep reaches for the runtime
# that is already a makedepend.  It listed only `python` and only `urllib`,
# so `python3 -c` - the spelling every current recipe uses - matched
# nothing, and neither did perl, ruby or node.
_INTERPRETER_FETCH = (
    r"python[23]?\s+-c\b[^|;&]*?"
    r"(?:urllib|requests|httpx|http\.client|urlopen|urlretrieve)"
    r"|python[23]?\s+-m\s+(?:http|urllib|pip)\b"
    r"|perl\s+-[eE]\b[^|;&]*?(?:LWP|HTTP::|Net::HTTP|getstore|get\()"
    r"|ruby\s+-e\b[^|;&]*?(?:Net::HTTP|open-uri|URI\.(?:parse|open))"
    r"|node\s+-e\b[^|;&]*?(?:https?\.get|fetch\(|require\(['\"]https?)"
)

_FETCH_CLIENT_ONLY_RE = re.compile(
    r"\b(?:" + _NETWORK_CLIENT + r")\b|(?:" + _INTERPRETER_FETCH + r")",
    re.IGNORECASE,
)

#: A scheme-bearing address, anchored to the start of a token.
#:
#: `\A` is not decoration.  Used with `.match()` the anchor changes nothing,
#: but the regex audit measures every module-level pattern with `.search()`
#: on a hostile line - and unanchored, the leading character run is retried
#: from every position, which measured 290 ms. A pattern whose safety
#: depends on how the caller invokes it is a pattern one refactor away from
#: being quadratic, so the anchor is written into it.
_SCHEME_ADDRESS_RE = re.compile(
    # `magnet:` and `ipfs:`/`ipns:` name content rather than a host, so
    # they carry no `//` and matched nothing - the client was recognised
    # and the fetch scored nothing because no address could be attributed
    # to it. A content address is still an address: it says the bytes come
    # from off the machine, which is the whole question.
    r"\A(?:[a-z][a-z0-9+.-]*://[^\s|;&'\"\)]+"
    r"|(?:magnet|ipfs|ipns|ed2k|bitcoin):[^\s|;&'\"\)]+)",
    re.IGNORECASE,
)

#: The scp/ssh form - `git@evil.example:r.git`, `host:/path` - which names a
#: remote with no scheme at all.  Requiring `http(s)://` left the whole ssh
#: transport invisible, but searching for this shape *inside* a line is a
#: quadratic scan: with no `@` present the engine retries the leading run
#: from every position, and a full-length hostile line measured 304 ms.
#: Anchored to a whole token instead, and the tokenizing is one pass.
_SCP_ADDRESS_RE = re.compile(
    # The user part is optional: `scp host:/x.sh dest` is the same remote
    # read as `scp user@host:/x.sh dest`, and requiring `@` left the fetch
    # unattributed while H082 paired the write with its execution.  The
    # host must carry a dot, or every `make target:` reads as a remote.
    r"\A(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:\S+\Z"
)


#: A CVS root: `:pserver:user@host:/repo`.
_CVS_ROOT_RE = re.compile(
    r"\A:(?:pserver|ext|ssh|extssh|fork|local):[^\s]*[A-Za-z0-9.-]+:", re.IGNORECASE
)


#: Schemes that name content instead of a host.
_CONTENT_ADDRESS_RE = re.compile(
    r"\A(?:magnet|ipfs|ipns|ed2k|bitcoin):[^\s|;&'\"\)]+", re.IGNORECASE)

__all__ = ['bisect', 're', 'canonical_host', 'DEFAULT_FOREIGN_PKG_MANAGERS', 'DEFAULT_OBFUSCATION_INDICATORS', '_EXEC_WRAPPER_RE', '_NETWORK_CLIENT', '_SHELL_EXEC', 'load_patterns', 'load_thresholds', '_strip_comment', 'extract_source_array_urls', 'parse_diff_lines', 'normalize_url', '_blank_quoted', '_classify_enclosing_function', '_PRINTER_LINE_RE', 'join_line_continuations', 'joined_indexed', 'reconstruct_lines_stateful', 'resolve_added_lines', '_code_rule_enabled', 'mask_to_pkgbuild', 'mask_to_recipe', 'split_lines', '_CRITICAL_FUNCTIONS', '_INSTALL_HOOKS', '_HOOK_EXEC_RE', '_HOOK_ADMIN_RE', '_UNTRUSTED_PATCH_RE', '_INTERPRETER_FETCH', '_FETCH_CLIENT_ONLY_RE', '_SCHEME_ADDRESS_RE', '_SCP_ADDRESS_RE', '_CVS_ROOT_RE', '_CONTENT_ADDRESS_RE']
