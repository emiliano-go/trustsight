"""Extracted from crossfire.py: _common."""

from __future__ import annotations
import logging
import re
from ...deps import _strip_comment
from ..base import _CMD
from ._ownership import _ownership_yields

__all__ = ['_ACCOUNT_OPTION_RE', '_ARRAY_ASSIGN_OPEN_RE', '_ARRAY_VAR_RE', '_ASSIGNMENT_RE', '_CMD', '_CONFUSABLE_CHARS', '_DATA_CONSUMER', '_DECEPTIVE_SPACE_RE', '_DEP_ARRAY_OPEN_RE', '_EVALUATION_RE', '_EXECUTING_SCOPES', '_EXEC_WRAPPER', '_FENCE_RE', '_FIRST_WORD_RE', '_FOR_LOOP_RE', '_H032_CLAIMS_RE', '_HOME_ALIASES', '_INTERPRETER_DECODE', '_LITERAL_WORD_RE', '_NUMERIC_RE', '_PATH_LOOKUP_ASSIGN_RE', '_PIPE_WRAPPER_RE', '_PLAIN_VAR_RE', '_PRIVILEGE_WRAPPERS', '_REDIRECT_RE', '_SHELL', '_SHELL_CMD', '_SHELL_NAME', '_STAGED_RE', '_WORD_VAR_RE', '_WRAPPERS', '_WRITE_COMMAND_RE', '_WRITE_PREFIX', '_command_words', '_confusable_class', '_continuation_lines', '_dependency_array_lines', '_executes', '_home_alias_hit', '_loop_variable_names', '_opens_a_value', '_path_lookup_names', '_pipeline_sink', '_quote_open_at_end', '_resolved_records', '_resolves_to_a_literal', '_split_commands', '_unquoted_paren_delta', '_word_around', 'log']

log = logging.getLogger(__name__)

_EXECUTING_SCOPES = (
    "prepare", "build", "check", "package", "pkgver",
    "post_install", "post_upgrade", "pre_install",
    "pre_upgrade", "pre_remove", "post_remove",
)

def _executes(function: str | None) -> bool:
    """Whether code inside *function* runs during a build or install.

    The answer for a PKGBUILD is "yes, wherever it is", and the allowlist
    that used to decide this said no to three shapes that all run:

    * ``package_libfoo()`` - a **split package**. makepkg calls
      ``package_$pkgname()`` for each name in a split recipe, so renaming
      ``package`` to ``package_libfoo`` moved a payload out of range of
      every rule in this family. It is the most common function shape in
      the AUR after the five standard ones.
    * ``_helper()`` - an ordinary helper, called from ``build()``. The name
      is the author's to choose, which is the whole problem with matching
      on it.
    * anything else a recipe defines and calls.

    A function that is *never called* is dead code, and treating dead code
    as executing costs a finding on a package that was already writing
    evasion-shaped shell into a function it does not run. That trade is
    the right way round: the alternative is a rule whose scope the author
    chooses.
    """
    return function is not None

_SHELL_CMD = r"(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)"

_SHELL_NAME = _SHELL_CMD + r"|python3?|perl|ruby|node"

_EXEC_WRAPPER = r"(?:env|exec|command)(?:\s+-[-\w]+)*\s+"

_SHELL = (
    r"(?:/(?:usr/)?bin/)?(?:" + _SHELL_NAME + r")\b"
    r"|" + _EXEC_WRAPPER + r"(?:/(?:usr/)?bin/)?(?:" + _SHELL_NAME + r")\b"
    # `source /dev/stdin` and `. /dev/stdin` read the pipe as a script.
    r"|(?:source|\.)\s+/dev/stdin\b"
)

_INTERPRETER_DECODE = (
    r"b(?:ase)?64[_.]?decode|b64decode|base64_decode|decode_base64"
    r"|unhexlify|atob|decodestring|Base64\.decode(?:64)?"
    r"|unpack1?\s*\(\s*[\"'](?:m|H\*|u)"
    r"|pack\s*\(\s*[\"']H\*"
    r"|Buffer\.from\s*\([^)]*[\"'](?:base64|hex)[\"']"
    r"|(?:zlib|gzip|bz2|lzma|zstd)\.(?:decompress|decode)"
    r"|Compress::(?:Zlib|Raw)|Inflate|uncompress"
    r"|codecs\.decode|binascii\.[ab]2[ab]_"
)

_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]{0,40}\])?\+?=")

_FENCE_RE = re.compile(r"^\s*(?:```|~~~|#|//|\*|-\s)")

def _confusable_class() -> str:
    """The confusable characters, as a regex character class.

    Reuses the curated map rather than a second list: a character that
    impersonates ASCII is the same set whether it appears in a domain
    (R013b) or in a command name.
    """
    from ...buckets import _CONFUSABLE_TO_LATIN

    return "".join(re.escape(ch) for ch in sorted(_CONFUSABLE_TO_LATIN))

_CONFUSABLE_CHARS = _confusable_class()

_FIRST_WORD_RE = re.compile(r"^\s*([^\s;&|<>]+)")

_H032_CLAIMS_RE = re.compile(r"^[\"']?(?:~|\$\{?HOME\}?)/")

_HOME_ALIASES = (
    # A literal home path, with a real or variable username.
    # `/home//alice/` reaches the same directory; a single slash in the
    # pattern was an evasion.
    #
    # The trailing slash is optional, and that was an evasion too: `cp
    # payload /home/alice` writes into the same directory as `/home/alice/`
    # and every one of these patterns required the separator. The path must
    # still *end* there - a bare `/home` with nothing after it names the
    # parent of all homes, which packaging touches legitimately.
    ("literal-home", re.compile(
        r"(?:^|[\s\"'=])/home/+(?:\$\{?\w+\}?|[A-Za-z0-9._-]+)(?:/|[\s\"']|$)")),
    # Tilde-user expansion: ~alice/ is $HOME for alice, and dodges `^~/`.
    ("tilde-user", re.compile(r"(?:^|[\s\"'=])~[A-Za-z0-9._-]+(?:/|[\s\"']|$)")),
    # root's home.
    ("root-home", re.compile(r"(?:^|[\s\"'=])/root(?:/|[\s\"']|$)")),
    # A default-value expansion that names a home path if HOME is unset.
    # Unbounded: 81 characters of default value walked past this.
    ("home-default", re.compile(r"\$\{HOME[:-][=+-][^}]*+\}")),
    # Traversal that explicitly aims at a home directory.
    ("traversal-home", re.compile(r"(?:\.\./){1,8}(?:home|root)/")),
)

_WRITE_PREFIX = r"(?:[A-Za-z_]\w*=\S*\s+|(?:env|sudo|doas|exec|nohup|command|timeout|nice)\s+)*"

_WRITE_COMMAND_RE = re.compile(
    _CMD + _WRITE_PREFIX +
    r"(?:install|cp|mv|tee|ln|mkdir|touch|rsync|dd|chmod|chown|sed)\b|"
    r">>?\s*[\"']?(?=\S)",
    re.MULTILINE,
)

_STAGED_RE = re.compile(r"\$\{?(?:pkgdir|srcdir|builddir|startdir)\}?")

def _word_around(body: str, start: int, end: int) -> str:
    """The whitespace-delimited word containing ``body[start:end]``."""
    left = start
    while left > 0 and not body[left - 1].isspace():
        left -= 1
    right = end
    while right < len(body) and not body[right].isspace():
        right += 1
    return body[left:right]

def _home_alias_hit(body: str):
    """The alias shape this line uses to reach a home directory, or None."""
    if not _WRITE_COMMAND_RE.search(body):
        return None
    for shape, pattern in _HOME_ALIASES:
        match = pattern.search(body)
        if not match:
            continue
        # The staging exemption belongs to the *target*, not to the line.
        # It used to be tested against the whole body, so a decoy anywhere
        # on the line bought silence: `echo "$pkgdir" && cp payload
        # /home/alice/.bashrc` reported nothing. What makes a write
        # packaging is that the path being written is under a staging root,
        # which is a property of that one word.
        # The alias match opens with its boundary character - a space, a
        # quote or an `=` - so expanding from `match.start()` walks
        # backwards into the *previous* argument, and `cp "$pkgdir/x"
        # /home/alice/.bashrc` read as one staged word. Start at the path.
        matched = match.group(0)
        path_start = match.start() + len(matched) - len(matched.lstrip(" \t\"'="))
        target_word = _word_around(body, path_start, match.end())
        if _STAGED_RE.search(target_word):
            continue
        # Defer to H032 when the target is spelled the plain way.
        target = match.group(0).lstrip(" \t\"'=")
        if _H032_CLAIMS_RE.match(target):
            continue
        return shape
    return None

_DECEPTIVE_SPACE_RE = re.compile(r"[^\S \t\n\r]")

def _split_commands(body: str) -> list[str]:
    """Split *body* on command separators, respecting quotes.

    A `|` inside a quoted argument does not start a command:
    ``sed -i 's|"$LIBS -lfoo|...|'`` is one command, and splitting naively
    on the pipe offered ``"$LIBS ...`` as a command word. That was the only
    substitution-shaped false positive the benign corpus produced.
    """
    parts, current, quote = [], [], None
    depth = 0
    index = 0
    while index < len(body):
        ch = body[index]
        if quote:
            if ch == quote:
                quote = None
            current.append(ch)
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch == "[" and body[index:index + 2] == "[[":
            # `[[ -n "$a" && "$a" != "$b" ]]` is one test, not two commands.
            # Splitting on the `&&` handed the second half to the scan with
            # `"$a"` in first position, and a conditional that mentions a
            # variable is most of the shell ever written. The guard at the
            # top of the loop only sees a part that *begins* with `[[`.
            depth += 1
            current.append(body[index:index + 2])
            index += 2
            continue
        elif ch == "]" and body[index:index + 2] == "]]":
            depth = max(0, depth - 1)
            current.append(body[index:index + 2])
            index += 2
            continue
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch in ";&|" and depth == 0:
            parts.append("".join(current))
            current = []
            # Consume the second character of && and ||.
            if index + 1 < len(body) and body[index + 1] == ch:
                index += 1
        elif ch in ";&|":
            # Inside `(( ... && ... ))` or `$( ... )` this is arithmetic or a
            # nested pipeline, not a new command.
            current.append(ch)
        else:
            current.append(ch)
        index += 1
    parts.append("".join(current))
    return parts

_WRAPPERS = frozenset({
    "env", "exec", "sudo", "doas", "nohup", "command", "builtin", "time",
    "nice", "ionice", "timeout", "xargs", "setsid", "stdbuf", "unbuffer",
    "script", "then", "else", "do", "!",
    "if", "elif", "while", "until",
})

_REDIRECT_RE = re.compile(r"^\d?[<>]")

_EVALUATION_RE = re.compile(r"^(?:\(\(|\[\[|\[\s|test\s)")

_NUMERIC_RE = re.compile(r"^\d+$")

def _opens_a_value(token: str) -> bool:
    """True when *token* leaves a quote or a substitution unclosed.

    `FOO=1 cmd` is an environment prefix and the scan must walk past it to
    reach `cmd`. `outmsg=$(eval "$(...)" 2>&1)` is not: everything after the
    first token is the assignment's *value*, and reading on found the `$(`
    inside it and called it a command name. The two are told apart by
    whether the token closes what it opened.
    """
    return bool(
        token.count('"') % 2
        or token.count("'") % 2
        or token.count("(") > token.count(")")
    )

_WORD_VAR_RE = re.compile(r"\$(\{)?([A-Za-z_][A-Za-z0-9_]*)(?(1)\})")

_LITERAL_WORD_RE = re.compile(r"^[A-Za-z0-9_./+-]+$")

def _resolves_to_a_literal(word: str, scalar_values: dict) -> bool:
    """True when *word* is expansions of known scalars and nothing else.

    `${_arch}-cmake` with `_arch=x86_64-w64-mingw32` collapses to a literal
    command name; `${D}url` with `D` unknown does not.  Only scalar
    expansions are folded - an operator, subscript or command substitution
    inside the word is assembly the table cannot reproduce, so the word is
    left for X002.
    """
    if not word or not scalar_values:
        return False
    if "$(" in word or "`" in word or "${!" in word:
        return False
    stripped = word.strip("\"'")
    resolved = []
    last = 0
    for match in _WORD_VAR_RE.finditer(stripped):
        resolved.append(stripped[last:match.start()])
        value = scalar_values.get(match.group(2))
        if value is None:
            return False
        resolved.append(value)
        last = match.end()
    resolved.append(stripped[last:])
    litt = "".join(resolved).strip("\"'")
    return bool(litt) and bool(_LITERAL_WORD_RE.match(litt))

_PRIVILEGE_WRAPPERS = frozenset({"sudo", "doas", "run0"})

_ACCOUNT_OPTION_RE = re.compile(r"^-{1,2}(?:u|user|g|group)(?:=(.*))?$")

def _command_words(body: str, resolvable: frozenset[str] = frozenset(),
                   scalar_values: dict | None = None):
    """Each command-position word on *body* that is not a literal.

    A command word is not always the first token. Every one of these hides
    it one or more tokens to the right, and each was an evasion of an
    earlier version of this rule:

    * an environment assignment - `FOO=1 ${A[0]} x`
    * a wrapper command - `env`, `exec`, `sudo`, `nohup`, `timeout 5`
    * a redirection - `>out ${A[0]} x`
    * a subshell or group opener - `( ${A[0]} x )`

    So the scan skips prefixes rather than reading position zero. What it
    will not do is examine *arguments*: `make "$pkgdir"` names a literal
    command, and treating its arguments as command words would fire on most
    of the corpus.

    A variable the tokenizer reduced to a literal is dropped: `$DKMS add`
    where the recipe assigned `DKMS=dkms` is a spelling choice, not an
    evasion.
    """
    for part in _split_commands(body):
        # `(( ... ))` and `[[ ... ]]` evaluate an expression; nothing in them
        # is a command name, and reading one as such fired on
        # `(( $(vercmp ...) >= 0 ))`.
        if _EVALUATION_RE.match(part.lstrip()):
            continue
        seen_wrapper = False
        wrapper = ""
        account_option = False
        for token in part.split():
            if token.startswith("(("):
                # `if (( $(vercmp $2 x) >= 0 ))` - arithmetic. The check at
                # the top of the loop catches it when the part *begins*
                # there; after a wrapper it does not, and the `$(` inside
                # read as a command name.
                break
            word = token.lstrip("({")
            if not word:
                continue
            if _ASSIGNMENT_RE.match(word):
                if _opens_a_value(word):
                    break
                continue
            if _REDIRECT_RE.match(word) or _NUMERIC_RE.match(word):
                continue
            if word.startswith("-"):
                # A flag before any command means this line continues a
                # previous one - `sed \` then `  -i "${dir}/x"` - so it has
                # no command position at all. Inside a wrapper's arguments
                # it is just a flag, and the scan goes on.
                if not seen_wrapper:
                    break
                # ...unless the flag turns the wrapper into a *lookup*.
                # `command -v "$cmd"` asks where `$cmd` is, and runs
                # nothing; reading its argument as a command name fired on
                # the ordinary dependency-check idiom.
                if wrapper == "command" and word in ("-v", "-V"):
                    break
                if wrapper == "type" and word in ("-p", "-P", "-a"):
                    break
                # A privilege tool's account option takes a target that
                # names an account, not a command.  `-u x` leaves it as the
                # next token; `--user=x` carries it inline.
                inline_word = None
                if wrapper in _PRIVILEGE_WRAPPERS:
                    account_match = _ACCOUNT_OPTION_RE.match(word)
                    if account_match is not None:
                        inline = account_match.group(1)
                        if inline is None:
                            account_option = True
                        else:
                            inline = inline.strip("\"'")
                            # `--user=${A[0]}` hides a name in the account
                            # slot: scan the inline value.  `--user=root`
                            # is a literal account, and `--user=$SUDO_USER`
                            # the de-escalation idiom; neither is a command.
                            if (
                                not _PLAIN_VAR_RE.match(inline)
                                and ("$" in inline or "`" in inline)
                            ):
                                inline_word = inline
                if inline_word is None:
                    continue
                word = inline_word
            if word.strip("\"'") in _WRAPPERS:
                seen_wrapper = True
                wrapper = word.strip("\"'")
                account_option = False
                continue
            bare = _PLAIN_VAR_RE.match(word)
            if bare and bare.group(1) in resolvable:
                break
            if account_option:
                # The word right after `sudo -u`/`--user`/`-g` is the target
                # account, not the command.  A dynamic target is the
                # de-escalation idiom (`sudo -u $SUDO_USER env … fcitx5`);
                # a literal one (`sudo -u root`) is an ordinary escalation.
                # Neither is a command *name*, so both keep scanning: a
                # hidden command after the target (`sudo -u X ${A[0]} …`) is
                # still yielded.
                account_option = False
                continue
            # A static array subscript on a known array resolves to a
            # literal, so it is a spelling choice like `$DKMS`; a dynamic
            # subscript or an unknown array is not in *resolvable* and the
            # word is yielded for X002 to claim.
            element = _ARRAY_VAR_RE.match(word)
            if element and element.group(1) in resolvable:
                break
            # A *spliced* name (`${_arch}-cmake`, `ba${x}sh`) is a spelling
            # choice too when every expansion in it is a known scalar: the
            # tokenizer never folds a mid-word splice, so `${_arch}-cmake`
            # stayed unresolvable and X002 fired CRITICAL on a build target
            # that is plain text one line up.  Resolve the word with the
            # scalar table; if it collapses to a literal command name, it
            # is not an evasion.  An unknown variable, an empty result or
            # any surviving shell metacharacter keeps it yielded.
            if _resolves_to_a_literal(word, scalar_values):
                break
            yield word
            break

_PLAIN_VAR_RE = re.compile(r"^[\"\']?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?[\"\']?$")

_ARRAY_VAR_RE = re.compile(
    r"^[\"\']?\$\{([A-Za-z_][A-Za-z0-9_]*)\[(?:\*|@|\d+)\]\}[\"\']?$"
)

_PATH_LOOKUP_ASSIGN_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)=[\"']?\$\(\s*"
    r"(?:which|type\s+-p|command\s+-v)\s+[A-Za-z0-9_.+-]+\s*\)",
)

def _matched_names(lines: list[str], pattern: re.Pattern) -> set[str]:
    """Names captured by *pattern* on any of *lines*."""
    return {match.group(1) for line in lines
            if (match := pattern.match(line))}


def _path_lookup_names(lines: list[str]) -> set[str]:
    """Variables assigned the result of a PATH lookup."""
    return _matched_names(lines, _PATH_LOOKUP_ASSIGN_RE)


_FOR_LOOP_RE = re.compile(r"^\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b")


def _loop_variable_names(lines: list[str]) -> set[str]:
    """Variables bound by a `for … in` loop.

    A loop variable is iteration, not assembly: `${_arch}-cmake` inside
    `for _arch in …` names a real program (`x86_64-w64-mingw32-cmake`) for
    every value the loop takes, and the value is the loop *list*, not a
    hidden string.  The tokenizer does not fold a loop binding, so without
    this X002 scored the build target CRITICAL.
    """
    return _matched_names(lines, _FOR_LOOP_RE)


_ARRAY_ASSIGN_OPEN_RE = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]{0,40}\])?\+?=\s*\("
)

def _quote_open_at_end(text: str, quote: str | None) -> str | None:
    """The quote character still open when *text* ends, or None.

    Carried across lines, because a quoted string is allowed to span them::

        eval "package_$i()
          $(declare -f _package_x11 | tail +2)"

    The second line is the middle of a string. Read on its own it starts
    with `$(`, which is a command substitution in first position - and
    that is exactly what a rule looking for an assembled command name is
    hunting for. The difference is that this one is inside quotes somebody
    else opened.
    """
    index = 0
    while index < len(text):
        ch = text[index]
        if quote == "'":
            if ch == "'":
                quote = None
        elif quote == '"':
            if ch == "\\":
                index += 1
            elif ch == '"':
                quote = None
        elif ch == "\\":
            index += 1
        elif ch in "'\"":
            quote = ch
        index += 1
    return quote

def _unquoted_paren_delta(text: str) -> int:
    """``(`` minus ``)`` outside quotes, so a paren in a string does not count.

    ``sed 's/(/x/'`` inside an array would otherwise leave the depth
    counter raised for the rest of the file.
    """
    depth = 0
    quote = None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
    return depth

_DEP_ARRAY_OPEN_RE = re.compile(
    r"^\s*(?:depends|makedepends|optdepends|checkdepends)"
    r"(?:_[a-z0-9_]+)?\s*\+?=\s*\("
)

def _dependency_array_lines(lines: list[str]) -> set[int]:
    """Indices inside a dependency array's value.

    Tracked across ``+`` and context lines and abandoned on a removed one,
    like :func:`_continuation_lines`: a hunk can open the array and show
    only part of it.  The depth is counted outside quotes
    (:func:`_unquoted_paren_delta`), because an optdepends description may
    contain a paren that closes nothing.
    """
    out: set[int] = set()
    depth = 0
    for index, line in enumerate(lines):
        if line.startswith("-"):
            continue
        body = _strip_comment(line[1:] if line[:1] in "+ " else line)
        if depth > 0 or _DEP_ARRAY_OPEN_RE.match(body):
            out.add(index)
            depth = max(0, depth + _unquoted_paren_delta(body))
    return out

def _continuation_lines(raw_lines: list[str], joined_count: int) -> set[int]:
    """Joined-line indices whose command position belongs to an earlier line.

    ``join_line_continuations`` rejoins a backslash-continued command, but
    only across lines carrying the *same* diff marker. Editing the tail of
    one separates the halves with the removed version::

         httpdirfs "${_opts[@]}" \\
           --dl-seg-size 1 --single-file-mode \\
        -   "${_iso_url}" "${_http_mount}" > /dev/null
        +   "${_iso_url}" "${_http_mount}"

    The head is context and the tail is an addition, so the join never
    happens: the ``+`` line arrives alone and its first word - an argument
    to a command two lines up - reads as a command name. Every remaining
    benign-corpus hit on X002 was this shape.

    Removed lines are skipped when deciding what precedes a line, which is
    what reconnects the two halves. This is the same reasoning as the
    leading-flag rule in :func:`_command_words`: a line that continues
    another has no command position at all, so there is nothing on it for
    X002 to read. And it is not a way through: the continued command is the
    one on the head line, so a payload on the tail is an *argument* to it,
    which this rule has never claimed.

    Measured on the raw lines, because the joiner strips the backslash the
    measurement depends on, then mapped onto joined positions through
    ``_joined_indexed`` - the same pairing the rule path uses.
    """
    from ...tokenizer import joined_indexed

    carried_raw: set[int] = set()
    pending = False
    array_depth = 0
    test_depth = 0
    quote: str | None = None
    for index, line in enumerate(raw_lines):
        if line.startswith("-"):
            # Including `---`: a file header is not part of any command.
            continue
        raw_body = line[1:] if line[:1] in "+ " else line
        # A `#` inside an open string is not a comment.
        body = raw_body if quote else _strip_comment(raw_body)
        if pending or array_depth > 0 or test_depth > 0 or quote:
            carried_raw.add(index)
        # `if ! [[` on one line and the condition on the next: the
        # condition is not a command, and read alone its first word is
        # whatever the test compares.
        test_depth = max(0, test_depth + body.count("[[") - body.count("]]"))
        quote = _quote_open_at_end(body, quote)
        # An array literal spanning lines: `depends=(` then a line per
        # entry. Those entries are data, and one of them - `"${_depends[@]}"`
        # in a split package - read as a command word the moment split
        # packages came into scope. The opening line is an assignment and
        # is skipped anyway; what needed tracking is everything up to the
        # closing paren.
        if array_depth > 0 or _ARRAY_ASSIGN_OPEN_RE.match(body):
            array_depth = max(0, array_depth + _unquoted_paren_delta(body))
        stripped = body.rstrip()
        # A trailing backslash continues the line, unless it is itself
        # escaped (`printf 'x\\\\'`).
        pending = stripped.endswith("\\") and not stripped.endswith("\\\\")

    if not carried_raw:
        return set()
    pairs = joined_indexed(raw_lines)
    if len(pairs) != joined_count:
        # The two joiners are documented to agree; if they ever do not,
        # drop the refinement rather than silence a line at the wrong index.
        return set()
    return {j for j, (raw_index, _text) in enumerate(pairs) if raw_index in carried_raw}

_DATA_CONSUMER = (
    r"(?:bsd)?tar|cpio|unzip|zcat|bzcat|xzcat|lzcat|zstdcat"
    r"|g?unzip|gzip|bunzip2|bzip2|unxz|xz|unzstd|zstd|unlz4|lz4|lzma|unlzma"
    r"|brotli|lrzip|uncompress"
    r"|grep|e?grep|f?grep|rg|ag|ack|sed|awk|gawk|mawk|nawk|cut|tr|sort|uniq"
    r"|head|tail|wc|jq|yq|xmllint|xmlstarlet|column|tac|rev|fold|paste|join"
    r"|comm|split|csplit|nl|expand|unexpand|fmt|pr|shuf|numfmt|strings|file"
    r"|iconv|dos2unix|unix2dos|recode"
    r"|tee|cat|dd|sponge|install|patch|git|diff|cmp|pv|less|more|bat"
    r"|(?:sha[0-9]+|md5|b2)sum|cksum|openssl|gpg[v2]?|minisign|signify"
    r"|base32|base64|basenc|xxd|od|hexdump"
    r"|ffmpeg|convert|magick|gm|inkscape|rsvg-convert|optipng|potrace"
    r"|desktop-file-validate|appstream-util|msgfmt|msgcat|gettext"
)

_PIPE_WRAPPER_RE = re.compile(
    r"\A(?:(?:env|command|exec|sudo|doas|nice|ionice|stdbuf|timeout|nohup"
    r"|setsid|unbuffer|script|LC_ALL=\S+|LANG=\S+|[A-Z_]+=\S*)"
    r"(?:\s+-[-\w]+)*\s+)+",
)

def _pipeline_sink(body: str) -> str | None:
    """The command word after the last unquoted `|`, or ``None``.

    Quoting matters: `echo "a|b" | tar` has one pipe, not two, and reading
    the wrong one names `b"` as the sink.
    """
    depth_s = depth_d = False
    cut = -1
    for i, ch in enumerate(body):
        if ch == "'" and not depth_d:
            depth_s = not depth_s
        elif ch == '"' and not depth_s:
            depth_d = not depth_d
        elif ch == "|" and not depth_s and not depth_d:
            # `||` is an operator between commands, not a pipe - so it
            # *ends* the pipeline rather than voiding it. Returning None
            # here discarded the whole line, and `curl u | bash || true`
            # is how nearly every probe in the audit spells the shape:
            # the fallback is there so a failing payload does not fail the
            # build, and it hid the pipe that preceded it.
            if body[i - 1:i] == "|" or body[i + 1:i + 2] == "|":
                break
            cut = i
    if cut < 0:
        return None
    tail = body[cut + 1:].lstrip()
    tail = _PIPE_WRAPPER_RE.sub("", tail)
    # `xargs` runs what follows it, so the sink is that command and not
    # `xargs` itself: `fswatch … | xargs -0 -I{} bash x.sh` ends in a
    # shell. Its flags may carry braces (`-I{}`), which the general
    # wrapper pattern does not allow.
    xargs = re.match(r"xargs\b((?:\s+-[^\s]+)*)\s+", tail)
    if xargs:
        tail = tail[xargs.end():]
    word = re.split(r"[\s;&|<>()]", tail, maxsplit=1)[0]
    return word.strip("\"'") or None

def _resolved_records(found: dict) -> dict:
    """The kept records after resolution, each carrying ``resolved_by``.

A record is ``(line, shape, quoted, resolved_by)``. A yielded
    record is not emitted, so every emitted record owns its line and its
    ``resolved_by`` is ``None``; :func:`resolve_ownership_audit` keeps the
    yielded records and names their owner.
    """
    if not found:
        return found
    winner = _ownership_yields(found)
    resolved: dict = {}
    for rule_id, hits in found.items():
        kept = []
        for hit in hits:
            owner = winner.get(hit[0])
            if owner and owner != rule_id:
                continue
            kept.append((hit[0], hit[1], hit[2], None))
        if kept:
            resolved[rule_id] = kept
    return resolved
