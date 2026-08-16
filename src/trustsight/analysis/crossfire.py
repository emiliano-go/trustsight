"""Crossfire: the evasion technique, not the payload it hides.

Every other family here fires on what a diff *does*. These fire on how it was
*written*. The distinction is not stylistic - it is a response to where the
detection actually failed.

The rules held. The tokenizer that feeds them did not: partial quoting
(``c"u"rl``), array routing (``${A[0]}``), namerefs, and command substitution
(``$(printf '\\x63...')``) all reconstruct an executable name that no pattern
over the resolved text ever sees, because resolution is the step that broke.
Closing each of those in the tokenizer means teaching it to expand more, which
is slow, risky, and trades one bypass for an over-expansion bug.

Crossfire inverts the problem instead. **A word the tokenizer could not
resolve literally is itself the signal.** One rule then covers the evasion
surface of every payload rule at once - R001, R127, R137 and the rest - because
it does not care which payload was being hidden, only that hiding happened.

The failure mode inverts with it. Today a defeated tokenizer produces silence,
which is the worst possible output: the analysis looks clean precisely when it
understood least. Here a defeated tokenizer produces a CRITICAL finding. The
bypass and the alarm become the same event, so cleverness cannot buy quiet.

**What this family is not.** It is not a substitute for fixing the tokenizer,
and it must not become an excuse to stop. A payload written plainly and hidden
by a technique nobody anticipated still gets through; crossfire raises the cost
of evasion, it does not bound it. And it deliberately claims no bytes another
rule already claims: X008 (bidi and homoglyphs) is absent because
[R013](../../docs/reference/rules/deception.md) is FATAL and already covers
those codepoints, and scoring the same characters twice would corrupt the
calibration the project measures.

Every rule here was measured against the 3,739-diff locked benign corpus
before it was given a weight. The rates are in the reference page; the short
version is that legitimate PKGBUILDs do not do these things.
"""

from __future__ import annotations

import re

from ..deps import _strip_comment
from ..rules import clamp_text, join_line_continuations

#: Functions makepkg runs, plus the scriptlets pacman runs as root. A
#: technique only matters where something executes.
#:
#: Kept for documentation and for the split-package prefix below; the gate
#: itself is :func:`_executes`, because this list was an allowlist and an
#: allowlist of function names is a rename away from empty.
_EXECUTING_SCOPES = (
    "prepare", "build", "check", "package", "pkgver",
    "post_install", "post_upgrade", "pre_install",
    "pre_upgrade", "pre_remove", "post_remove",
)


#: Files whose every line is shell: the recipe, pacman's scriptlets, and any
#: shell companion the recipe ships. A `.patch` is excluded even though it
#: contains shell-looking text - the text is a payload for `patch`, and the
#: rules that read a patch are R063's, not these.
_SHELL_FILE_RE = re.compile(
    r"(?:^|/)(?:PKGBUILD|[^/]*\.(?:install|sh|bash|zsh))$", re.IGNORECASE
)

_DIFF_TARGET_RE = re.compile(r"^\+\+\+ (?:b/)?(.+?)(?:\t.*)?$")


def _file_at_line(lines: list[str]) -> dict[int, str]:
    """``{line_index: path}`` from the diff's own ``+++`` headers.

    Which file a hunk belongs to decides whether its lines are shell at
    all. Without it the only available gate was "inside a function makepkg
    calls", which is both too narrow (top-level code runs when makepkg
    *sources* the recipe) and too broad (a `.desktop` file's lines are not
    shell in any scope).
    """
    files: dict[int, str] = {}
    current = None
    for index, line in enumerate(lines):
        match = _DIFF_TARGET_RE.match(line)
        if match:
            current = match.group(1).strip()
            continue
        if current is not None:
            files[index] = current
    return files


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

_CMD = r"(?:\A|(?<=[;&|(\n])|(?<=&&)|(?<=\|\|)|^)\s*"

# ---------------------------------------------------------------------------
# X001: an encoding decoded straight into a shell.
#
# Base64 is deliberately absent: R003 and R043 claim it at CRITICAL already.
# What is left uncovered is every *other* encoding, and the Atomic Arch second
# wave used hex.
# ---------------------------------------------------------------------------

#: A shell, however it is spelled: `sh`, `/bin/bash`, `env sh`.  Naming
#: it by absolute path or behind `env` was an evasion of the first draft.
_SHELL = (r"(?:/(?:usr/)?bin/)?(?:ba|z|da|k)?sh\b|"
          r"(?:env|exec|command)\s+(?:/(?:usr/)?bin/)?(?:ba|z|da|k)?sh\b")

X001_RE = re.compile(
    # A hex or octal escape blob piped into a shell.
    r"(?:printf|echo\s+-e|/bin/echo\s+-e)[^\n|;&]{0,200}"
    r"(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3})[^\n|;&]{0,200}\|\s*(?:" + _SHELL + r")|"
    # A hex dump reversed and piped into a shell.
    r"\b(?:xxd\s+-r|od\s+-An|hexdump)\b[^\n|;&]{0,200}\|\s*(?:" + _SHELL + r")|"
    # The decoders that are not `base64`. R003 and R043 claim that one
    # spelling; `base32 -d`, `openssl enc -d` and `uudecode` decode the same
    # payload into the same shell and were claimed by nobody.
    r"\b(?:base32\s+-d|basenc\s+--\w+\s+-d|uudecode|openssl\s+enc\b[^\n|;&]{0,80}\s-d)\b"
    r"[^\n|;&]{0,200}\|\s*(?:" + _SHELL + r")|"
    # An ANSI-C quoted blob executed via eval or a shell.
    r"\b(?:eval|" + _SHELL + r")\s+\$'(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}){3,}|"
    # tr-based rotation (ROT13 and friends) fed to a shell.
    r"\btr\s+[^\n|;&]{0,80}\|\s*(?:" + _SHELL + r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# X002: the executable name is not a literal.
#
# The one that pays for the family. Zero hits on the benign corpus, and it
# catches every tokenizer bypass found so far, because each of them works by
# assembling a command name the parser cannot read.
# ---------------------------------------------------------------------------

# An assignment is not a command: `font=$(grep ...)` names no executable, and
# the corpus's only near-misses were exactly that shape.
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]{0,40}\])?\+?=")

# Markdown fences and prose survive into diffs of README-ish files.
_FENCE_RE = re.compile(r"^\s*(?:```|~~~|#|//|\*|-\s)")

def _confusable_class() -> str:
    """The confusable characters, as a regex character class.

    Reuses the curated map rather than a second list: a character that
    impersonates ASCII is the same set whether it appears in a domain
    (R013b) or in a command name.
    """
    from ..buckets import _CONFUSABLE_TO_LATIN

    return "".join(re.escape(ch) for ch in sorted(_CONFUSABLE_TO_LATIN))


_CONFUSABLE_CHARS = _confusable_class()


X002_SHAPES = (
    # ${A[0]}, $cmd, ${!ref} - a variable in command position.
    #
    # The word must *be* the variable, or continue into more name
    # characters (`${D}url` assembles a name). A `/` after it means the
    # variable named a directory and the executable is spelled out:
    # `"$srcdir/calibre-release/calibre-debug"` hides nothing, and matching
    # it made X002 fire CRITICAL on ordinary in-tree test invocations.
    # Three spellings, because a `/` means opposite things on the two
    # sides of a brace.
    #
    # Inside `${...}` it is parameter expansion, and any operator there is
    # assembling a name: `${c//X/}` turns `XurlX` into `curl`, which is a
    # bypass this family has to hold. Outside, it is a path separator, and
    # `"$srcdir/calibre-release/calibre-debug"` names its executable in
    # plain text - the directory came from a variable and nothing is
    # hidden. Matching that made X002 fire CRITICAL on ordinary in-tree
    # test invocations.
    #
    # The `(?![A-Za-z0-9_])` on the bare form is load-bearing: without it
    # the name could match a *prefix* and the "continues into more name
    # characters" alternative would match the rest of its own name, so
    # `"${pkgdir}/etc/x.conf"` read as `${pkgdi}` + `r`.
    ("variable", re.compile(
        # ${!ref} - indirect expansion is assembly by definition.
        r"^[\"']?\$\{!"
        # ${A[0]}, ${c//X/}, ${c,,}, ${a[@]:0:1} - an operator inside.
        # The name is maximal here too, or `${srcdir}/x` matches as
        # `${srcdi` + `r` + `}`, which is the same prefix backtrack again.
        r"|^[\"']?\$\{[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])[^}\s]+\}"
        # $cmd, ${cmd}, ${D}url - the word is the variable, or grows a name.
        r"|^[\"']?\$\{?[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_])\}?"
        r"(?:[\"']?$|[A-Za-z0-9_.-])")),
    # $(...) or `...` producing the command name.
    ("substitution", re.compile(r"^[\"']?(?:\$\(|`)")),
    # c"u"rl, c'u'rl - quotes inside a word the shell then joins.
    ("partial-quote", re.compile(r"^[A-Za-z0-9_./-]*[\"'][^\"']{0,40}[\"'][A-Za-z0-9_./-]")),
    # $'\x63\x75\x72\x6c' - an ANSI-C string as the command.
    ("ansi-c", re.compile(r"^\$'")),
    # cur{l,} - brace expansion assembling the name. Not `${...}`, which the
    # variable shape above already claims.
    ("brace-expansion", re.compile(r"^(?!\$)[^\s{}]*\{[^}]{0,60}(?:,|\.\.)[^}]{0,60}\}")),
    # A character that *impersonates* an ASCII letter: `\u0441url` reads as
    # `curl` and is not it. Deliberately not "any non-ASCII" - that fired on
    # ordinary English prose carrying a typographic apostrophe, which
    # impersonates nothing and names no command. The curated map from
    # `buckets` is the same one R013b uses for domains.
    ("homoglyph", re.compile(r"^[^\s]{0,60}[" + _CONFUSABLE_CHARS + r"]")),
    # There is deliberately no `escaped-character` shape for `c\url`.
    #
    # It was added here first, because the tokenizer kept the backslash and
    # the name never reconstructed - so that spelling reached no rule at
    # all, R001 included, and this family was the only thing standing under
    # it. The tokenizer now removes the escape
    # (`tokenizer._ESCAPE_REMOVABLE`), which is the actual fix: every rule
    # that reads a command name sees `curl` again, not just this one.
    #
    # With the name resolved, claiming it here would score one command
    # twice - the same reason `curl""` has no shape either, and the same
    # reason X008 does not exist beside R013. This module's own warning is
    # that it must not become an excuse to stop fixing the tokenizer; a
    # shape retired because the tokenizer caught up is that working.
)

_FIRST_WORD_RE = re.compile(r"^\s*([^\s;&|<>]+)")


# ---------------------------------------------------------------------------
# X003: the argument is obfuscated rather than the command.
# ---------------------------------------------------------------------------

X003_SHAPES = (
    # curl/wget long options cut to a unique prefix: --upload-f for
    # --upload-file. Legitimate recipes spell options out.
    ("truncated-option", re.compile(
        r"\b(?:curl|wget)\b[^\n|;&]{0,200}?\s--(?:upload-f|dat|outp|hea|loca|"
        r"inse|conf|remote-na|post-f)[a-z]*(?=\s|$)")),
    # A shell invoked with its options stuffed together: bash -lc, sh -ec.
    # `sh -c` is ordinary; `sh -lc` / `bash -ec` stuffs extra
    # options in front of -c, which is how a payload gets a login shell
    # or error suppression without a second command.
    ("option-stuffing", re.compile(r"\b(?:ba|z|da|k)?sh\s+-[a-z]+c(?=\s|$)")),
    # An IP written in octal, hex or as a single integer, inside a URL.
    ("encoded-host", re.compile(
        r"https?://(?:0\d{1,3}\.[0-9.]{1,15}|0x[0-9a-fA-F]{2,8}(?:\.|/|:)|\d{8,10}(?:/|:|$))")),
)

# ---------------------------------------------------------------------------
# X004: the build hides its own output.
#
# Bare `2>/dev/null` is excluded: it is ordinary defensive shell and fires on
# 0.481% of the benign corpus, which is small but is noise rather than signal.
# The three forms kept fire on zero.
# ---------------------------------------------------------------------------

X004_SHAPES = (
    ("term-dumb", re.compile(r"\bTERM\s*=\s*dumb\b")),
    # `set +x` and its long spelling. `set +o xtrace` is the same
    # instruction and used to walk past the short form's pattern, which
    # required the `x` to end the option cluster.
    ("trace-off", re.compile(
        _CMD + r"set\s+(?:\+[a-z]*x(?=\s|;|$)|\+o\s+(?:xtrace|verbose)\b)",
        re.MULTILINE)),
    ("stderr-detached", re.compile(r"\bexec\s+\d?>\s*(?:/dev/null|&-)")),
)

# ---------------------------------------------------------------------------
# X005: the home directory, reached by a spelling that dodges the check.
#
# R077 claims a write whose target starts with `~/` or `$HOME/`, plus any
# rc-file basename. That is the obvious spelling, and it is the one an
# attacker will not use. The same directory is reachable as
# `/home/alice/...`, `~alice/...`, `/root/...`, `/home/$USER/...`,
# `${HOME:-/home/alice}/...`, or by traversing into it - and none of those
# start with the prefix R077 looks for.
#
# This is the family's thesis applied to a path: the technique is the signal.
# Choosing `/home/$USER/bin` over `$HOME/bin` is a choice, and the only thing
# it buys is getting past a check.
#
# It **defers** to R077 rather than doubling it: a target R077 already claims
# is skipped here, so one write is scored once.
# ---------------------------------------------------------------------------

#: What R077 already matches.  X005 stands down on these.
_R077_CLAIMS_RE = re.compile(r"^[\"']?(?:~|\$\{?HOME\}?)/")

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
    ("home-default", re.compile(r"\$\{HOME[:-][=+-][^}]{0,80}\}")),
    # Traversal that explicitly aims at a home directory.
    ("traversal-home", re.compile(r"(?:\.\./){1,8}(?:home|root)/")),
)

#: The write, allowing the same prefixes X002 walks past: an assignment or
#: a wrapper before `cp` does not stop it being a copy.
_WRITE_PREFIX = r"(?:[A-Za-z_]\w*=\S*\s+|(?:env|sudo|doas|exec|nohup|command|timeout|nice)\s+)*"

_WRITE_COMMAND_RE = re.compile(
    _CMD + _WRITE_PREFIX +
    r"(?:install|cp|mv|tee|ln|mkdir|touch|rsync|dd|chmod|chown|sed)\b|"
    r">>?\s*[\"']?(?=\S)",
    re.MULTILINE,
)

#: makepkg's staging roots.  `$pkgdir/home/...` is packaging, not a write to
#: anybody's home.
_STAGED_RE = re.compile(r"\$\{?(?:pkgdir|srcdir|builddir|startdir)\}?", re.IGNORECASE)


def _home_alias_hit(body: str):
    """The alias shape this line uses to reach a home directory, or None."""
    if _STAGED_RE.search(body):
        return None
    if not _WRITE_COMMAND_RE.search(body):
        return None
    for shape, pattern in _HOME_ALIASES:
        match = pattern.search(body)
        if not match:
            continue
        # Defer to R077 when the target is spelled the plain way.
        target = match.group(0).lstrip(" \t\"'=")
        if _R077_CLAIMS_RE.match(target):
            continue
        return shape
    return None


# ---------------------------------------------------------------------------
# X006: the source points somewhere unexpected.
#
# Domain reputation and upstream-owner matching are deliberately absent: the
# novelty tier already scores a globally-first-seen URL, and an owner
# heuristic is too brittle for a decentralised repository. What is left is the
# two forms that are never legitimate in a source array.
# ---------------------------------------------------------------------------

X006_SHAPES = (
    ("url-shortener", re.compile(
        r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly|rb\.gy|"
        r"cutt\.ly|shorturl\.at|s\.id|rebrand\.ly)/", re.IGNORECASE)),
    ("raw-ip-source", re.compile(
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)")),
)




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


#: Commands that run another command, so the *next* word is the real one.
#: An attacker who writes `env ${A[0]} ...` has still routed the name through
#: an array; the wrapper only moves it one token to the right.
#:
#: ``eval`` is deliberately absent. It runs another command like the rest,
#: but R039 already claims eval-of-dynamic-content, and this family's own
#: rule is that it never scores bytes another rule scores - the reason X008
#: does not exist beside R013. Treating it as a wrapper made X002 fire a
#: second CRITICAL on `eval "$(updpkgsrcs ...)"`, which was both benign and
#: already R039's.
#:
#: ``if``/``elif``/``while``/``until`` are here for the opposite reason:
#: each takes a *command* whose exit status it tests, so `if ${A[0]} x;
#: then` runs the array-routed name exactly as `${A[0]} x` does, and the
#: scan used to stop at the keyword and never look. ``for`` is not here -
#: the word after it is a loop variable, not a command.
_WRAPPERS = frozenset({
    "env", "exec", "sudo", "doas", "nohup", "command", "builtin", "time",
    "nice", "ionice", "timeout", "xargs", "setsid", "stdbuf", "unbuffer",
    "script", "then", "else", "do", "!",
    "if", "elif", "while", "until",
})

#: A redirection can precede the command: `>out ${A[0]} x`.
_REDIRECT_RE = re.compile(r"^\d?[<>]")

#: An expression context: nothing inside names a command.
_EVALUATION_RE = re.compile(r"^(?:\(\(|\[\[|\[\s|test\s)")

#: A number is an argument to a wrapper (`timeout 5 cmd`), not a command.
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


def _command_words(body: str, resolvable: frozenset[str] = frozenset()):
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
                continue
            if word.strip("\"'") in _WRAPPERS:
                seen_wrapper = True
                wrapper = word.strip("\"'")
                continue
            bare = _PLAIN_VAR_RE.match(word)
            if bare and bare.group(1) in resolvable:
                break
            yield word
            break


#: A plain scalar variable used as a command: `$DKMS`, `${MAKE}`.  An array
#: subscript or a nameref is deliberately not this shape.
_PLAIN_VAR_RE = re.compile(r"^[\"\']?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")

#: `DKMS=$(which dkms)` then `$DKMS add ...`: a PATH lookup names its
#: executable *literally* inside the substitution, so the command is not
#: hidden from anything - it is spelled out one line up, and every payload
#: rule reads that line. The tokenizer cannot fold it, so the name stayed
#: unresolvable and X002 fired CRITICAL on it; it was the whole of the rule's
#: remaining benign-corpus rate outside `eval`.
#:
#: Narrow on purpose. It exempts the discovery idiom, not assignment in
#: general: `CMD=$(printf '\x63\x75\x72\x6c')` assembles a name that appears
#: nowhere, and stays an evasion.
_PATH_LOOKUP_ASSIGN_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)=[\"']?\$\(\s*"
    r"(?:which|type\s+-p|command\s+-v)\s+[A-Za-z0-9_.+-]+\s*\)",
)


def _path_lookup_names(lines: list[str]) -> set[str]:
    """Variables assigned the result of a PATH lookup."""
    names = set()
    for line in lines:
        match = _PATH_LOOKUP_ASSIGN_RE.match(line)
        if match:
            names.add(match.group(1))
    return names


#: `depends=(`, `source+=(`, `_arr[0]=(` - an assignment opening an array
#: literal.  A bare `(` is a subshell, whose contents *are* commands, so the
#: two are told apart by what precedes the paren rather than by the paren.
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
    from ..tokenizer import _joined_indexed

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
    pairs = _joined_indexed(raw_lines)
    if len(pairs) != joined_count:
        # The two joiners are documented to agree; if they ever do not,
        # drop the refinement rather than silence a line at the wrong index.
        return set()
    return {j for j, (raw_index, _text) in enumerate(pairs) if raw_index in carried_raw}


def crossfire_techniques(diff_text: str) -> dict[str, list[tuple[int, str, str]]]:
    """``{rule_id: [(line, shape, quoted), ...]}`` for every technique found.

    Returned as data rather than findings so X007 can count techniques
    without re-deriving them, and so a caller can ask "what evasion is in
    this diff" without going through the scorer.
    """
    raw_lines = clamp_text(diff_text).splitlines()
    lines = join_line_continuations(raw_lines)
    from ..rules import _classify_enclosing_function
    from ..tokenizer import _variable_table

    enclosing = _classify_enclosing_function(lines)
    files = _file_at_line(lines)
    # Names the tokenizer reduced to a literal value. A command word that
    # resolves is not an evasion; one that does not is the whole point.
    readable = [
        ln[1:] for ln in lines
        if (ln.startswith("+") or ln.startswith(" ")) and not ln.startswith("+++")
    ]
    try:
        var_table, _array_table = _variable_table(readable)
        resolvable = frozenset(var_table) | _path_lookup_names(readable)
    except Exception:
        resolvable = frozenset(_path_lookup_names(readable))
    carried = _continuation_lines(raw_lines, len(lines))
    found: dict[str, list[tuple[int, str, str]]] = {}

    def record(rule_id, line_no, shape, quoted):
        found.setdefault(rule_id, []).append((line_no, shape, quoted[:120]))

    for index, line in enumerate(lines):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        raw = line[1:]
        if _FENCE_RE.match(raw):
            continue
        body = _strip_comment(raw)
        if not body.strip():
            continue
        line_no = index + 1
        # Which file the line is in decides whether it is shell; the
        # function it sits in no longer decides anything, because
        # *top-level* code runs when makepkg sources the recipe - before
        # any build step, and before any rule that reads a function body.
        # A diff with no `+++` header (a fragment handed straight to
        # `scan_diff`) keeps the old function gate rather than losing
        # detection: unknown fails toward looking.
        path = files.get(index)
        if path is None:
            executing = _executes(enclosing.get(index))
        else:
            executing = bool(_SHELL_FILE_RE.search(path))

        # X006 is checked on every line, not only a `source=` one: the two
        # shapes it carries - a URL shortener and a raw-IP host - are never
        # legitimate anywhere in a recipe, and a fetch inside `build()` is
        # the same fact as one in the source array. This was written as an
        # if/else whose branches were identical, so the source-field test
        # decided nothing; it is stated once instead.
        for shape, pattern in X006_SHAPES:
            if pattern.search(body):
                record("X006", line_no, shape, body.strip())

        if not executing:
            continue

        if X001_RE.search(body):
            record("X001", line_no, "decode-to-shell", body.strip())

        # X002 is the one position-sensitive rule here, so it is the one
        # that must stand down on a line whose command position lives
        # further up. The rest match on content and are unaffected.
        if index not in carried:
            for word in _command_words(body, resolvable):
                for shape, pattern in X002_SHAPES:
                    if pattern.match(word):
                        record("X002", line_no, shape, body.strip())
                        break

        for shape, pattern in X003_SHAPES:
            if pattern.search(body):
                record("X003", line_no, shape, body.strip())

        for shape, pattern in X004_SHAPES:
            if pattern.search(body):
                record("X004", line_no, shape, body.strip())

        alias = _home_alias_hit(body)
        if alias:
            record("X005", line_no, alias, body.strip())

    return found


_NAMES = {
    "X001": ("Encoded Payload Decoded To A Shell", "CRITICAL"),
    "X002": ("Non-Literal Executable Name", "CRITICAL"),
    "X003": ("Obfuscated Command Argument", "HIGH"),
    "X004": ("Build Output Suppressed", "MEDIUM"),
    "X005": ("Home Reached By An Alternative Spelling", "HIGH"),
    "X006": ("Source Points Somewhere Unexpected", "HIGH"),
}

#: How many distinct techniques make a diff X007.  Two, because one technique
#: can be an accident of style and two in one diff is a method.
X007_MIN_TECHNIQUES = 2


def _crossfire_findings(diff_text, config, add) -> None:
    """Emit X001-X006 and the X007 cluster.

    Each rule reports once per diff: a second `${A[0]}` tells the reader
    nothing the first did not, and counting occurrences would let a noisy
    recipe outscore a careful attack.
    """
    techniques = crossfire_techniques(diff_text)

    for rule_id in ("X001", "X002", "X003", "X004", "X005", "X006"):
        hits = techniques.get(rule_id)
        if not hits:
            continue
        line_no, shape, quoted = hits[0]
        name, severity = _NAMES[rule_id]
        add(rule_id, name, severity, "evasion",
            f"{shape}: {quoted}", line=line_no, shape=shape, body=quoted)

    if len(techniques) >= X007_MIN_TECHNIQUES:
        shapes = ", ".join(sorted(techniques))
        add("X007", "Multiple Evasion Techniques", "CRITICAL", "evasion",
            f"{len(techniques)} evasion techniques in one diff: {shapes}",
            line=None, count=len(techniques), techniques=shapes)
