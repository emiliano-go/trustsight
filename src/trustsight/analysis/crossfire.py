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
_EXECUTING_SCOPES = (
    "prepare", "build", "check", "package", "pkgver",
    "post_install", "post_upgrade", "pre_install",
    "pre_upgrade", "pre_remove", "post_remove",
)

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
    ("variable", re.compile(r"^[\"']?\$\{?!?[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]{0,40}\])?\}?")),
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
    ("trace-off", re.compile(_CMD + r"set\s+\+[a-z]*x(?=\s|;|$)", re.MULTILINE)),
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
    ("literal-home", re.compile(r"(?:^|[\s\"'=])/home/+(?:\$\{?\w+\}?|[A-Za-z0-9._-]+)/")),
    # Tilde-user expansion: ~alice/ is $HOME for alice, and dodges `^~/`.
    ("tilde-user", re.compile(r"(?:^|[\s\"'=])~[A-Za-z0-9._-]+/")),
    # root's home.
    ("root-home", re.compile(r"(?:^|[\s\"'=])/root/")),
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

_SOURCE_FIELD_RE = re.compile(r"^\s*(?:source|patches|_?url)\w*\s*(?:\+)?=", re.IGNORECASE)

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
_WRAPPERS = frozenset({
    "env", "exec", "sudo", "doas", "nohup", "command", "builtin", "time",
    "nice", "ionice", "timeout", "xargs", "setsid", "stdbuf", "unbuffer",
    "script", "eval", "then", "else", "do", "!",
})

#: A redirection can precede the command: `>out ${A[0]} x`.
_REDIRECT_RE = re.compile(r"^\d?[<>]")

#: An expression context: nothing inside names a command.
_EVALUATION_RE = re.compile(r"^(?:\(\(|\[\[|\[\s|test\s)")

#: A number is an argument to a wrapper (`timeout 5 cmd`), not a command.
_NUMERIC_RE = re.compile(r"^\d+$")


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
        for token in part.split():
            word = token.lstrip("({")
            if not word:
                continue
            if _ASSIGNMENT_RE.match(word):
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
                continue
            if word.strip("\"'") in _WRAPPERS:
                seen_wrapper = True
                continue
            bare = _PLAIN_VAR_RE.match(word)
            if bare and bare.group(1) in resolvable:
                break
            yield word
            break


#: A plain scalar variable used as a command: `$DKMS`, `${MAKE}`.  An array
#: subscript or a nameref is deliberately not this shape.
_PLAIN_VAR_RE = re.compile(r"^[\"\']?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")


def crossfire_techniques(diff_text: str) -> dict[str, list[tuple[int, str, str]]]:
    """``{rule_id: [(line, shape, quoted), ...]}`` for every technique found.

    Returned as data rather than findings so X007 can count techniques
    without re-deriving them, and so a caller can ask "what evasion is in
    this diff" without going through the scorer.
    """
    lines = join_line_continuations(clamp_text(diff_text).splitlines())
    from ..rules import _classify_enclosing_function
    from ..tokenizer import _variable_table

    enclosing = _classify_enclosing_function(lines)
    # Names the tokenizer reduced to a literal value. A command word that
    # resolves is not an evasion; one that does not is the whole point.
    try:
        var_table, _array_table = _variable_table([
            ln[1:] for ln in lines
            if (ln.startswith("+") or ln.startswith(" ")) and not ln.startswith("+++")
        ])
        resolvable = frozenset(var_table)
    except Exception:
        resolvable = frozenset()
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
        executing = enclosing.get(index) in _EXECUTING_SCOPES

        # X006 reads the source array, which lives outside any function.
        if _SOURCE_FIELD_RE.match(body) or "source=" in body or "patches=" in body:
            for shape, pattern in X006_SHAPES:
                if pattern.search(body):
                    record("X006", line_no, shape, body.strip())
        else:
            for shape, pattern in X006_SHAPES:
                if pattern.search(body):
                    record("X006", line_no, shape, body.strip())

        if not executing:
            continue

        if X001_RE.search(body):
            record("X001", line_no, "decode-to-shell", body.strip())

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
