"""Extracted from crossfire.py: _x01_x08."""

from __future__ import annotations
import re
from ...config import (
    DECOMPRESSOR as _DECOMPRESSOR,
    STRUCTURED_EXTRACTOR as _STRUCTURED_EXTRACTOR,
)
from ._common import _CMD, _CONFUSABLE_CHARS, _INTERPRETER_DECODE, _SHELL, _SHELL_CMD

__all__ = ['X001_RE', 'X002_SHAPES', 'X003_SHAPES', 'X004_SHAPES', 'X006_SHAPES']

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
    # Every character must be a name character or a confusable: a confusable
    # impersonates an ASCII letter *inside a command name*, so a word that is
    # pure non-Latin (a CJK install-hook message, `首次使用需扫码登录`) names no
    # command and must not match.  A whole fullwidth-Latin word (`ｃｕｒｌ`) is
    # all confusables and still matches.
    ("homoglyph", re.compile(
        r"^(?=[^\s]*[" + _CONFUSABLE_CHARS + r"])"
        r"[A-Za-z0-9_./\-" + _CONFUSABLE_CHARS + r"]+$")),
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
