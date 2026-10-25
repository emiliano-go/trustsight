"""X026-X031: the refusal family.

X001-X025 detect *catalogued* hiding techniques; an unanticipated one
passes.  These rules close the hole by widening what counts as a signal:
an unresolved construct in an executable position (X026/X027), ANSI-C
spelling in a command (X030), encoded material at rest (X029), a build
reading its own recipe (X031), and - with recorded history - a pattern
completed across commits (X028, in the pipeline where history lives).

Every rule reads the typed core: ``RecipeDoc.unresolved``/``functions``
and ``DiffDoc`` projections, never a fresh text walk.
"""

from __future__ import annotations

import re

#: The functions an unresolved assignment must be *referenced from* to be
# in an executable position. Top-level metadata is not.
_EXECUTABLE_FUNCTIONS = ("build", "prepare", "check", "package")

#: A ``$name`` / ``${name}`` reference, including a subscript.
def _references(name: str) -> re.Pattern:
    return re.compile(r"\$\{?" + re.escape(name) + r"(?:\}|\b|\[)")


def _executes(name: str, body: str) -> bool:
    """Whether *name* can reach a command rather than only data.

    An unresolved value in a URL, a ``-j`` argument or a test is a boundary,
    not an execution: ``jobs`` from ``nproc`` and ``uv_ver`` from ``sed`` are
    build data.  X026 is about the value the shell will *run*, so only a
    command word, an interpreter/source/eval target, ``xargs``/``find -exec``
    or a command substitution counts.
    """
    from ..deps import _strip_comment
    from ..tokenizer import join_line_continuations, split_lines
    from .crossfire._common import _command_words, _pipeline_sink, _split_commands

    ref = _references(name)
    target = re.compile(
        r"(?:^|[;&|(])\s*(?:[A-Za-z0-9_./-]+=|\S+\s+)*-*\s*"
        r"(?:bash|sh|zsh|dash|ksh|python[23]?|perl|ruby|node"
        r"|source|\.|eval)\b\s+(?:-[^\s]+\s+)*[\"']?" + ref.pattern,
        re.IGNORECASE,
    )
    declaration = re.compile(
        r"^\s*(?:local|declare|typeset|export|readonly)\b"
    )
    for raw in join_line_continuations(split_lines(body)):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        sink = _pipeline_sink(line)
        if (sink and ref.search(line.rsplit("|", 1)[0])
                and re.match(
                    r"(?:bash|sh|zsh|dash|ksh|python[23]?|perl|ruby"
                    r"|node|eval|xargs)\b", sink, re.IGNORECASE)):
            return True
        for part in _split_commands(line):
            part = part.strip()
            if not part or declaration.match(part):
                continue
            if ref.search(part) and any(ref.search(word) for word in _command_words(part)):
                return True
            if target.search(part):
                return True
            if re.search(r"-exec\s+[\"']?" + ref.pattern, part):
                return True
            if re.search(r"\$\(\s*[\"']?" + ref.pattern, part):
                return True
    return False


_ANSI_C_LITERAL_RE = re.compile(r"\$'((?:\\.|[^'\\])*)'")
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
_OCTAL_ESCAPE_RE = re.compile(r"\\0([0-7]{1,3})")
_CONTROL_ESCAPE_RE = re.compile(r"\\(?:e|a|v|f|b)")
_COMMAND_POSITION_LITERAL_RE = re.compile(
    r"(?:^|[;&|(]|\$\()\s*\$'((?:\\.|[^'\\])*)'", re.MULTILINE)

def _encoded_literal_classes(haystack: str, floor: int) -> list[str]:
    """The encoded-alphabet classes present above *floor* characters.

    The floor is ``[thresholds] x029.min_length`` (default 256).  The
    patterns are compiled here rather than fixed at import: the previous
    constants hardcoded ``{256,}`` while the configured floor was read and
    then ignored, so lowering the floor changed the finding text but not
    what fired.
    """
    floor = max(1, int(floor))
    classes: list[str] = []
    if re.search(
        rf"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{{{floor},}}={{0,2}}"
        r"(?![A-Za-z0-9+/=])",
        haystack,
    ):
        classes.append("base64")
    if re.search(
        rf"(?<![A-Z2-7])[A-Z2-7]{{{floor},}}={{0,6}}(?![A-Z2-7=])", haystack
    ):
        classes.append("base32")
    if re.search(rf"(?<![0-9A-Fa-f])[0-9A-Fa-f]{{{floor},}}(?![0-9A-Fa-f])",
                 haystack):
        classes.append("hex")
    return classes

_DECODER_RE = re.compile(
    r"\b(?:base64|base32|basenc)\b[^|;&\n]*\s(?:-d|--decode)\b"
    r"|\bb64decode\b|\batob\b|\bxxd\b[^|;&\n]*\s-r\b"
    r"|\bopenssl\b[^|;&\n]*\benc\b[^|;&\n]*\s-d\b"
    r"|\buudecode\b|\bbun\s+add\b|\bnpm\s+(?:i|install)\b"
    r"|\bpip\s+install\b",
    re.IGNORECASE,
)

# A self-read piped into an executor. The middle segment
#: allows further pipes, so `grep … PKGBUILD | cut … | bash` is the shape.
_SELF_READ_RE = re.compile(
    r"\b(?:cat|grep|cut|awk|sed|base64|strings|tail|head|sort|tr)\b"
    r"[^;&\n]*?(?:PKGBUILD|\$?\{?(?:srcdir|startdir)\}?/PKGBUILD)"
    r"[^;&\n]*?\|[^;&\n]*?(?:bash|sh|zsh|eval)\b",
    re.IGNORECASE,
)
_SELF_READ_EVAL_RE = re.compile(
    r"\beval\b[^|;&\n]*(?:PKGBUILD|\$?\{?(?:srcdir|startdir)\}?/PKGBUILD)",
    re.IGNORECASE,
)

#: A printable decoded ANSI-C literal that is a benign value: a path, a
#: flag, or a filename with an extension.  A bare word is a command
#: (`bun`), and a value with a space or a shell metacharacter is a
#: command line, so neither stands down.
_BENIGN_DECODED_RE = re.compile(
    r"^(?:/|\./|\.\./|~?/|-{1,2}[A-Za-z0-9-]+$"
    r"|[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+"
    r"|[A-Za-z0-9_-]+\.[A-Za-z0-9]+)$"
)


def _thresholds(config) -> dict:
    return (config or {}).get("thresholds", {})


def _unresolved_names(recipe) -> list[str]:
    from ..recipedoc import _ASSIGNMENT_SHAPE_RE

    names: list[str] = []
    for line in recipe.unresolved:
        match = _ASSIGNMENT_SHAPE_RE.match(line)
        if match and match.group(1) not in names:
            names.append(match.group(1))
    return names


#: A function-local declaration.  ``local kernver="$(make kernelrelease)"``
#: is build machinery, not a coverage boundary: X026/X027 still rate the
#: name (a malicious local inside ``build()`` fires there), but the W008
#: boundary list excludes it.
_FUNCTION_LOCAL_DECL_RE = re.compile(r"^(?:local|declare)\s")


def _reportable_unresolved_names(recipe) -> list[str]:
    """The W008-facing unresolved names: function locals excluded.

    A ``local``/``declare`` name inside a function body is ordinary build
    machinery; the name is still "not seen" to every rule, but naming it to
    the reader as a boundary trained them to skim the list.  Track the
    declared *name*, not the declaration line: the refusal is often a later
    ``name=$(command)`` assignment.
    """
    from ..recipedoc import _ASSIGNMENT_SHAPE_RE
    from ..tokenizer import split_lines

    local_names: set[str] = set()
    for body in recipe.functions.values():
        for raw in split_lines(body):
            raw = raw.strip()
            if not _FUNCTION_LOCAL_DECL_RE.match(raw):
                continue
            for token in raw.split()[1:]:
                if token.startswith("-"):
                    continue
                name = token.split("=", 1)[0].strip("\"'{}")
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                    local_names.add(name)
    names: list[str] = []
    for line in recipe.unresolved:
        match = _ASSIGNMENT_SHAPE_RE.match(line)
        if not match or match.group(1) in names:
            continue
        if match.group(1) in local_names:
            continue
        names.append(match.group(1))
    return names


def _added_stream(diff_text: str) -> str:
    """Only the added content lines of a diff, as a headerless stream."""
    from ..diffdoc import parse_diff_lines
    from ..tokenizer import split_lines

    doc = parse_diff_lines(split_lines(diff_text))
    return "\n".join(line.raw for line in doc.added_lines())


def pattern_across_commits(previous_diff: str, diff_text: str, add,
                           previous_commit: str = "",
                           current_commit: str = "") -> None:
    """X028: a technique completed by joining two consecutive diffs.

    Runs ``crossfire_techniques`` over the joined added-line stream and
    fires when it yields a technique *neither half yields alone* - the
    split array, the split literal, the pipeline whose source was added
    last push and whose sink is added now.  Gaps in history degrade to
    no-firing rather than guessing; the caller only passes the immediately
    preceding recorded review.  The two commit ids are cited in the
    finding when the caller supplies them.
    """
    if not previous_diff:
        return
    from .crossfire import crossfire_techniques

    previous_ids = set(crossfire_techniques(previous_diff))
    current_ids = set(crossfire_techniques(diff_text))
    joined = _added_stream(previous_diff) + "\n" + _added_stream(diff_text)
    joined_ids = set(crossfire_techniques(joined))
    new_ids = joined_ids - previous_ids - current_ids
    if new_ids:
        listed = ", ".join(sorted(new_ids))
        where = ""
        if previous_commit or current_commit:
            where = (f" (commits {previous_commit[:12] or '?'} -> "
                     f"{current_commit[:12] or '?'})")
        add("X028", "Pattern Completed Across Commits", "HIGH", "evasion",
            f"joining the previous recorded diff completes technique(s) "
            f"neither diff shows alone: {listed}{where}",
            line=None, techniques=listed,
            previous_commit=previous_commit, current_commit=current_commit)


def _recipe_post_doc(doc):
    """The post-state recipe of the PKGBUILD file only.

    ``recipe_states`` concatenates every file's post lines into one text,
    so a ``build() {`` whose closing brace sits outside the hunk leaves the
    function segment open and swallows whatever file section follows it:
    linux-mnt-reform-bin's hook locals (``DTB_TARGET=$(readlink …)`` in the
    ``.install`` hunk) were reported as referenced from ``build()``.  The
    refusal family reads the recipe, not the hook, so the projection is
    restricted to the PKGBUILD file.  A headerless fragment names no file;
    there the old whole-diff projection is kept.
    """
    from ..recipedoc import parse_recipe, recipe_from_post_state

    post_lines = [
        line for line in doc.lines
        if line.side in ("add", "context") and line.file == "PKGBUILD"
    ]
    if not post_lines:
        return recipe_from_post_state(doc)
    origins = [
        (line.file, line.new_lineno or 0, line.side) for line in post_lines
    ]
    return parse_recipe(
        "\n".join(line.content for line in post_lines), origins=origins)


def refusal_findings(diff_text: str, config, add, current_text=None,
                     previous_diff: str = "", previous_commit: str = "",
                     current_commit: str = "") -> None:
    """Emit X026/X027/X029/X030/X031 for one diff.

    ``add`` is the structural finding builder (same callable the crossfire
    family uses).  ``current_text`` is the post-state PKGBUILD when the
    caller holds it; the diff's own post projection is the fallback.
    """
    from ..diffdoc import parse_diff

    try:
        doc = parse_diff(diff_text)
        post = _recipe_post_doc(doc)
    except Exception:
        return
    if current_text:
        try:
            from ..recipedoc import parse_recipe

            post = parse_recipe(current_text, file="PKGBUILD")
        except Exception:
            pass

    # --- X026 / X027: refusals in executable positions -------------------
    names = _unresolved_names(post)
    referenced: list[tuple[str, list[str]]] = []
    for name in names:
        functions = [
            fn for fn in _EXECUTABLE_FUNCTIONS
            if _executes(name, post.functions.get(fn, ""))
        ]
        if functions:
            referenced.append((name, functions))
    min_count = int(_thresholds(config).get("x026", {}).get("min_count", 1))
    count = len(referenced)
    # X027 fires at two distinct names; X026's configurable floor can be
    # higher, but X027 must never orphan: the cluster invariant is "X027
    # implies X026 fired", so the cluster threshold also forces X026.
    cluster = count >= 2
    if count >= max(1, min_count) or cluster:
        # Capped at MEDIUM: a refusal is a boundary the analysis could not
        # read, which must stay visible but must not, by weight alone, lift an
        # otherwise-clean package over the alert bar.  `X026 + X027` = 30 < the
        # 35 bar, so a refusal-only package is reported and (via the watcher's
        # refusal tier) alerted, but a legitimate complex recipe the tokenizer
        # could not resolve no longer scores like a compromise.
        severity = "MEDIUM"
        listed = ", ".join(name for name, _fns in referenced)
        where = "; ".join(
            f"{name} <- {', '.join(fns)}" for name, fns in referenced)
        add("X026", "Unresolved Constructs In Executable Positions", severity,
            "evasion",
            f"{count} unresolved assignment(s) referenced from executable "
            f"functions: {where}",
            line=None, count=count, names=listed)
    if cluster:
        listed = ", ".join(name for name, _fns in referenced)
        add("X027", "Refusal Cluster", "MEDIUM", "evasion",
            f"{len(referenced)} distinct unresolved assignments in "
            f"executable positions: {listed}",
            line=None, count=len(referenced), names=listed)

    # --- W008: the analysis boundary behind X026/X027 --------------------
    # An unresolved construct is not only a suspicion (X) but a boundary
    # (W): the reader is told what the analysis could not resolve.  This is
    # the W-series cross-reference the spec requires; weight-0, so it never
    # moves a score.  Function-local declarations are excluded: ordinary
    # build machinery, not a boundary the reader can act on (X026 still
    # rates the name above).
    reportable = _reportable_unresolved_names(post)
    if reportable:
        add("W008", "Unresolved Construct In A Recipe", "INFO", "unverifiable",
            f"{len(reportable)} unresolved assignment(s) this analysis could "
            "not resolve: " + ", ".join(reportable[:5]),
            line=None, count=len(reportable),
            names=", ".join(reportable[:5]))

    # --- X030: ANSI-C quoted content in commands -------------------------
    for fn in _EXECUTABLE_FUNCTIONS:
        body = post.functions.get(fn, "")
        if not body:
            continue
        for match in _COMMAND_POSITION_LITERAL_RE.finditer(body):
            literal = match.group(1)
            hexes = _HEX_ESCAPE_RE.findall(literal)
            octals = _OCTAL_ESCAPE_RE.findall(literal)
            controls = _CONTROL_ESCAPE_RE.findall(literal)
            escapes = len(hexes) + len(octals)
            # fire on >=2 hex/octal escapes, OR a control escape,
            # OR any single hex/octal escape spelling a byte outside
            # printable ASCII (a lone \x01 is as suspicious as two).
            nonprintable = any(
                not (0x20 <= int(h, 16) <= 0x7E) for h in hexes
            ) or any(
                not (0x20 <= int(o, 8) <= 0x7E) for o in octals
            )
            if escapes < 2 and not controls and not nonprintable:
                continue
            from .._tokenizer_engine import _decode_ansi_c

            decoded = _decode_ansi_c(literal)
            if all(0x20 <= ord(ch) <= 0x7E for ch in decoded) and \
                    _BENIGN_DECODED_RE.match(decoded):
                continue  # a resolved benign value, not a spelled command
            add("X030", "ANSI-C Quoted Content In Commands", "HIGH",
                "evasion",
                f"{fn}() carries an ANSI-C quoted literal with "
                f"{escapes} hex/octal escape(s)",
                line=None, function=fn, escapes=escapes)
            break

    # --- X029: encoded material at rest ----------------------------------
    # A literal is "at rest" only when neither a decoder nor an executor
    # References it in the same diff. The decoder arm is the
    # regex below; the executor arm is the crossfire ownership table's
    # decode-and-execute / output-executed families - when one of those
    # fired, that rule owns the line and X029 stands down.
    decoder_present = bool(_DECODER_RE.search(diff_text))
    if not decoder_present:
        try:
            from .crossfire import crossfire_techniques

            techniques = crossfire_techniques(diff_text)
            decoder_present = any(
                rid in techniques for rid in ("X001", "X023"))
        except Exception:
            pass
    floor = int(_thresholds(config).get("x029", {}).get("min_length", 256))
    if not decoder_present:
        scanned = "\n".join(post.functions.values())
        top_level = "\n".join(
            line.content for line in doc.lines
            if line.side in ("add", "context") and not line.in_hunk
        )
        haystack = f"{scanned}\n{top_level}"
        for literal_class in _encoded_literal_classes(haystack, floor):
            add("X029", "Encoded Material At Rest", "MEDIUM", "evasion",
                f"{literal_class} literal of at least {floor} encoded "
                "characters with no decoder in this diff",
                line=None, literal_class=literal_class, min_length=floor)

    # --- X031: build reads non-code text ---------------------------------
    for fn in _EXECUTABLE_FUNCTIONS:
        body = post.functions.get(fn, "")
        if not body:
            continue
        if _SELF_READ_RE.search(body) or _SELF_READ_EVAL_RE.search(body):
            add("X031", "Build Reads Non-Code Text", "HIGH", "evasion",
                f"{fn}() reads its own PKGBUILD and pipes it into an "
                "executor",
                line=None, function=fn)
            break

    # --- X028: pattern completed across consecutive commits --------------
    pattern_across_commits(previous_diff, diff_text, add,
                           previous_commit=previous_commit,
                           current_commit=current_commit)
