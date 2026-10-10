"""X026-X031: the refusal family (Addendum 1).

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
#: in an executable position (spec X026).  Top-level metadata is not.
_EXECUTABLE_FUNCTIONS = ("build", "prepare", "check", "package")

#: A ``$name`` / ``${name}`` reference, including a subscript.
def _references(name: str) -> re.Pattern:
    return re.compile(r"\$\{?" + re.escape(name) + r"(?:\}|\b|\[)")


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

#: A self-read piped into an executor (spec X031).  The middle segment
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


def _decode_ansi_c(body: str) -> str:
    """Best-effort decode of ANSI-C escapes, for the benign check only."""
    out: list[str] = []
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "x" and i + 3 < len(body) + 1:
                try:
                    out.append(chr(int(body[i + 2:i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "t":
                out.append("\t")
                i += 2
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(body[i])
        i += 1
    return "".join(out)


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
    finding (spec X028) when the caller supplies them.
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


def refusal_findings(diff_text: str, config, add, current_text=None,
                     previous_diff: str = "", previous_commit: str = "",
                     current_commit: str = "") -> None:
    """Emit X026/X027/X029/X030/X031 for one diff.

    ``add`` is the structural finding builder (same callable the crossfire
    family uses).  ``current_text`` is the post-state PKGBUILD when the
    caller holds it; the diff's own post projection is the fallback.
    """
    from ..diffdoc import parse_diff
    from ..recipedoc import recipe_states

    try:
        doc = parse_diff(diff_text)
        _pre, post = recipe_states(doc)
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
        pattern = _references(name)
        functions = [
            fn for fn in _EXECUTABLE_FUNCTIONS
            if pattern.search(post.functions.get(fn, ""))
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
        severity = "HIGH" if count >= 3 else "MEDIUM"
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
        add("X027", "Refusal Cluster", "CRITICAL", "evasion",
            f"{len(referenced)} distinct unresolved assignments in "
            f"executable positions: {listed}",
            line=None, count=len(referenced), names=listed)

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
            if escapes < 2 and not controls:
                continue
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
    # references it in the same diff (spec X029).  The decoder arm is the
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
