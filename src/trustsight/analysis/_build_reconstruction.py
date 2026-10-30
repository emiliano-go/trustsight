# ruff: noqa: F405
from ._build_constants import *  # noqa: F401,F403


# ---------------------------------------------------------------------------
# H065 - obfuscated literal reconstructed
# ---------------------------------------------------------------------------

# A revealed run this long is a word - a command name, a host, a flag.  A
# shorter one is punctuation, and ``$'\n'``/``$'\t'`` in a sed or awk program
# is ordinary shell, not a campaign marker.
_REVEALED_RUN_RE = re.compile(r"[!-~]{3,}")

# Ordinary quoted data (``depends=('glibc' 'foo')``) is not obfuscation, but
# quote stripping would make it look as if something was hidden.  Only report
# H065 when the original line carried one of the reconstruction targets.
#
# The partial-quoting arms require an alphanumeric in the quoted interior.
# A revealed literal is *content* (``b"u"n`` hides ``bun``); the ``::`` that
# separates the two halves of a makepkg array element is punctuation, so
# ``"${pkgname}-x86_64"::"${url}/..."`` must not read as a hidden word.
_OBFUSCATION_MARKER_RE = re.compile(
    r"(?<=\w)(?:''|\"\")(?=\w)"          # empty-quote concat: b''u''n
    r"|\$\(\s*printf\s+['\"]"           # $(printf 'literal')
    r"|\$'"                                # ANSI-C quote (also: fully=False)
    r"|\w['\"][^'\"\s]*[A-Za-z0-9][^'\"\s]*['\"]"   # partial quoting, left-glued
    r"|['\"][^'\"\s]*[A-Za-z0-9][^'\"\s]*['\"]\w",  # partial quoting, right-glued
    re.IGNORECASE,
)


def _reconstruction_findings(diff_text, config, add) -> None:
    """Report that a line was read in reconstructed form (H065).

    The tokenizer already rebuilds the four obfuscation forms so that
    H035/R003/R039 match on what the line *means* rather than on how it is
    spelled.  Doing that silently would leave the report describing text the
    file does not contain, so the reconstruction is itself a reported fact:
    weight 0, no score, but the reviewer is told which line was rewritten and
    into what before any other rule quoted it.

    A literal that could *not* be rebuilt (a malformed ``$'``) is reported
    too, and as the inconclusive case - unreconstructable input is never
    read as clean.
    """
    raw_lines = parse_diff_lines(join_line_continuations(split_lines(diff_text))).lines
    bodies = [
        _strip_comment(line.content)
        for line in raw_lines
        if line.side == "add" and not line.raw.startswith("+++")
    ]
    # One round-trip for every line's reconstruction rather than one per
    # line: the body walk is O(lines) and would otherwise be the sandbox's
    # dominant cost on ordinary text.
    rebuilt_pairs = reconstruct_lines_stateful(bodies)
    for body, (rebuilt, fully, quoted) in zip(bodies, rebuilt_pairs, strict=True):
        if quoted:
            continue
        if not fully:
            # An ANSI-C quote that survived reconstruction is the
            # inconclusive case, whether or not anything else on the line
            # was rebuilt - so this is tested before the "nothing changed"
            # exit, which a wholly unreconstructable line also takes.
            add("H065", "Obfuscated Literal Reconstructed", "INFO", "obfuscation",
                f"line carries a literal that could not be reconstructed: {body.strip()[:80]}",
                detail="obfuscated literal could not be fully reconstructed",
                reconstructed=False, body=body.strip()[:80])
            return
        if rebuilt == body:
            continue
        if not _OBFUSCATION_MARKER_RE.search(body):
            continue
        # Partial quoting is only obfuscation when it hides a command word.
        # `install -Dm"$mode"` and `install -Dm"755"` are ordinary shell
        # quoting of an option argument; the command word is unchanged, so
        # the reconstruction reveals nothing a rule did not already see.
        # The explicit forms (empty-quote concatenation, printf, ANSI-C)
        # still report in any position.
        explicit = any(marker in body for marker in ("''", '""', "$(printf", "$'"))
        raw_word = body.strip().split(None, 1)[0] if body.strip() else ""
        rebuilt_word = rebuilt.strip().split(None, 1)[0] if rebuilt.strip() else ""
        if not explicit and raw_word == rebuilt_word:
            continue
        revealed = [
            token for token in _REVEALED_RUN_RE.findall(rebuilt)
            if token not in body
        ]
        if not revealed:
            continue
        add("H065", "Obfuscated Literal Reconstructed", "INFO", "obfuscation",
            f"obfuscated literal reconstructs to {revealed[0][:40]!r}: {body.strip()[:80]}",
            detail=f"obfuscated literal reconstructs to {revealed[0][:40]!r}",
            reconstructed=True, revealed=revealed[0][:40], body=body.strip()[:80])
        return
