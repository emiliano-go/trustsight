# ruff: noqa: F405
from ._build_constants import *  # noqa: F401,F403


# ---------------------------------------------------------------------------
# H079 - the recipe overrides the distribution build flags
# ---------------------------------------------------------------------------

_BUILD_FLAG_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+|declare\s+-x\s+)?"
    r"(CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|RUSTFLAGS|MAKEFLAGS)\s*(\+?=)\s*(.*)$"
)

# Turning one of these off removes a mitigation makepkg.conf turned on.
# ``-D_FORTIFY_SOURCE=0``/``-U_FORTIFY_SOURCE`` are the disabling spellings;
# a package raising the level is not weakening anything.
_HARDENING_OFF_RE = re.compile(
    r"-fno-stack-protector|-U_FORTIFY_SOURCE|-D_FORTIFY_SOURCE\s*=\s*0"
    r"|-fno-PIE\b|-fno-pie\b|-no-pie\b|-fno-PIC\b|-fno-pic\b"
    r"|-fcf-protection\s*=\s*none|-fno-stack-clash-protection"
    r"|-z\s*execstack|-z\s*norelro|-Wl,-z,execstack|-Wl,-z,norelro",
    re.IGNORECASE,
)


def _build_flag_findings(diff_text, config, add) -> None:
    """The recipe replaces or weakens the distribution's build flags (H079).

    makepkg exports a hardened flag set (stack protector, FORTIFY_SOURCE,
    PIE, RELRO).  A recipe that *appends* to it keeps those; one that
    assigns over it silently drops every mitigation the distribution
    configured, and one that spells out a disabling flag drops a named one.
    Either way the binary a user installs is built with weaker mitigations
    than the same source built through the normal path, and nothing in the
    package metadata says so.

    Only the recipe's own lines count: a vendored Makefile or configure
    fragment inside a shipped patch is not the packager's assignment.

    Kept off H025's evidence: H025 reports that a build function *modified*
    the environment, which is the weaker claim and already covers the
    in-function case.  H079 adds the two things H025 does not say - a named
    mitigation being switched off (HIGH, wherever it appears) and a
    top-level replacement of the whole set (MEDIUM), which H025 cannot see
    because it is scoped to build functions and which also runs at parse
    time, before any build step.
    """
    lines = mask_to_recipe(join_line_continuations(split_lines(diff_text)))
    enclosing = _classify_enclosing_function(lines)
    for i, line in enumerate(parse_diff_lines(lines).lines):
        if line.side != "add" or line.raw.startswith("+++"):
            continue
        body = _strip_comment(line.content)
        match = _BUILD_FLAG_ASSIGN_RE.match(body)
        if not match:
            continue
        variable, operator, value = match.group(1), match.group(2), match.group(3)
        if _HARDENING_OFF_RE.search(value):
            add("H079", "Build Flags Weakened", "HIGH", "integrity",
                f"{variable} disables a hardening default: {value.strip()[:70]}",
                line=i + 1, variable=variable, value=value.strip()[:70],
                detail=f"{variable} disables a hardening default")
            return
        # A value that carries no literal flag token (``CFLAGS="${_cflags[@]}"``)
        # is a set this rule cannot read: whether it still contains the
        # distribution's flags is not visible here, and claiming a
        # replacement would be claiming more than the diff shows.
        if (
            enclosing.get(i) is None
            and operator == "="
            and not re.search(r"\$\{?" + variable + r"\b", value)
            and re.search(r"(?:^|\s|[\"'])-[A-Za-z]", value)
        ):
            add("H079", "Build Flags Weakened", "MEDIUM", "integrity",
                f"{variable} is replaced at the top level rather than "
                f"extended, dropping the makepkg.conf set: {value.strip()[:70]}",
                line=i + 1, variable=variable, value=value.strip()[:70],
                detail=f"{variable} replaces the distribution flag set at parse time")
            return
