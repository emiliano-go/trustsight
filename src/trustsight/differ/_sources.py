"""Extracted from differ.py: _sources."""

import re
from ..diffdoc import parse_diff_lines
from ..schema import SourceChanges
from ..line_lex import strip_comment_stateful
from ..tokenizer import split_lines
from ._bounds import MAX_URLS_PER_SIDE, MAX_URL_TOKEN_BYTES
from ._checksums import detect_checksum_changes, detect_checksum_removed
from ._common import _SOURCE_ARRAY_START_RE, _clean_url, _post_diff_lines

__all__ = ['_ARRAY_TOKEN_RE', '_CMD_SUBST_RE', '_DKMS_RE', '_GIT_PKG_RE', '_SIG_SRC_RE', '_SKIP_JUSTIFICATION_CHECKS', '_SOURCE_CMD_SUBST_RE', '_SOURCE_OPEN_RE', '_URL_TOKEN_RE', '_VALIDPGPKEYS_RE', '_VCS_SOURCE_RE', 'extract_source_array_urls', 'extract_urls_from_diff', 'is_skip_justified', 'local_source_names', 'source_array_has_command_substitution', 'urls_from_pkgbuild_text']

_VCS_SOURCE_RE = re.compile(
    r"^[+ ](?:.*\b(?:git\+https?://|git://|svn://|hg://|bzr://|svn\+https?://|git\+ssh://))",
    re.IGNORECASE,
)

_GIT_PKG_RE = re.compile(r"^[+ ]\s*source\s*=.*\.git\b", re.IGNORECASE)

_SIG_SRC_RE = re.compile(r"\.(?:sig|asc)[\'\"]?(?:\s|\)|$)", re.IGNORECASE)

_VALIDPGPKEYS_RE = re.compile(r"^[+ ]\s*validpgpkeys\s*=\s*\(", re.IGNORECASE)

_DKMS_RE = re.compile(r"^[+ ]\s*DKMS", re.IGNORECASE)

_SKIP_JUSTIFICATION_CHECKS = [
    ("vcs source", lambda t: bool(_VCS_SOURCE_RE.search(t) or _GIT_PKG_RE.search(t) or _DKMS_RE.search(t))),
    ("validpgpkeys present", lambda t: bool(_VALIDPGPKEYS_RE.search(t))),
]

#: A VCS scheme inside a resolved ``source`` array entry.  The diff-side check
#: is line-anchored; this one reads the value the tokenizer produced.
_VCS_ENTRY_RE = re.compile(
    r"git\+https?://|git\+ssh://|git://|svn\+https?://|svn://|hg://|bzr://",
    re.IGNORECASE,
)


def _recipe_skip_justification(recipe_text: str) -> str:
    """The justification for a SKIP that the *head recipe* carries.

    Read through the typed recipe (``recipedoc``), not a raw line walk: a
    ``source`` entry is a resolved value, so a VCS source or a
    ``validpgpkeys`` declaration that sits outside the diff hunk is still
    seen.  A parse the tokenizer refuses justifies nothing (it is not a
    licence to assume the SKIP is fine).
    """
    from ..recipedoc import parse_recipe

    try:
        recipe = parse_recipe(recipe_text)
    except Exception:  # noqa: BLE001 - a refusal justifies nothing
        return ""
    sources = recipe.arrays.get("source", ())
    if any(_VCS_ENTRY_RE.search(str(s)) or str(s).rstrip("'\"").endswith(".git")
           for s in sources):
        return "vcs source"
    if "validpgpkeys" in recipe.arrays or "validpgpkeys" in recipe.scalars:
        return "validpgpkeys present"
    keys = list(recipe.arrays) + list(recipe.scalars)
    if any(str(k).upper().startswith("DKMS") for k in keys):
        return "vcs source"
    return ""


def is_skip_justified(diff_text: str, current_text: str | None = None) -> str:
    """Check whether a ``SKIP`` checksum has a valid justification.

    Returns a short reason string (truthy) or ``""`` (falsy).

    The signature check reads the post-diff text, so a `.sig` entry the diff
    removes cannot justify a new `SKIP`.

    *current_text* is the full head recipe when the caller has it.  A SKIP
    is justified by the ``source=()`` entry it belongs to (a VCS source, a
    ``validpgpkeys`` declaration), and that entry is frequently unchanged and
    outside the hunk - a ``-git`` package bumping its ``pkgver`` shows only
    the ``sha256sums=('SKIP')`` line, so reading the diff alone reports an
    unjustified SKIP on every such update.
    """
    post = "\n".join(_post_diff_lines(diff_text))
    if _SIG_SRC_RE.search(post):
        return "signature file"
    for reason, check in _SKIP_JUSTIFICATION_CHECKS:
        if any(check(line.raw)
               for line in parse_diff_lines(split_lines(diff_text)).lines):
            return reason
    if current_text:
        recipe_reason = _recipe_skip_justification(current_text)
        if recipe_reason:
            return recipe_reason
    return ""

_URL_TOKEN_RE = re.compile(r"https?://[^\s\'\"\)]+")

def extract_urls_from_diff(diff_text: str) -> SourceChanges:
    """Extract added and removed URLs from a diff."""
    added_urls: set[str] = set()
    removed_urls: set[str] = set()

    # Raw lines, headers included: the text walk matched on them, so the
    # typed document supplies them unchanged.  The quote state is carried
    # across lines: a line that starts with `#` inside a multi-line quoted
    # string is data in bash, and a per-line scan dropped the URL on it.
    quote = ""
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        raw = line.raw
        if raw.startswith("+++ "):
            # A new file cannot continue a quote from the previous one.
            quote = ""
            continue
        if raw.startswith(("diff --git ", "@@ ", "--- ")) or raw in ("---", "+++"):
            continue
        prefix = raw[:1] if raw[:1] in "+-" else ""
        # A URL in a comment cannot reach the build: it is not in
        # ``source=()``, not ``url=``, and no function runs it.  The comment
        # boundary is the tokenizer's: a `#` inside quotes, in a URL
        # fragment (``x#sha256=``) or in ``${var#…}`` is data, so a plain
        # split on `#` would cut a real URL.
        body, quote = strip_comment_stateful(raw[len(prefix):], quote)
        if prefix == "+" and "http" in body:
            for u in _URL_TOKEN_RE.findall(body):
                if len(added_urls) < MAX_URLS_PER_SIDE and len(u) <= MAX_URL_TOKEN_BYTES:
                    added_urls.add(_clean_url(u))
        elif prefix == "-" and "http" in body:
            for u in _URL_TOKEN_RE.findall(body):
                if len(removed_urls) < MAX_URLS_PER_SIDE and len(u) <= MAX_URL_TOKEN_BYTES:
                    removed_urls.add(_clean_url(u))

    checksum_behavior = detect_checksum_changes(diff_text)
    # A declaration deleted with no replacement is also a checksum change,
    # and the strongest one: the end state verifies nothing.  It used to
    # live only in `detect_checksum_removed`, a second notion the summary
    # and verification-evidence paths never consulted, so C004 fired while
    # `changes` said "no declared facts changed" and the end-state was read
    # as having a checksum at all.  Checked before `checksum_entry_removed`
    # because a removed declaration also trips the entry-removal signal.
    if detect_checksum_removed(diff_text):
        checksum_behavior = "checksum_array_removed"

    return SourceChanges(
        added_urls=sorted(added_urls),
        removed_urls=sorted(removed_urls),
        checksum_behavior=checksum_behavior,
    )

_SOURCE_CMD_SUBST_RE = re.compile(
    r"^\+\s*(?:_?\w*source\w*)\s*=\s*\(?[^)]*(?:\$\(|`)",
    re.IGNORECASE,
)

def extract_source_array_urls(diff_text: str, side: str = "after") -> set[str]:
    """URLs declared in ``source=()``, on one side of the diff.

    Distinct from :func:`extract_urls_from_diff`, which collects URLs from
    *any* added line.  H016 asks whether a download inside ``build()`` is
    also a declared source, and the broader helper would include the
    download's own URL, so the comparison could never fail.

    ``side="after"`` is the post-diff end-state (the default, which H016
    relies on); ``side="before"`` is the pre-diff state, so H019 can tell a
    URL that was downgraded from one that was always plain http.
    """
    skip = "-" if side == "after" else "+"
    skip_side = "remove" if side == "after" else "add"
    urls: set[str] = set()
    in_array = False
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        if line.raw.startswith(("+++", "---", "@@")):
            continue
        if line.side == skip_side or line.raw.startswith(skip):
            continue
        # Context lines keep their leading prefix space, as the text walk
        # produced them; only the +/- sides lose a character.
        body = line.content if line.side in ("add", "remove") else line.raw

        if not in_array:
            if not _SOURCE_ARRAY_START_RE.match(body):
                continue
            in_array = True
        for candidate in re.findall(r"https?://[^\s'\"\)]+", body):
            urls.add(_clean_url(candidate))
        if ")" in body:
            in_array = False
    return urls

_SOURCE_OPEN_RE = re.compile(r"^\+\s*(?:_?\w*source\w*)\s*=\s*\(", re.IGNORECASE)

_CMD_SUBST_RE = re.compile(r"\$\(|`")

def source_array_has_command_substitution(diff_text: str) -> bool:
    """Detect command substitution inside an added ``source=()`` array.

    Multi-line aware: the opener and the ``$(...)`` continuation line are
    usually different physical lines, so the whole open array is tracked, not
    just the single line the substitution shares with ``source=``.
    """
    in_array = False
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        raw = line.raw
        if raw.startswith(("+++", "---", "@@")):
            continue
        if _SOURCE_CMD_SUBST_RE.search(raw):
            return True
        if not in_array:
            if _SOURCE_OPEN_RE.match(raw) and ")" not in raw:
                in_array = True
            continue
        # Inside an open array: only added/context lines belong to it.
        if line.side == "add" and _CMD_SUBST_RE.search(raw):
            return True
        if ")" in raw:
            in_array = False
    return False

_ARRAY_TOKEN_RE = re.compile(r"""'([^']*)'|"([^"]*)"|([^\s()'"]+)""")

def local_source_names(pkgbuild_text: str) -> set[str]:
    """Basenames of the local (non-URL) entries in the ``source=()`` arrays.

    A ``name::url`` rename is a download and is skipped; a bare filename,
    quoted or not, is a companion file the recipe ships.  ``source_x86_64``
    and friends count.
    """
    names: set[str] = set()
    in_array = False
    for raw in split_lines(pkgbuild_text):
        line = raw.strip()
        if not in_array:
            if not _SOURCE_ARRAY_START_RE.match(line):
                continue
            in_array = True
            line = line[line.index("(") + 1:]
        segment = line.split(")", 1)[0] if ")" in line else line
        for q1, q2, bare in _ARRAY_TOKEN_RE.findall(segment):
            tok = q1 or q2 or bare
            if not tok or "://" in tok:
                continue
            names.add(tok.rsplit("/", 1)[-1])
        if ")" in line:
            in_array = False
    return names

def urls_from_pkgbuild_text(pkgbuild_text: str) -> set[str]:
    """URLs declared in ``source=()`` anywhere in a whole PKGBUILD.

    The post-diff counterpart of :func:`extract_source_array_urls`, which
    reads one side of a diff and therefore misses a declaration outside the
    changed hunk.  A rule that asks "is this fetch already declared?" must
    read the file as it now stands; reading only the diff found an empty
    array and reported a declared URL as undeclared (H016 false positive).
    """
    if not pkgbuild_text:
        return set()
    urls: set[str] = set()
    in_array = False
    for raw in split_lines(pkgbuild_text):
        if not in_array:
            if not _SOURCE_ARRAY_START_RE.match(raw):
                continue
            in_array = True
            raw = raw[raw.index("(") + 1:]
        segment = raw.split(")", 1)[0] if ")" in raw else raw
        for candidate in re.findall(r"https?://[^\s'\"\)]+", segment):
            urls.add(_clean_url(candidate))
        # A `name::url` rename keeps its URL after the `::`; the token scan
        # above already catches the scheme, so nothing extra is needed.
        if ")" in raw:
            in_array = False
    return urls
