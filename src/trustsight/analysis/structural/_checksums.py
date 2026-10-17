"""Extracted from structural.py: _checksums."""

import re
from ...differ import (
    checksum_array_parity_in_text,
)
from ..build import (
    _INTERPRETER_FETCH,
)
from ...config import NETWORK_CLIENT
from ...findings import stamp
from ...recipedoc import recipe_states
from ...rules import find_line_in_diff
from ...diffdoc import parse_diff_lines
from ...tokenizer import split_lines

__all__ = ['_CHECKSUM_ADDED_RE', '_CHECKSUM_ARRAY_NAMES', '_CHECKSUM_EMPTIED_RE', '_CHECKSUM_REMOVED_LINE_RE', '_CHECKSUM_SKIP_RE', '_CHECKSUM_STRENGTH', '_FETCH_IN_PACKAGE_RE', '_HARDENING_OPTIONS', '_INTERPRETER_FETCH_RE', '_SCHEME_MARKERS', '_family_values', '_first_insertion_index', '_ip_literal_hosts', '_is_checksum_array', '_is_subsequence', '_line_has_scheme', '_package_fetch_client', '_removed_declarations', '_require_content_change', '_skip_positions', '_url_host', '_userinfo_urls', 'addendum4_findings', 'array_order_changes', 'isolated_checksum_insertion', 'recipe_checksum_parity_finding']

_CHECKSUM_SKIP_RE = re.compile(
    r"sha256sums\s*=\s*\(?\s*[\'\"]?(?:SKIP|NONE)"
)

_CHECKSUM_EMPTIED_RE = re.compile(
    r"sha256sums\s*=\s*\(\s*\)"
)

_CHECKSUM_ADDED_RE = re.compile(
    r"sha256sums\s*=\s*\('[a-fA-F0-9]"
)

_CHECKSUM_REMOVED_LINE_RE = re.compile(
    r"sha256sums"
)

_FETCH_IN_PACKAGE_RE = re.compile(
    r"(?:^|[;&|(])\s*(?:" + NETWORK_CLIENT + r")\b",
    re.IGNORECASE | re.MULTILINE,
)

_INTERPRETER_FETCH_RE = re.compile(_INTERPRETER_FETCH, re.IGNORECASE)

_SCHEME_MARKERS = ("://", "magnet:", "ipfs:", "ipns:")

def _line_has_scheme(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in _SCHEME_MARKERS)

def _package_fetch_client(body: str) -> str | None:
    """The first fetch command in a function body, or ``None``.

    Command-position only (see the regexes above); an assignment whose
    value is literal data is skipped, while a command substitution
    (``x=$(curl ...)``) is still a fetch.
    """
    for raw_line in split_lines(body):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if (re.match(r"(?:export\s+|local\s+)?[A-Za-z_]\w*\s*\+?=", stripped)
                and "$(" not in stripped and "`" not in stripped):
            continue
        match = _FETCH_IN_PACKAGE_RE.search(raw_line)
        if match:
            return match.group(0).strip()
        interpreter = _INTERPRETER_FETCH_RE.search(raw_line)
        if interpreter and _line_has_scheme(raw_line):
            return interpreter.group(0)
    return None

_CHECKSUM_ARRAY_NAMES = frozenset({
    "md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums",
    "sha512sums", "b2sums",
})

def _is_checksum_array(name: str) -> bool:
    return (name in _CHECKSUM_ARRAY_NAMES
            or name.split("_", 1)[0] in _CHECKSUM_ARRAY_NAMES)

def _skip_positions(entries) -> set[int]:
    return {
        index for index, entry in enumerate(entries)
        if entry.strip().upper() in ("SKIP", "NONE")
    }

def _require_content_change(config) -> bool:
    """The ``c014.require_content_change`` gate (``h099`` alias)."""
    thresholds = (config or {}).get("thresholds", {})
    section = thresholds.get("c014") or thresholds.get("h099") or {}
    return bool(section.get("require_content_change", True))

def array_order_changes(diff_text: str, config: dict | None = None,
                        pre=None, post=None):
    """Checksum arrays whose entries moved, with delta and span.

    Returns ``[(array_name, ArrayDelta, span)]``.  Ordering facts come from
    the typed recipe arrays (positions are preserved there); the rule never
    re-reads diff text.  A reorder with no content change and no SKIP
    movement is reformatting, so the default gate stands it down.
    """
    from ...recipedoc import array_diff

    if pre is None or post is None:
        try:
            pre, post = recipe_states(parse_diff_lines(split_lines(diff_text)))
        except Exception:
            return []
    require_content = _require_content_change(config)
    names = {name for name in pre.arrays if _is_checksum_array(name)}
    names |= {name for name in post.arrays if _is_checksum_array(name)}
    changes = []
    for name in sorted(names):
        old = pre.arrays.get(name, ())
        new = post.arrays.get(name, ())
        delta = array_diff(old, new)
        if not delta.reordered:
            continue
        content_changed = bool(delta.gained or delta.lost)
        skip_moved = _skip_positions(old) != _skip_positions(new)
        if require_content and not (content_changed or skip_moved):
            continue
        spans = post.array_spans.get(name) or pre.array_spans.get(name) or ()
        changes.append((name, delta, spans[0] if spans else None))
    return changes

def _is_subsequence(small, big) -> bool:
    """True when ``small`` appears in ``big`` in order (insertions allowed)."""
    it = iter(big)
    return all(item in it for item in small)

def _first_insertion_index(old, new):
    """Index of the first entry that only exists in ``new``, or None.

    ``old`` must be a subsequence of ``new`` (pure insertion).  Returns the
    first position at which ``new`` diverges from ``old``.
    """
    if len(new) <= len(old):
        return None
    for i in range(len(old)):
        if new[i] != old[i]:
            return i
    return len(old)

def isolated_checksum_insertion(pre, post, name: str):
    """The mildest shape: a checksum entry inserted out of parity.

    A checksum array gains an entry (relative order of the rest preserved)
    whose index differs from the index at which the corresponding ``source``
    entry was inserted, so the hash/source positional pairing is perturbed
    without a reorder.  Returns ``(checksum_index, source_index)`` or None.
    """
    if pre is None or post is None:
        return None
    old_ck = pre.arrays.get(name, ())
    new_ck = post.arrays.get(name, ())
    old_src = pre.arrays.get("source", ())
    new_src = post.arrays.get("source", ())
    if not (old_ck and new_ck and old_src and new_src):
        return None
    if not (_is_subsequence(old_ck, new_ck) and _is_subsequence(old_src, new_src)):
        return None
    ck_idx = _first_insertion_index(old_ck, new_ck)
    src_idx = _first_insertion_index(old_src, new_src)
    if ck_idx is None or src_idx is None or ck_idx == src_idx:
        return None
    return ck_idx, src_idx

_CHECKSUM_STRENGTH = ("b2sums", "sha512sums", "sha256sums", "sha1sums",
                      "md5sums")

_HARDENING_OPTIONS = frozenset(
    {"!strip", "!debug", "!lto", "!fortify", "!debugsplit"})

def _family_values(arrays, base: str) -> tuple[str, ...]:
    """Every ``base``/``base_<arch>`` array's entries, concatenated."""
    out: list[str] = []
    for key in sorted(arrays):
        if key == base or key.startswith(base + "_"):
            out.extend(arrays[key])
    return tuple(out)

def _removed_declarations(doc) -> set[str]:
    """Array names whose declaration line is removed and not re-added."""
    if doc is None:
        return set()
    removed: set[str] = set()
    added: set[str] = set()
    for line in doc.lines:
        match = re.match(r"\s*([A-Za-z_]\w*)\s*\+?=", line.content)
        if not match:
            continue
        if line.side == "remove":
            removed.add(match.group(1))
        elif line.side == "add":
            added.add(match.group(1))
    return removed - added

def _url_host(url: str) -> str:
    from ...buckets import canonical_host

    if "://" not in url:
        return ""
    return canonical_host(url.split("://", 1)[1].split("/", 1)[0])

def _userinfo_urls(urls) -> list[str]:
    """URLs carrying userinfo before the host (credentials in a source)."""
    return [url for url in urls if "://" in url
            and "@" in url.split("://", 1)[1].split("/", 1)[0]]

def _ip_literal_hosts(hosts) -> list[str]:
    import ipaddress

    out: list[str] = []
    for host in hosts:
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            continue
        out.append(host)
    return out

def addendum4_findings(diff_text, scope_doc, pre, post, source_changes,
                       config, add, tree_manifest=None,
                       post_text=None) -> None:
    """G1/G3/G4/G5/G6/G7 predicates over the typed core."""
    from ...recipedoc import array_diff

    # G1 (C020): credentials embedded in a gained source URL.  The value
    # itself is never printed - evidence shows the host only.
    if _userinfo_urls(source_changes.added_urls):
        hosts = []
        for url in _userinfo_urls(source_changes.added_urls):
            host = _url_host(url)
            if host and host not in hosts:
                hosts.append(host)
        add("C020", "Credentials In A Source URL", "HIGH", "source",
            "gained source URL(s) carry embedded credentials for "
            + ", ".join(hosts),
            line=find_line_in_diff(diff_text, r"://[^/\s'\"]*@"),
            hosts=", ".join(hosts))

    # G6 (C024): an added/modified .install no install= declaration names.
    # This is the "dead hook" case: either install= is entirely absent, or it
    # names a different file, so pacman never runs the shipped hook.
    if scope_doc is not None:
        declared = post.scalars.get("install", "") if post is not None else ""
        # The diff reconstruction holds only what the hunks show, so an
        # `install=` that is unchanged and sits outside the hunk reads as
        # absent, and C024 fired on packages that do declare their install
        # file (keymux/sonarr-develop: `install=keymux.install`).  The
        # complete new recipe is authoritative whenever the caller has it.
        if post_text:
            try:
                from ...recipedoc import parse_recipe

                declared = parse_recipe(post_text).scalars.get("install", "")
            except Exception:  # noqa: BLE001 - a refusal keeps the diff read
                pass
        declared_base = declared.rsplit("/", 1)[-1] if declared else ""
        # A variable-bearing declaration cannot be basename-compared without
        # resolution; treat it as declaring rather than guess a mismatch.
        if "$" in declared:
            declared_base = ""
        for file in scope_doc.files:
            if not file.path.endswith(".install") or file.status == "removed":
                continue
            base = file.path.rsplit("/", 1)[-1]
            if not declared:
                add("C024", "Install Script Not Declared", "MEDIUM",
                    "composition",
                    f"{file.path} is shipped but install= does not name "
                    "it; pacman never runs the hook",
                    file=file.path, line=None)
                break
            if declared_base and base and base != declared_base:
                add("C024", "Install Script Not Declared", "MEDIUM",
                    "composition",
                    f"{file.path} is shipped but install= names "
                    f"{declared_base}, not it; pacman never runs this hook",
                    file=file.path, line=None)
                break
        # G6(a) (C027): install= names a file the diff/tree does not carry -
        # a dangling declaration, almost always benign but worth an INFO.
        # Tree knowledge is required (never guess): without the manifest the
        # absence could just be an unchanged file outside the hunk.
        if declared and tree_manifest is not None:
            wanted = declared.rsplit("/", 1)[-1]
            seen = {f.path.rsplit("/", 1)[-1] for f in scope_doc.files}
            seen |= {str(p).rsplit("/", 1)[-1] for p, _body in tree_manifest}
            if wanted not in seen:
                add("C027", "Declared Install Script Is Absent", "INFO",
                    "integrity",
                    f"install= names {declared}, which the diff and the tree "
                    "do not carry",
                    file="PKGBUILD", line=None)

    if pre is None or post is None:
        return

    # G3 (C021): a test/dependency array removed while a build function
    # changed - dropping the checks that would catch a payload.  Dropping
    # `checkdepends` eliminates the test-suite execution outright, so it is
    # the HIGH candidate the spec gates on fire rates; `optdepends` removal
    # is far more often cleanup, so it stays MEDIUM.
    for name in ("checkdepends", "optdepends"):
        lost = array_diff(_family_values(pre.arrays, name),
                          _family_values(post.arrays, name)).lost
        if not lost:
            continue
        touched = any(
            pre.functions.get(fn) != post.functions.get(fn)
            for fn in ("build", "prepare", "check")
        )
        if touched:
            severity = "HIGH" if name == "checkdepends" else "MEDIUM"
            add("C021", "Dependency Removal During A Build Change", severity,
                "composition",
                f"{name} lost {', '.join(sorted(set(lost))[:3])} while a "
                "build function changed",
                line=None, field=name, lost=", ".join(sorted(set(lost))[:5]))

    # G4 (C022): verification downgraded to a weaker algorithm.  The
    # strongest array must be *declared removed in this diff* (a partial
    # post projection that simply does not show it is not a removal), and
    # a strictly weaker array must remain.
    present = {base: _family_values(pre.arrays, base)
               for base in _CHECKSUM_STRENGTH}
    post_present = {base: _family_values(post.arrays, base)
                    for base in _CHECKSUM_STRENGTH}
    removed_names = _removed_declarations(scope_doc)
    strongest = next((base for base in _CHECKSUM_STRENGTH if present[base]), None)
    strongest_gone = strongest is not None and (
        strongest in removed_names
        or (strongest in post.arrays and not post_present[strongest])
    )
    if strongest is not None and strongest_gone:
        weaker = [base for base in _CHECKSUM_STRENGTH
                  if base != strongest and post_present[base]]
        # Stands down when every array was removed together: H002 owns it.
        if weaker and any(post_present.values()):
            add("C022", "Checksum Strength Downgraded", "HIGH", "integrity",
                f"{strongest} removed or emptied while "
                f"{', '.join(weaker)} remains",
                line=None, lost=strongest, retained=", ".join(weaker))

    # G5 (C023): a gained host that is a bare IP literal.
    literal_hosts = _ip_literal_hosts(
        sorted({_url_host(url) for url in source_changes.added_urls} - {""}))
    if literal_hosts:
        add("C023", "IP-Literal Source Host", "MEDIUM", "source",
            "gained source host(s) are IP literals: "
            + ", ".join(literal_hosts[:3]),
            line=None, hosts=", ".join(literal_hosts[:5]))

    # G7 (C025): a hardening option gained.
    gained_options = array_diff(
        pre.arrays.get("options", ()), post.arrays.get("options", ())).gained
    hardening = sorted(set(gained_options) & _HARDENING_OPTIONS)
    if hardening:
        add("C025", "Hardening Option Disabled", "LOW", "build",
            "options gained hardening-disabling entries: "
            + ", ".join(hardening),
            line=None, options=", ".join(hardening))

def recipe_checksum_parity_finding(recipe_text: str) -> dict | None:
    """H091 for a first-seen recipe, which has no diff to read arrays from.

    A new package is exactly where a source slipped in beside a checksum
    list nobody recounted is least likely to be noticed, and the fresh
    analysis path ran no integrity rule at all.
    """
    if not recipe_text:
        return None
    parity = checksum_array_parity_in_text(recipe_text)
    if parity is None:
        return None
    n_src, n_sum, var = parity
    return stamp({
        "rule_id": "H091", "name": "Checksum Array Shorter Than Source Array",
        "severity": "HIGH", "category": "integrity",
        "match": f"{n_src} sources declared against {n_sum} {var} entries",
        "file": "PKGBUILD", "line": None,
        "params": {"sources": n_src, "sums": n_sum, "var": var},
    })
