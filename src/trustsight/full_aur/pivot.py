"""Phase 7 - the corpus-side indicator pivot (plan §9).

R106 answers "does *this* package carry a known indicator?".  The pivot
answers the other direction: given one indicator, which AUR packages
reference it?  That is the question an advisory raises - one malicious host
is published, and the useful next step is the full list of packages that
point at it, not a per-package rescan.

The pivot reads only material the corpus already holds: the metadata
snapshot (names, maintainers, declared dependencies, upstream ``url=``) and
the stored PKGBUILD snapshots.  It never fetches anything a PKGBUILD points
at - the same threat-model line the plan draws for R122.

Matching is R106's: exact equality on a declared fact.  The query value does
not have to be on the shipped list; when it is, the entry's provenance and
confidence ride along with the result.
"""

from ..db import get_connection
from ..iocs import load_indicators, normalize

_DEP_KEYS = (
    "Depends", "MakeDepends", "OptDepends", "CheckDepends",
    "Provides", "Replaces",
)

# Version constraints and optdepends descriptions are not part of the name.
_DEP_SEPARATORS = ("<=", ">=", "=", "<", ">", ":")


def _dep_name(entry: str) -> str:
    name = entry.strip()
    for sep in _DEP_SEPARATORS:
        if sep in name:
            name = name.split(sep, 1)[0]
    return name.strip()


def _same_host(candidate: str, needle: str) -> bool:
    """Compare a host found in corpus text with a normalized query host.

    The candidate goes through the same normalization as the query - case,
    trailing root dot, IDNA - so an internationalised host written either
    way compares equal, and anything that is not a host compares to nothing.
    """
    return normalize("domain", candidate) == needle


def infer_type(value: str) -> str:
    """Classify a raw query string into an indicator type.

    Shape decides: a hex digest of digest length is a hash, a dotted host is
    a domain, anything else is a package name.
    """
    for type_ in ("hash", "domain"):
        if normalize(type_, value) is not None:
            return type_
    return "package"


def _snapshot_rows() -> list[tuple[str, str]]:
    with get_connection() as conn:
        try:
            rows = conn.execute(
                "SELECT package_name, pkgbuild_text FROM pkgbuild_snapshots"
            ).fetchall()
        except Exception:  # table absent on a cold database
            return []
    return [(r[0], r[1] or "") for r in rows]


def _load_metadata() -> dict:
    """Read this install's metadata snapshot.

    Exactly one location, ``metadata.default_metadata_path()``.  The pivot
    used to fall back to ``full-aur-meta.json`` in the working directory,
    left over from when the pipeline wrote one there.  That made the
    answer depend on where the command was run from, and a file in the
    current directory is not an input this tool trusts: dropping a
    snapshot in a shared checkout would decide which packages the pivot
    reports as related to an indicator.
    """
    from .metadata import default_metadata_path, load_metadata

    return load_metadata(path=default_metadata_path()) or {}


def _metadata_hits(value: str, type_: str, metadata: dict) -> list[dict]:
    from ..analysis.ioc import _hosts_in

    hits: list[dict] = []
    for name, meta in metadata.items():
        if not isinstance(meta, dict):
            continue
        if type_ == "package":
            if name == value or meta.get("PackageBase") == value:
                hits.append({"package": name, "surface": "package_name",
                             "detail": value})
                continue
            for key in _DEP_KEYS:
                declared = meta.get(key) or []
                if isinstance(declared, str):
                    declared = [declared]
                if any(_dep_name(entry) == value for entry in declared):
                    hits.append({"package": name, "surface": key.lower(),
                                 "detail": value})
                    break
        elif type_ == "domain":
            url = meta.get("URL") or ""
            if url and any(_same_host(host, value) for host, _ in _hosts_in(url)):
                hits.append({"package": name, "surface": "url", "detail": url})
    return hits


def _snapshot_hits(value: str, type_: str) -> list[dict]:
    from ..analysis.ioc import _digests_in, _hosts_in

    if type_ == "package":
        # A name in PKGBUILD *text* is not a declared fact - it could be a
        # comment or a path fragment.  The metadata pass above owns names.
        return []
    hits: list[dict] = []
    for name, text in _snapshot_rows():
        if not text:
            continue
        for line in text.splitlines():
            found = None
            if type_ == "domain":
                found = next(
                    (h for h, _ in _hosts_in(line) if _same_host(h, value)), None
                )
            elif type_ == "hash":
                found = next((d for d in _digests_in(line) if d.lower() == value), None)
            if found:
                hits.append({"package": name, "surface": f"pkgbuild_{type_}",
                             "detail": line.strip()[:120]})
                break
    return hits


def pivot(value: str, metadata: dict | None = None,
          indicators=None, type: str | None = None) -> dict:
    """Return every corpus package referencing *value*.

    *type* overrides the shape inference, which a caller needs when the two
    disagree: a package name can be spelled like a host, and a name that is
    all hex of digest length reads as a digest.

    The result carries ``listed``/``confidence``/``provenance`` so a caller
    can tell a shipped indicator from an ad-hoc query, and ``sources`` names
    what was actually searched - an empty result over an empty corpus means
    "nothing was searched", not "nothing references it".
    """
    indicators = load_indicators() if indicators is None else indicators
    type_ = type or infer_type(value)
    entry = indicators.match(type_, value)
    normalized = normalize(type_, value)
    if normalized is None:
        return {
            "indicator": value, "type": type_, "listed": False,
            "error": f"{value!r} is not a usable {type_} value",
            "matches": [], "sources": [],
        }
    needle = normalized

    if metadata is None:
        metadata = _load_metadata()

    sources = []
    matches = _metadata_hits(needle, type_, metadata)
    if metadata:
        sources.append(f"metadata ({len(metadata)} packages)")
    snapshot_matches = _snapshot_hits(needle, type_)
    if snapshot_matches or type_ != "package":
        rows = _snapshot_rows()
        if rows:
            sources.append(f"pkgbuild snapshots ({len(rows)})")
    seen = {(m["package"], m["surface"]) for m in matches}
    for hit in snapshot_matches:
        if (hit["package"], hit["surface"]) not in seen:
            matches.append(hit)

    matches.sort(key=lambda m: (m["package"], m["surface"]))
    return {
        "indicator": needle,
        "type": type_,
        "listed": entry is not None,
        "confidence": entry.confidence if entry else None,
        "provenance": entry.provenance if entry else None,
        "campaign": entry.campaign if entry else None,
        "list_version": indicators.version,
        "matches": matches,
        "sources": sources,
    }
