"""The U-series extension: upstream CI and release integrity.

The layer reads only what a recipe *declares* about upstream (its ``url=``,
its ``source=()`` entries, its ``validpgpkeys``) and what the diff already
shows (an added ``.github/workflows/*`` path).  A2 forbids fetching a
declared URL and A8 forbids extracting an archive, so upstream content is
never read locally: these rules see the manifest presented at the border,
never the cargo inside it.

Two rules are *federation-fed* (U007/U008): the upstream workflow content
lives on a host a local analyser may not read, so a signed IOC baseline of
type ``upstream_repo`` carries the shape a scanner with legitimate access
observed.  The remaining rules are pure diff projections.

The spec's flagship (same URL and version, changed declared checksum) is
already C001 "Checksum Changed Without Source Change With Stable Version",
so no rule is filed for it here.
"""

from __future__ import annotations

import re

from ..buckets import canonical_host, host_is_non_routable
from .structural._provenance import (
    _declared_upstream_url,
    _forge_owner_repo,
    _head_upstream_text,
)

#: A workflow file inside ``.github/workflows`` (YAML; ``.yml`` or ``.yaml``).
_CI_WORKFLOW_RE = re.compile(
    r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", re.IGNORECASE)

#: A scheme, per RFC 3986: ``scheme://`` (``git+ssh://``, ``file://``, ...).
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")

#: scp-style transport: ``user@host:path``, which carries no scheme at all.
_SCP_RE = re.compile(r"^[^/@:\s]+@[^/:\s]+:")

#: Schemes that name a private access transport rather than a public fetch.
_SSH_SCHEMES = frozenset({"ssh", "git+ssh", "svn+ssh", "rsync"})

__all__ = [
    "access_of_source",
    "added_ci_workflows",
    "declared_upstream_repo",
    "has_validpgpkeys",
    "upstream_release_findings",
]


def _strip_rename(token: str) -> str:
    """The URL half of a ``name::url`` source entry, or the token unchanged."""
    if "::" in token:
        return token.split("::", 1)[1]
    return token


def access_of_source(token: str) -> tuple[str, str]:
    """``(access, host)`` for one declared ``source=()`` token.

    ``access`` is one of ``public``, ``embedded_credentials``, ``ssh``,
    ``file``, ``private_network``, ``local`` or ``other``.  ``host`` is the
    canonical host when the token names one, else ``""``.  Nothing is
    fetched: this is a read of the declaration's shape.
    """
    token = str(token).strip().strip("'\"")
    if not token:
        return "local", ""
    value = _strip_rename(token)
    if _SCP_RE.match(value):
        host = value.split("@", 1)[1].split(":", 1)[0]
        return "ssh", canonical_host(host)
    match = _SCHEME_RE.match(value)
    if not match:
        # A bare filename is a companion file the recipe ships.
        return "local", ""
    scheme = match.group(1).lower()
    rest = value[match.end():]
    if scheme == "file":
        return "file", ""
    authority = rest.split("/", 1)[0]
    if scheme in _SSH_SCHEMES:
        return "ssh", canonical_host(authority)
    host = canonical_host(authority)
    if "@" in authority:
        return "embedded_credentials", host
    if host_is_non_routable(authority):
        return "private_network", host
    return "public", host


def declared_upstream_repo(recipe_text: str | None) -> str:
    """The canonical ``host/owner/repo`` of a trusted-forge ``url=``, else ""."""
    url = _declared_upstream_url(recipe_text)
    if not url:
        return ""
    parsed = _forge_owner_repo(url)
    if parsed is None:
        return ""
    forge, owner, repo = parsed
    return f"{forge}/{owner}/{repo}"


def has_validpgpkeys(recipe_text: str | None) -> bool:
    """True when the recipe carries a ``validpgpkeys`` declaration."""
    if not recipe_text:
        return False
    try:
        from ..recipedoc import parse_recipe

        recipe = parse_recipe(recipe_text)
    except Exception:  # noqa: BLE001 - a refusal falls back to the raw shape
        return bool(re.search(r"^\s*validpgpkeys\s*=", recipe_text, re.M))
    return "validpgpkeys" in recipe.arrays or "validpgpkeys" in recipe.scalars


def is_ci_workflow_path(path: str) -> bool:
    """Whether *path* is a committed GitHub Actions workflow."""
    return bool(_CI_WORKFLOW_RE.search(path))


def added_ci_workflows(delta) -> list[str]:
    """Added ``.github/workflows/*`` paths the diff introduced, sorted."""
    if delta is None:
        return []
    return sorted(
        f.path for f in getattr(delta, "files", ())
        if f.status == "added" and is_ci_workflow_path(f.path)
    )


def _resolve_entry(raw: str, table: dict[str, str] | None) -> str:
    """Resolve a source entry's own variables, when a table is available."""
    if not table or "$" not in raw:
        return raw
    from ..expansion import resolve_text

    try:
        return resolve_text(raw, table)
    except Exception:  # noqa: BLE001 - an unresolved entry stays literal
        return raw


def _ioc_section(config) -> dict:
    """The ``baselines.ioc`` mapping, or {} for any shape that is not one.

    A caller may hand a config with ``baselines: None``, an ``ioc`` key set to
    a non-mapping, or no config at all: none of those is a reason to fail an
    analysis, so every read of the section goes through here.
    """
    if not isinstance(config, dict):
        return {}
    baselines = config.get("baselines")
    if not isinstance(baselines, dict):
        return {}
    section = baselines.get("ioc")
    return section if isinstance(section, dict) else {}


def _federation_matches(repo: str, config: dict | None, matches) -> list:
    """Signed ``upstream_repo`` baseline matches for *repo*, or [] when cold.

    *matches* is injectable so a test (or the harness) can supply a
    federation finding without a populated database.
    """
    if matches is not None:
        try:
            return list(matches)
        except TypeError:  # noqa: BLE001 - a non-iterable injection is no match
            return []
    if not repo:
        return []
    if not _ioc_section(config).get("enabled", True):
        return []
    try:
        from ..config import load_ioc_sources
        from ..ioc_baseline import match_upstream_repo

        matched = match_upstream_repo(repo)
        sources = set(load_ioc_sources())
        if sources:
            matched = [m for m in matched if getattr(m, "source", "") in sources]
        return matched
    except Exception:  # noqa: BLE001 - a cold or unlocked store is no matches
        return []


def _federation_unavailable(repo: str, config: dict | None, matches) -> bool:
    """True when the federation channel could not answer for *repo*.

    A *cold* channel - a disabled baseline or a store carrying no
    ``upstream_repo`` entries - leaves the declared upstream unread, so W012
    names it.  A consulted channel that simply holds no entry for *repo* is a
    miss, not an unavailable channel; *matches* being injected means it was
    consulted.
    """
    if not repo or matches is not None:
        return False
    if not _ioc_section(config).get("enabled", True):
        return True
    try:
        from ..ioc_baseline import has_upstream_repo_entries

        return not has_upstream_repo_entries()
    except Exception:  # noqa: BLE001 - an unreachable store is unavailable
        return True


def _c020_owns(token: str) -> bool:
    """True when C020 already files this credential-bearing source URL.

    C020 reads the gained routable ``http(s)`` URLs, so a credential on a
    public web URL is its finding; U010 stands down there and keeps the
    transports C020 cannot see (non-``http`` schemes, non-routable hosts).
    """
    match = _SCHEME_RE.match(token)
    if not match or match.group(1).lower() not in ("http", "https"):
        return False
    authority = token[match.end():].split("/", 1)[0]
    return not host_is_non_routable(authority)


def upstream_release_findings(
    diff_text: str,
    delta,
    add,
    config: dict | None = None,
    package_name: str = "",
    current_text: str | None = None,
    source_changes=None,
    matches=None,
) -> None:
    """Emit U007-U010 for one analysis.

    U007/U008 are federation-fed (a signed ``upstream_repo`` baseline match
    on the declared upstream).  U009 reads an added CI workflow path from
    the diff.  U010 reads the access mode of source entries the diff gained.
    """
    thresholds = (config or {}).get("thresholds", {}) if isinstance(config, dict) else {}
    try:
        max_u010 = int(thresholds.get("u010", {}).get("max_findings", 5) or 5)
    except (TypeError, ValueError):
        max_u010 = 5

    head = _head_upstream_text(diff_text, current_text)
    pkgver_bumped = bool(
        delta is not None and getattr(delta.version, "pkgver_changed", False))

    # U007 / U008: a federation finding for the repo this recipe declares.
    repo = declared_upstream_repo(head)
    federated = _federation_matches(repo, config, matches)
    federated_fired = False
    for match in federated:
        shape = (getattr(match, "shape", "") or "exfil").strip().lower()
        rule_id = "U008" if shape == "history_sweep" else "U007"
        name = ("Git-History Credential Sweep" if rule_id == "U008"
                else "CI Exfil Shape")
        corroboration = " (pkgver bumped in the same diff)" if pkgver_bumped else ""
        add(rule_id, name, "MEDIUM", "upstream-ci",
            f"federated finding: {repo} gained a {shape} workflow"
            f"{corroboration}",
            line=None, upstream_repo=repo, shape=shape,
            ioc_source=getattr(match, "source", ""),
            provenance=getattr(match, "provenance", ""),
            campaign=getattr(match, "campaign", ""),
            pkgver_bumped=pkgver_bumped,
            # Federation is an indicator tier: maximum-priority alerting,
            # never heuristic points (the same contract as other IOC hits).
            weight_override=0)
        federated_fired = True

    # U009: a CI workflow committed into the AUR repository (weight 0).
    for path in added_ci_workflows(delta):
        add("U009", "New CI Surface Committed", "LOW", "upstream-ci",
            f"{path} added; a new automation surface in the package repo",
            file=path, line=None, corroborated=federated_fired,
            weight_override=0)

    # U010: a source the public cannot inspect.
    table = None
    if current_text:
        from ..expansion import text_variable_table

        try:
            table = text_variable_table(current_text)
        except Exception:  # noqa: BLE001 - falls back to literal entries
            table = None
    gained = tuple(getattr(delta, "sources", None).gained) if delta is not None else ()
    validpgp = has_validpgpkeys(head)
    emitted: set[tuple[str, str]] = set()
    for raw in gained:
        token = _resolve_entry(str(raw), table)
        access, host = access_of_source(token)
        if access not in ("ssh", "file", "private_network", "embedded_credentials"):
            continue
        if access == "embedded_credentials" and _c020_owns(token):
            continue
        key = (access, host)
        if key in emitted or len(emitted) >= max_u010:
            continue
        emitted.add(key)
        where = f"host {host}" if host else "the local filesystem"
        amplified = not validpgp
        add("U010", "Unauditable Upstream", "MEDIUM", "source",
            f"source entry is not publicly inspectable ({access}) on {where}"
            + ("; no validpgpkeys vouches for it" if amplified else ""),
            line=None, access=access, host=host, amplified=amplified)

    # W011 / W012: the A2 standing boundary and the cold-federation note.
    # Both are weight-0 statements about the analysis, reported once per
    # report, never a gap (forbids_clean stays False).
    if repo:
        url = _declared_upstream_url(head)
        add("W011", "Upstream Content Not Read", "INFO", "unverifiable",
            f"upstream content declared at {url or repo} was not read "
            f"(A2: the analysis reads declarations, never upstream itself)",
            line=None, upstream_repo=repo, url=url)
        if _federation_unavailable(repo, config, matches):
            add("W012", "Federation Not Consulted", "INFO", "unverifiable",
                f"the upstream_repo federation channel holds no data for "
                f"{repo}; U007/U008 could not be checked",
                line=None, upstream_repo=repo)
