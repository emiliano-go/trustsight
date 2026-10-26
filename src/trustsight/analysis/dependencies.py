import re

from ..config import (
    DEFAULT_NETWORK_TOOLS,
    load_patterns,
    load_thresholds,
)
from ..db import (
    dependency_observation_count,
    dependency_table_populated,
    is_established_package,
    top_dependency_names,
)
from ..deps import (
    declared_package_names,
    extract_dependency_changes,
    is_ignorable,
    is_related_package,
    normalize_dependency,
)
from ..novelty import is_dependency_novel, typosquat_target
from .base import _code_rule_enabled, _rarities_of

_DEP_EXPANSION_GATE = 1.5

#: A VCS source already needs its client in `makedepends`; adding that client
#: is not a *new* network reach.  `waycentral-git` moved `git` from `depends`
#: to `makedepends` while its source stayed `git+https://...`, and D003 read
#: the correction as a new fetch capability.
_VCS_SCHEME_RE = re.compile(r"\b(git|svn|hg|bzr|fossil)\+", re.IGNORECASE)
_VCS_NAME_SUFFIXES = ("git", "svn", "hg", "bzr", "fossil")


def _vcs_tools(text: str | None, package_name: str) -> set[str]:
    """VCS clients the recipe already needs to fetch its own source."""
    tools = {match.lower() for match in _VCS_SCHEME_RE.findall(text or "")}
    for suffix in _VCS_NAME_SUFFIXES:
        if package_name.endswith("-" + suffix):
            tools.add(suffix)
    return tools

# A name this many packages depend on counts as "widely provided" for H064.
# Uses the same observation table as the typosquat proxy; overridden by
# ``[h064] widely_provided_observations`` in thresholds.toml.
_WIDELY_PROVIDED_OBSERVATIONS = 25


def _network_tools(config: dict) -> frozenset:
    """Return network tool names from patterns.toml, then config.toml, then
    the code default."""
    tools = load_patterns().get("patterns", {}).get("network_tools")
    if tools:
        return frozenset(tools)
    tools = config.get("tools", {}).get("network_makedepends")
    return frozenset(tools) if tools else frozenset(DEFAULT_NETWORK_TOOLS)


def _widely_provided_threshold(config: dict) -> int:
    thresholds = load_thresholds().get("h064", {})
    return int(thresholds.get(
        "widely_provided_observations", _WIDELY_PROVIDED_OBSERVATIONS
    ))


def _is_widely_provided(name: str, config: dict) -> bool:
    """True when the corpus shows *name* is depended on by many packages.

    H064's "widely-provided (corpus-measured)" signal: distinct from
    *established* (official repo membership), this is the observation-count
    proxy from the dependency seed, so a package claiming a name the whole
    AUR relies on is flagged even when pacman has no repo data.
    """
    return dependency_observation_count(name) >= _widely_provided_threshold(config)


def _added_deps(diff_text, package_name, delta,
                current_text=None) -> dict[str, set[str]]:
    """The normalised added dependency names, from the shared delta or the
    extractor. One construction site: the delta and the rules
    read the same facts.  The fallback validates against *current_text* too,
    so every path that has the post recipe agrees about hunk-boundary
    ambiguity."""
    if delta is not None:
        return {f: set(v) for f, v in delta.added_dependencies.items()}
    return extract_dependency_changes(
        diff_text, package_name, current_text=current_text
    )


def _scope_expansion_findings(diff_text, package_name, config, add,
                              delta=None, current_text=None) -> None:
    """Newly claimed ``provides``/``replaces`` naming an established or widely
    provided package unrelated to *package_name* (H064).

    The default-path counterpart of the experimental D004: a package that
    inserts itself in front of a name the ecosystem relies on has a
    packaging purpose only when that name is its own project (a variant,
    companion or sibling - ``is_related_package``), which is suppressed
    here.  No corpus and no pacman data means neither signal can fire, so
    cold start never trips it.

    The added names come from the shared ``ChangeDelta`` when *delta* is
    given; otherwise the extractor runs here.
    """
    added_deps = _added_deps(
        diff_text, package_name, delta, current_text=current_text
    )
    # `conflicts` belongs beside the other two.  All three insert this
    # package in front of a name the ecosystem relies on: `provides` and
    # `replaces` claim to *be* it, and `conflicts` makes pacman refuse to
    # install it alongside - which removes the real package just as
    # effectively while raising nothing at all.  The asymmetry was visible
    # in the numbers: `replaces=('firefox')` scored HIGH and
    # `conflicts=('firefox')` scored zero.
    for field in ("provides", "replaces", "conflicts"):
        for name in sorted(added_deps.get(field, ())):
            if is_related_package(name, package_name):
                continue
            established = is_established_package(name)
            widely = _is_widely_provided(name, config)
            if not (established or widely):
                continue
            # `provides`/`replaces` *claim* the name, so official-repo
            # membership alone is enough for HIGH.  `conflicts` only refuses
            # co-installation; it is a scope statement when the target is one
            # the ecosystem depends on, and a lower-confidence note when it is
            # merely established (alda's documented icedtea-web
            # incompatibility is the common benign shape).  A conflict alone
            # never composes into H098, because D004 stays provides/replaces.
            if field == "conflicts":
                severity = "HIGH" if widely else "INFO"
                kind = "widely depended on" if widely else "established"
            else:
                severity = "HIGH" if established else "MEDIUM"
                kind = "established" if established else "widely depended on"
            add("H064", "Provides/Replaces Scope Expansion", severity,
                "dependency",
                f"{field} claims '{name}', {kind} but unrelated "
                f"to '{package_name}'",
                field=field, dep_name=name, kind=kind,
                package_name=package_name,
                weight_override=0 if field == "conflicts" and not widely else None)
            return


def name_shadow_findings(text: str, package_name: str,
                         skip: set[str] | None = None) -> list[dict]:
    """D005: a name that shadows an established package, as absolute state.

    H064/D004 own *newly added* ``provides``/``replaces``/``conflicts``; this
    rule owns the name a recipe carries now, including one whose target only
    became an official package later.  Three signals:

    * a ``pkgname`` output that is exactly an established package - the AUR
      package claims a name pacman already resolves elsewhere;
    * a ``provides``/``replaces`` entry naming an established package
      unrelated to this one, whether it was added in this diff or has been
      there all along (sonames and variants are suppressed);
    * a ``conflicts`` entry naming an established package unrelated to this
      one (a variant such as ``foo-git`` conflicting ``foo`` is the ordinary
      pattern and is suppressed).

    *skip* holds names already reported by the diff-time rules, so an added
    claim is not reported twice.  Weight 0 until the benign corpus
    calibrates it; cold start (no pacman, no observations) fires nothing.
    """
    if not text:
        return []
    from ..findings import stamp
    from ..recipedoc import parse_recipe

    try:
        doc = parse_recipe(text, file="PKGBUILD")
    except Exception:
        return []

    skip = skip or set()
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def emit(name: str, kind: str, match: str) -> None:
        key = (kind, name)
        if key in seen:
            return
        seen.add(key)
        findings.append(stamp({
            "rule_id": "D005", "name": "Official-Repo Name Shadow",
            "severity": "MEDIUM", "category": "dependency",
            "weight_override": 0, "match": match,
            "file": "PKGBUILD", "line": None,
            "params": {"kind": kind, "dep_name": name,
                       "package_name": package_name},
        }))

    for name in sorted(declared_package_names(text)):
        if name in skip:
            continue
        if is_established_package(name):
            emit(name, "pkgname",
                 f"pkgname '{name}' is an established package")

    def field_entries(field: str) -> tuple[str, ...]:
        return tuple(
            entry
            for key, values in doc.arrays.items()
            if key == field or key.startswith(field + "_")
            for entry in values
        )

    # Absolute provides/replaces: the same claim H064/D004 see only when it
    # is *added*.  A reservation or rename that predates the diff still
    # redirects installs of the name, so it belongs to the absolute-state
    # rule.  The fold drops an entry that cannot be resolved rather than
    # guessing at a name.
    from ..changes import _resolve_relational

    claimed: set[str] = set()
    for field in ("provides", "replaces"):
        for entry in _resolve_relational(field_entries(field), doc.scalars):
            name = normalize_dependency(entry)
            if not name or name in skip or name in claimed:
                continue
            if is_ignorable(name) or is_related_package(name, package_name):
                continue
            if is_established_package(name):
                claimed.add(name)
                emit(name, field,
                     f"{field} claims '{name}', an established package "
                     f"unrelated to '{package_name}'")

    conflicts = field_entries("conflicts")
    for name in sorted(conflicts):
        if name in skip or is_related_package(name, package_name):
            continue
        if is_established_package(name):
            emit(name, "conflicts",
                 f"conflicts claims '{name}', an established package "
                 f"unrelated to '{package_name}'")

    return findings


def _dependency_findings(diff_text, package_name, config, add, current_text=None,
                         delta=None) -> None:
    added_deps = _added_deps(
        diff_text, package_name, delta, current_text=current_text
    )
    # A split package's own outputs are new to the AUR by construction;
    # D001/H030 must not read a dependency on them as an outside name.
    self_outputs = declared_package_names(current_text) if current_text else set()

    all_new: list[str] = []
    for field in ("depends", "makedepends", "optdepends", "checkdepends"):
        all_new.extend(
            name for name in added_deps.get(field, ())
            if name not in self_outputs
        )
    if len(all_new) >= 3:
        rarities = _rarities_of(all_new)
        magnitude = len(all_new) * (sum(rarities) / len(rarities))
        if magnitude >= _DEP_EXPANSION_GATE:
            # Sorted: the names come out of a set, and the finding text is
            # part of the recorded analysis, so its order must not depend
            # on the set's internal layout.
            novel = sorted(d for d, r in zip(all_new, rarities) if r > 0.5)
            add("H030", "Dependency-Set Expansion", "MEDIUM", "dependency",
                f"diff adds {len(novel)} novel/rare deps: {novel}",
                n_novel=len(novel), novel_names=", ".join(novel))

    _scope_expansion_findings(
        diff_text, package_name, config, add,
        delta=delta, current_text=current_text,
    )

    # H064/D004 own a claim added in this diff; D005 owns the claim the
    # recipe carries now.  Hand the diff-time names over so a fresh claim is
    # reported once, on the rule that describes the change.
    diff_claims: set[str] = set()
    for field in ("provides", "replaces", "conflicts"):
        diff_claims.update(added_deps.get(field, ()))
    for shadow in name_shadow_findings(
        current_text or "", package_name, skip=diff_claims,
    ):
        add(shadow["rule_id"], shadow["name"], shadow["severity"],
            shadow["category"], shadow["match"],
            weight_override=shadow.get("weight_override"),
            **(shadow.get("params") or {}))

    wanted = {r for r in ("D001", "D002", "D003", "D004")
              if _code_rule_enabled(config, r)}
    if not wanted:
        return

    # D2: a D-rule that declines for insufficient observations
    # is a first-class, weight-0 boundary, not silence.  D001/D002 abstain
    # when the dependency corpus is unseeded (every name would look novel,
    # which is the cold-start guard); naming that abstention is the same
    # honesty contract the W series applies to unread content.
    if wanted & {"D001", "D002"} and all_new and not dependency_table_populated():
        add("W007", "Dependency Novelty Declined For Insufficient Observations",
            "INFO", "unverifiable",
            "D001/D002 abstained: the dependency corpus holds no "
            f"observations, so {len(all_new)} added dependency name(s) were "
            "not judged novel or known",
            line=None, rule="D001/D002", observed=0, count=len(all_new))

    if wanted & {"D001", "D002"}:
        candidates: list[str] | None = None
        for field in ("depends", "makedepends", "optdepends", "checkdepends"):
            for name in sorted(added_deps.get(field, ())):
                if name in self_outputs or not is_dependency_novel(name):
                    continue
                impersonated = None
                # An added name that is itself an established package is not a
                # typosquat: `tlottie` resembles `rlottie` but is a real extra
                # package, and a name-similarity hit on a package that exists
                # is a naming heuristic, not impersonation.
                if "D002" in wanted and not is_established_package(name):
                    if candidates is None:
                        candidates = top_dependency_names()
                    impersonated = typosquat_target(name, candidates)
                if impersonated:
                    add("D002", "Typosquatted Dependency", "HIGH", "dependency",
                        f"{field} '{name}' resembles '{impersonated}'",
                        field=field, dep_name=name, impersonated=impersonated)
                elif "D001" in wanted:
                    # MEDIUM, not HIGH: "never seen in the AUR" is a
                    # history-derived prior (an unseeded or quiet corpus can
                    # make an ordinary new dependency look novel), so it is
                    # evidence to weigh, not a high-severity finding on its
                    # own.  It stays scored and quietable-by-poisoning.
                    add("D001", "Novel Dependency Added", "MEDIUM", "dependency",
                        f"{field} '{name}' has never been seen in the AUR",
                        field=field, dep_name=name)

    if "D003" in wanted:
        network = (added_deps.get("makedepends", set())
                   | added_deps.get("checkdepends", set())) & _network_tools(config)
        # A VCS client the recipe already needs to fetch its own source is not
        # a new network capability.  Keep curl/wget and every other fetch tool.
        network -= _vcs_tools(current_text or diff_text, package_name)
        new_network = sorted(network)
        if new_network:
            add("D003", "New Network-Using Makedepends", "MEDIUM", "dependency",
                f"build can now reach the network via {new_network}",
                new_network=", ".join(new_network))

    if "D004" in wanted:
        # A `conflicts` entry refuses co-installation; it does not claim to be
        # or replace the name.  H064 reports that shape at its own severity,
        # so D004 (and the H098 cluster) stay about actual provides/replaces
        # hijacks.
        for field in ("provides", "replaces"):
            for name in sorted(added_deps.get(field, ())):
                if is_related_package(name, package_name):
                    continue
                if is_established_package(name):
                    add("D004", "Dependency Hijack Via Provides", "HIGH", "dependency",
                        f"{field} '{name}', an established package unrelated to "
                        f"'{package_name}'",
                        field=field, dep_name=name)
                    return
