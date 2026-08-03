from ..config import (
    DEFAULT_NETWORK_TOOLS,
    load_patterns,
    load_thresholds,
)
from ..db import dependency_observation_count, is_established_package, top_dependency_names
from ..deps import extract_dependency_changes, is_related_package
from ..novelty import is_dependency_novel, typosquat_target
from .base import _experimental_enabled, _rarities_of

_DEP_EXPANSION_GATE = 1.5

# A name this many packages depend on counts as "widely provided" for R116.
# Uses the same observation table as the typosquat proxy; overridden by
# ``[r116] widely_provided_observations`` in thresholds.toml.
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
    thresholds = load_thresholds().get("r116", {})
    return int(thresholds.get(
        "widely_provided_observations", _WIDELY_PROVIDED_OBSERVATIONS
    ))


def _is_widely_provided(name: str, config: dict) -> bool:
    """True when the corpus shows *name* is depended on by many packages.

    R116's "widely-provided (corpus-measured)" signal: distinct from
    *established* (official repo membership), this is the observation-count
    proxy from the dependency seed, so a package claiming a name the whole
    AUR relies on is flagged even when pacman has no repo data.
    """
    return dependency_observation_count(name) >= _widely_provided_threshold(config)


def _scope_expansion_findings(diff_text, package_name, config, add) -> None:
    """Newly claimed ``provides``/``replaces`` naming an established or widely
    provided package unrelated to *package_name* (R116).

    The default-path counterpart of the experimental D004: a package that
    inserts itself in front of a name the ecosystem relies on has a
    packaging purpose only when that name is its own project (a variant,
    companion or sibling — ``is_related_package``), which is suppressed
    here.  No corpus and no pacman data means neither signal can fire, so
    cold start never trips it.
    """
    added_deps = extract_dependency_changes(diff_text, package_name)
    for field in ("provides", "replaces"):
        for name in sorted(added_deps.get(field, ())):
            if is_related_package(name, package_name):
                continue
            if is_established_package(name):
                add("R116", "Provides/Replaces Scope Expansion", "HIGH",
                    "dependency",
                    f"{field} claims '{name}', an established package unrelated "
                    f"to '{package_name}'",
                    field=field, dep_name=name, kind="established",
                    package_name=package_name)
                return
            if _is_widely_provided(name, config):
                add("R116", "Provides/Replaces Scope Expansion", "MEDIUM",
                    "dependency",
                    f"{field} claims '{name}', widely depended on but unrelated "
                    f"to '{package_name}'",
                    field=field, dep_name=name, kind="widely depended on",
                    package_name=package_name)
                return


def _dependency_findings(diff_text, package_name, config, add) -> None:
    added_deps = extract_dependency_changes(diff_text, package_name)

    all_new: list[str] = []
    for field in ("depends", "makedepends", "optdepends", "checkdepends"):
        all_new.extend(added_deps.get(field, ()))
    if len(all_new) >= 3:
        rarities = _rarities_of(all_new)
        magnitude = len(all_new) * (sum(rarities) / len(rarities))
        if magnitude >= _DEP_EXPANSION_GATE:
            novel = [d for d, r in zip(all_new, rarities) if r > 0.5]
            add("R075", "Dependency-Set Expansion", "MEDIUM", "dependency",
                f"diff adds {len(novel)} novel/rare deps: {novel}",
                n_novel=len(novel), novel_names=", ".join(novel))

    _scope_expansion_findings(diff_text, package_name, config, add)

    wanted = {r for r in ("D001", "D002", "D003", "D004")
              if _experimental_enabled(config, r)}
    if not wanted:
        return

    if wanted & {"D001", "D002"}:
        candidates: list[str] | None = None
        for field in ("depends", "makedepends", "optdepends", "checkdepends"):
            for name in sorted(added_deps.get(field, ())):
                if not is_dependency_novel(name):
                    continue
                impersonated = None
                if "D002" in wanted:
                    if candidates is None:
                        candidates = top_dependency_names()
                    impersonated = typosquat_target(name, candidates)
                if impersonated:
                    add("D002", "Typosquatted Dependency", "HIGH", "dependency",
                        f"{field} '{name}' resembles '{impersonated}'",
                        field=field, dep_name=name, impersonated=impersonated)
                elif "D001" in wanted:
                    add("D001", "Novel Dependency Added", "HIGH", "dependency",
                        f"{field} '{name}' has never been seen in the AUR",
                        field=field, dep_name=name)

    if "D003" in wanted:
        new_network = sorted(added_deps.get("makedepends", set()) & _network_tools(config))
        if new_network:
            add("D003", "New Network-Using Makedepends", "MEDIUM", "dependency",
                f"build can now reach the network via {new_network}",
                new_network=", ".join(new_network))

    if "D004" in wanted:
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
