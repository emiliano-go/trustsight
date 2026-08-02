from ..config import DEFAULT_NETWORK_TOOLS, load_patterns
from ..db import is_established_package, top_dependency_names
from ..deps import extract_dependency_changes, is_related_package
from ..novelty import is_dependency_novel, typosquat_target
from .base import _experimental_enabled, _rarities_of

_DEP_EXPANSION_GATE = 1.5


def _network_tools(config: dict) -> frozenset:
    """Return network tool names from patterns.toml, then config.toml, then
    the code default."""
    tools = load_patterns().get("patterns", {}).get("network_tools")
    if tools:
        return frozenset(tools)
    tools = config.get("tools", {}).get("network_makedepends")
    return frozenset(tools) if tools else frozenset(DEFAULT_NETWORK_TOOLS)


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
