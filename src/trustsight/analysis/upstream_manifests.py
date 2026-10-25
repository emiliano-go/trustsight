"""The U-series: rules over committed upstream dependency manifests.

The layer reads only what the repository already shows (the tree walk and
the diff).  U001/U002/U005 are ledger entries (INFO, weight 0, B10); only
U003 (a new remote source enters the recipe's reach) and U004 (the resolver
is redirected) score, at MEDIUM.  A manifest that could not be parsed is
named by W009, never skipped.
"""

from __future__ import annotations

import re

from .manifests import manifest_format

#: Ecosystem keyword -> format family, for the boundary cross-reference.
_ECOSYSTEMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("cargo", ("cargo", "rustc")),
    ("npm", ("npm", "yarn", "pnpm", "node", "bun", "deno")),
    ("pip", ("pip", "pip3", "poetry", "pipx", "uv")),
    ("conda", ("conda", "mamba", "micromamba", "pixi")),
    ("go", ("go",)),
    ("gem", ("gem", "bundle", "bundler")),
    ("composer", ("composer",)),
    ("jvm", ("maven", "mvn", "gradle", "sbt", "ant", "ivy")),
    ("dotnet", ("dotnet", "nuget", "msbuild", "paket")),
    ("dart", ("dart", "flutter", "pub")),
    ("swift", ("swift", "cocoapods", "pod", "carthage")),
    ("elixir", ("mix", "hex", "rebar3", "erlang")),
    ("haskell", ("cabal", "stack", "ghc")),
    ("ocaml", ("opam", "dune")),
    ("cpp", ("cmake", "conan", "vcpkg", "meson", "make")),
    ("r", ("rscript", "renv")),
    ("perl", ("cpan", "cpanm")),
    ("crystal", ("shards", "crystal")),
    ("julia", ("julia",)),
    ("fortran", ("fpm",)),
    ("gleam", ("gleam",)),
)


def ecosystem_of_command(command: str) -> str | None:
    """The manifest format a build-time registry command belongs to."""
    text = command.lower()
    for fmt, tokens in _ECOSYSTEMS:
        for token in tokens:
            if re.search(rf"(?<![\w-]){re.escape(token)}(?![\w-])", text):
                return fmt
    return None


def committed_manifest(tree_manifest, command: str) -> tuple[str, str] | None:
    """``(format, path)`` of a committed manifest for the command's ecosystem."""
    fmt = ecosystem_of_command(command)
    if not fmt:
        return None
    for path, _head in tree_manifest or ():
        if manifest_format(path) == fmt:
            return fmt, path
    return None


def _names(values) -> str:
    return ", ".join(str(v) for v in values)


#: Manifest basename -> the lockfile basenames that pin it.  A manifest that
#: changes without its lock is a real integrity signal (spec section 7.2),
#: but VCS and library packaging legitimately omit lockfiles, so U006 stays a
#: weight-0 ledger entry until the corpus can adjudicate a scored rate.
_LOCK_PEERS: dict[str, tuple[str, ...]] = {
    "go.mod": ("go.sum", "go.work.sum"),
    "cargo.toml": ("cargo.lock",),
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                     "pnpm-lock.yaml", "bun.lock"),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "pipfile.lock",
                       "pylock.toml"),
    "requirements.txt": ("requirements.lock", "poetry.lock", "uv.lock",
                         "pdm.lock", "pipfile.lock"),
    "pubspec.yaml": ("pubspec.lock",),
    "mix.exs": ("mix.lock",),
    "stack.yaml": ("stack.yaml.lock",),
    "shard.yml": ("shard.lock",),
    "package.swift": ("package.resolved",),
}


def _lock_peer(path: str) -> tuple[str, ...]:
    base = path.lower().rsplit("/", 1)[-1]
    if base in _LOCK_PEERS:
        return _LOCK_PEERS[base]
    if base.startswith("requirements") and base.endswith(".txt"):
        return _LOCK_PEERS["requirements.txt"]
    if base.endswith(".cabal"):
        return ("cabal.project.freeze",)
    return ()


def _is_lockfile(path: str) -> bool:
    base = path.lower().rsplit("/", 1)[-1]
    return any(base in peers for peers in _LOCK_PEERS.values()) \
        or base == "cabal.project.freeze"


def _integrity_pairs(delta, add) -> None:
    """U006: a manifest changed without a lockfile that pins it (weight 0)."""
    present = {
        m.path.lower() for m in delta.manifests if m.status != "removed"
    }
    for manifest in delta.manifests:
        if manifest.status == "removed":
            continue
        peers = _lock_peer(manifest.path)
        if not peers:
            continue
        directory = manifest.path.lower().rsplit("/", 1)[0] + "/" \
            if "/" in manifest.path else ""
        # A workspace root lock applies; a lock in an unrelated sibling does
        # not. Removed lockfiles never satisfy the pairing.
        if any(directory + peer in present or peer in present for peer in peers):
            continue
        add("U006", "Manifest Changed Without Its Lockfile", "INFO",
            "dependency-manifest",
            f"{manifest.path} changed but no lockfile ({', '.join(peers)}) "
            f"did in the same update",
            file=manifest.path, peers=", ".join(peers))


def upstream_manifest_findings(
    diff_text: str,
    tree_manifest,
    delta,
    add,
    config: dict | None = None,
    package_name: str = "",
) -> None:
    """Emit U001-U005 (and the W009 refusal boundary) for one analysis."""
    thresholds = (config or {}).get("thresholds", {}) if isinstance(config, dict) else {}
    try:
        jump = float(thresholds.get("u005", {}).get("jump_factor", 3.0) or 3.0)
    except (TypeError, ValueError):
        jump = 3.0

    for manifest in delta.manifests:
        path = manifest.path

        if manifest.status == "added":
            add("U001", "Manifest Added Or Removed", "INFO",
                "dependency-manifest",
                f"manifest added: {path} ({manifest.format})",
                file=path, change="added")
        elif manifest.status == "removed":
            add("U001", "Manifest Added Or Removed", "INFO",
                "dependency-manifest",
                f"manifest removed: {path} ({manifest.format})",
                file=path, change="removed")

        if manifest.added or manifest.removed:
            parts = []
            if manifest.added:
                parts.append("added " + _names(manifest.added))
            if manifest.removed:
                parts.append("removed " + _names(manifest.removed))
            add("U002", "Upstream Dependency Delta", "INFO",
                "dependency-manifest",
                f"{path}: " + "; ".join(parts),
                file=path, added=_names(manifest.added),
                removed=_names(manifest.removed))

        if manifest.remote_added:
            add("U003", "New Remote Source In Manifest", "MEDIUM",
                "dependency-manifest",
                f"{path} now fetches from new host(s): "
                f"{_names(manifest.remote_added)}",
                file=path, hosts=_names(manifest.remote_added),
                added=_names(manifest.added))

        for change in manifest.origin_changes:
            add("U011", "Upstream Origin Changed", "MEDIUM",
                "dependency-manifest", f"{path}: {change}",
                file=path, change=change)

        if manifest.integrity_changes or (
                manifest.status == "removed" and _is_lockfile(path)):
            detail = "; ".join(manifest.integrity_changes) or "lockfile removed"
            add("U012", "Lockfile Integrity Weakened", "INFO",
                "dependency-manifest", f"{path}: {detail}",
                file=path, changes="; ".join(manifest.integrity_changes))

        if (manifest.old_count and manifest.status != "removed"
                and manifest.new_count >= jump * manifest.old_count):
            add("U005", "Dependency Surface Jump", "INFO",
                "dependency-manifest",
                f"{path} dependency count {manifest.old_count} -> "
                f"{manifest.new_count} in one update",
                file=path, old=str(manifest.old_count),
                new=str(manifest.new_count))

        for kind, value in manifest.redirects:
            add("U004", "Registry Redirect", "MEDIUM",
                "dependency-manifest",
                f"{path} redirects the resolver ({kind}): {value}",
                file=path, redirect=kind, target=value)

        for reason in manifest.unresolved:
            add("W009", "Upstream Manifests Not Examined", "INFO",
                "unverifiable",
                f"{path} is a committed manifest but could not be parsed "
                f"({reason})",
                file=path, manifest=path, reason=reason)

    _integrity_pairs(delta, add)
