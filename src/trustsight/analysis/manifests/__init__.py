"""U-series: upstream dependency manifests committed in the AUR repository.

TrustSight never fetches what a package declares and never extracts archives
(A2, A8), so an upstream *archive* is a sealed container.  But the manifests
that ship beside a recipe (``Cargo.toml``, ``package.json``,
``requirements.txt``, ``go.mod``, ...) are committed to the repository, which
means the existing tree walk and diff already see them.  This module turns
those bytes into one :class:`ManifestDoc` per file, mirroring the
``RecipeDoc`` contract: parse once, project everywhere, refuse rather than
guess.

It is a pure read: no fetch, no extraction, no new walker.  Discovery is the
existing tree walk and diff file list, filtered by a filename table that
lives in ``patterns.toml`` (configuration, not a code constant).
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from dataclasses import dataclass
from urllib.parse import urlsplit
from ...buckets import canonical_host
from ...tokenizer import split_lines
from ..manifest_syntax import (
    ManifestSyntaxError,
    load_ini,
    load_json,
    load_toml,
    load_xml,
    load_yaml,
)
from ._common import (
    Dep,
    MAX_MANIFEST_BYTES,
    MAX_UPSTREAM_DEP_HOST_BYTES,
    MAX_UPSTREAM_DEP_NAME_BYTES,
    MAX_UPSTREAM_DEP_PAIRS,
    MAX_UPSTREAM_MANIFEST_BYTES,
    MAX_UPSTREAM_MANIFEST_FILES,
    ManifestDoc,
    _CARGO_REPLACE_RE,
    _DEFAULT_REGISTRY_FRAGMENTS,
    _FALLBACK_FILENAMES,
    _FORGE_HOSTS,
    _GIT_FIELD_RE,
    _GIT_URL_RE,
    _LEADING_KEY_RE,
    _PEP508_URL_RE,
    _REGISTRY_FIELD_RE,
    _REGISTRY_KEY_RE,
    _glob_rank,
    _host,
    _is_default_registry,
    _live_text,
    _matches,
    _pep508,
    _pep508_name,
    _registry_host,
    _table,
    _url_source,
    manifest_filenames,
    manifest_format,
    upstream_redirect_signals,
    upstream_source_deps,
    upstream_source_hosts,
)
from ._formats_a import (
    _GEMLOCK_SPEC_RE,
    _GEM_LINE_RE,
    _GEM_SOURCE_RE,
    _GO_BLOCK_RE,
    _GO_REPLACE_RE,
    _GO_REQUIRE_RE,
    _NODE_MODULES_RE,
    _NPMRC_HOST_RE,
    _NPMRC_RE,
    _PIP_OPTION_RE,
    _PLATFORM_PREFIXES,
    _PNPM_NAME_RE,
    _PNPM_URL_RE,
    _YARNRC_RE,
    _YARN_URL_RE,
    _cargo_config,
    _cargo_lock,
    _cargo_toml,
    _composer_json,
    _composer_lock,
    _gemfile,
    _gemfile_lock,
    _go_mod,
    _go_sum,
    _is_go_path,
    _json_deps,
    _json_object,
    _npm_lock,
    _npm_package_json,
    _npmrc,
    _pipfile,
    _pnpm_lock,
    _poetry_dep_tables,
    _poetry_lock,
    _pyproject,
    _requirements,
    _toml_lock,
    _yarn_lock,
    _yarnrc,
)
from ._formats_b import (
    _NOX_INSTALL_RE,
    _SETUP_EXTRAS_RE,
    _SETUP_REQUIRES_RE,
    _SETUP_STR_RE,
    _add_pixi,
    _as_list,
    _conda_dep,
    _conda_env,
    _conda_meta,
    _ini_requirements,
    _noxfile,
    _pip_config,
    _pixi,
    _pixi_channels,
    _pixi_tables,
    _pylock,
    _pypirc,
    _setup_cfg,
    _setup_py,
    _source_dep,
    _tox_ini,
    _uv_toml,
)
from ._formats_c import (
    _CARTFILE_RE,
    _CPANFILE_RE,
    _GEMSPEC_DEP_RE,
    _GRADLE_COORD_RE,
    _MIX_DEP_RE,
    _OPAM_DEP_RE,
    _PODFILE_RE,
    _POD_GIT_RE,
    _R_DESC_FIELDS,
    _R_VERSION_RE,
    _bun_lock,
    _cabal,
    _conan,
    _cpanfile,
    _deno_json,
    _dict_deps,
    _dotnet_project,
    _fpm_toml,
    _gemspec,
    _gleam_toml,
    _gradle_dsl,
    _gradle_libs,
    _julia_manifest,
    _julia_project,
    _localname,
    _maven_pom,
    _mix_exs,
    _mix_lock,
    _nuget_config,
    _opam,
    _packages_config,
    _podfile,
    _pubspec,
    _pubspec_lock,
    _r_description,
    _renv_lock,
    _shard_lock,
    _shard_yml,
    _swift_package,
    _swift_resolved,
    _vcpkg,
    _xml_text,
)
from ._formats_d import (
    _BAZEL_DEP_RE,
    _BY_NAME,
    _CABAL_LOCATION_RE,
    _CART_FORGE_RE,
    _CART_GIT_RE,
    _CLOJURE_COORD_RE,
    _CLOJURE_GIT_RE,
    _CLOJURE_MVN_MAP_RE,
    _CMAKE_URL_RE,
    _COORD_CHARS,
    _DUNE_DEPS_RE,
    _MESON_DEP_RE,
    _NIMBLE_RE,
    _PARSERS,
    _REBAR_DEP_RE,
    _ROCK_DEP_RE,
    _ZIG_URL_RE,
    _bazel,
    _cabal_project,
    _cartfile,
    _clojure,
    _cmake,
    _coord_before,
    _dub,
    _dune_project,
    _meson,
    _nimble,
    _package_yaml,
    _perl_meta,
    _rebar,
    _rockspec,
    _stack_yaml,
    _text_parser_for,
    _zig_zon,
    lowered_matches,
)
from ._parse import (
    parse_manifest_local,
)

def parse_manifest(path: str, text: str):
    """Parse a manifest in the sandboxed worker, never in this process."""
    from ...sandbox.manifest_client import ManifestUnavailable as _Unavailable
    from ...sandbox.manifest_client import parse_manifest as _remote

    try:
        payload = _remote(path, text)
    except _Unavailable as exc:
        from ..manifest_syntax import ManifestSyntaxError
        raise ManifestSyntaxError("manifest sandbox unavailable") from exc
    if payload is None:
        return None
    from ._common import Dep, ManifestDoc

    deps = tuple(Dep(
        name=item.get("name", ""),
        constraint=item.get("constraint"),
        source_kind=item.get("source_kind", "unknown"),
        remote=item.get("remote"),
        origin=item.get("origin"),
        integrity=item.get("integrity"),
    ) for item in payload.get("dependencies", ()))
    return ManifestDoc(
        path=payload.get("path", path),
        format=payload.get("format", ""),
        dependencies=deps,
        unresolved=tuple(payload.get("unresolved", ())),
        redirects=tuple(tuple(pair) for pair in payload.get("redirects", ())),
    )


__all__ = [
    "Dep",
    "ManifestDoc",
    "manifest_format",
    "manifest_filenames",
    "parse_manifest",
    "upstream_redirect_signals",
    "upstream_source_deps",
    "upstream_source_hosts",
    "MAX_MANIFEST_BYTES",
    "MAX_UPSTREAM_DEP_HOST_BYTES",
    "MAX_UPSTREAM_DEP_NAME_BYTES",
    "MAX_UPSTREAM_DEP_PAIRS",
    "MAX_UPSTREAM_MANIFEST_BYTES",
    "MAX_UPSTREAM_MANIFEST_FILES",
    "tree_remote_dependency_pairs",
]


def tree_remote_dependency_pairs(manifest_texts):
    """``(pairs, incomplete)`` for committed manifests in a snapshot tree.

    *manifest_texts* is ``[(path, text)]`` read from the AUR snapshot
    tarball, or ``None`` when the fetch had no tree at all.  Only
    dependencies carrying a remote host are returned: a default-registry
    version bump is not the shared-upstream-dependency shape G004 joins, and
    recording every registry name would make the feed churn with ordinary
    dependency updates.

    A refused or over-cap manifest makes the whole answer *incomplete*
    rather than contributing a partial set.  The caller then preserves the
    previous dependency snapshot and records a coverage gap: a truncated
    manifest parsed as if whole is exactly the silent skip A4/B2 forbid.
    """
    if manifest_texts is None:
        return set(), True
    pairs: set[tuple[str, str]] = set()
    incomplete = False
    for path, text in manifest_texts:
        doc = parse_manifest(path, text)
        if doc is None:
            continue
        if doc.unresolved:
            incomplete = True
            continue
        for dep in doc.dependencies:
            if not dep.name or not dep.remote:
                continue
            name = str(dep.name)
            host = str(dep.remote)
            if (len(name.encode("utf-8", "replace")) > MAX_UPSTREAM_DEP_NAME_BYTES
                    or len(host.encode("utf-8", "replace")) > MAX_UPSTREAM_DEP_HOST_BYTES):
                incomplete = True
                continue
            pairs.add((name, host))
            if len(pairs) > MAX_UPSTREAM_DEP_PAIRS:
                return set(), True
    return pairs, incomplete
