"""Extracted from manifests.py: _formats_d."""

from __future__ import annotations
import re
from ..manifest_syntax import (
    ManifestSyntaxError,
    load_json,
    load_yaml,
)
from ._common import Dep, ManifestDoc, _glob_rank, _host, _matches, manifest_format
from ._formats_a import _cargo_config, _cargo_lock, _cargo_toml, _composer_json, _composer_lock, _gemfile, _gemfile_lock, _go_mod, _go_sum, _npm_lock, _npm_package_json, _npmrc, _pipfile, _pnpm_lock, _poetry_lock, _pyproject, _requirements, _toml_lock, _yarn_lock, _yarnrc
from ._formats_b import _conda_env, _conda_meta, _noxfile, _pip_config, _pixi, _pylock, _pypirc, _setup_cfg, _setup_py, _source_dep, _tox_ini, _uv_toml
from ._formats_c import _bun_lock, _cabal, _conan, _cpanfile, _deno_json, _dotnet_project, _fpm_toml, _gemspec, _gleam_toml, _gradle_dsl, _gradle_libs, _julia_manifest, _julia_project, _maven_pom, _mix_exs, _mix_lock, _nuget_config, _opam, _packages_config, _podfile, _pubspec, _pubspec_lock, _r_description, _renv_lock, _shard_lock, _shard_yml, _swift_package, _swift_resolved, _vcpkg

__all__ = ['_BAZEL_DEP_RE', '_BY_NAME', '_CABAL_LOCATION_RE', '_CART_FORGE_RE', '_CART_GIT_RE', '_CLOJURE_COORD_RE', '_CLOJURE_GIT_RE', '_CLOJURE_MVN_MAP_RE', '_CMAKE_URL_RE', '_COORD_CHARS', '_DUNE_DEPS_RE', '_MESON_DEP_RE', '_NIMBLE_RE', '_PARSERS', '_REBAR_DEP_RE', '_ROCK_DEP_RE', '_ZIG_URL_RE', '_bazel', '_cabal_project', '_cartfile', '_clojure', '_cmake', '_coord_before', '_dub', '_dune_project', '_meson', '_nimble', '_package_yaml', '_perl_meta', '_rebar', '_rockspec', '_stack_yaml', '_text_parser_for', '_zig_zon', 'lowered_matches']

_ZIG_URL_RE = re.compile(r"\.url\s*=\s*\"([^\"]+)\"")

_NIMBLE_RE = re.compile(r"requires\s+[\"']([^\"']+)[\"']")

_ROCK_DEP_RE = re.compile(r"[\"']([A-Za-z0-9_.-]+)\s*[><=~]+\s*([0-9][0-9.]*)[\"']")

_CLOJURE_COORD_RE = re.compile(r"\[([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\s+\"([^\"]+)\"\]")

_CLOJURE_GIT_RE = re.compile(r":git/url\s+\"([^\"]+)\"")

_CLOJURE_MVN_MAP_RE = re.compile(r":mvn/version\s+\"([^\"]+)\"")

_COORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")

_DUNE_DEPS_RE = re.compile(r"\(depends((?:\s+[A-Za-z0-9_.-]+)+)\)")

_REBAR_DEP_RE = re.compile(r"\{\s*([a-z0-9_]+)\s*,\s*\"([^\"]+)\"")

_CART_GIT_RE = re.compile(r"\bgit\s+\"([^\"]+)\"")

_CART_FORGE_RE = re.compile(r"\b(?:github|gitlab|bitbucket)\s+\"([^\"/]+/[^\"]+)\"")

_CABAL_LOCATION_RE = re.compile(r"location:\s*(\S+)")

_CMAKE_URL_RE = re.compile(r"\b(?:URL|GIT_REPOSITORY)\s+\"?([^\"\s)]+)\"?")

_MESON_DEP_RE = re.compile(r"dependency\(\s*[\"']([^\"']+)")

_BAZEL_DEP_RE = re.compile(
    r"bazel_dep\(\s*name\s*=\s*\"([^\"]+)\""
    r"(?:\s*,\s*version\s*=\s*\"([^\"]+)\")?")

def _coord_before(text: str, index: int) -> str:
    """The ``group/artifact`` (or Clojure coordinate) ending just before *index*."""
    head = text[:index].rstrip()
    if head.endswith("{"):
        head = head[:-1].rstrip()
    token = head.rsplit(None, 1)[-1] if head else ""
    parts = token.split("/")
    if len(parts) == 2 and all(
            part and set(part) <= _COORD_CHARS for part in parts):
        return token
    return ""

def _zig_zon(text: str) -> ManifestDoc | None:
    deps = [Dep("", None, "git", _host(m.group(1)))
            for m in _ZIG_URL_RE.finditer(text)]
    return ManifestDoc("", "zig", tuple(deps))

def _nimble(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1).split(" ")[0].split(">")[0].strip(), None, "registry", None)
            for m in _NIMBLE_RE.finditer(text)]
    return ManifestDoc("", "nim", tuple(deps))

def _rockspec(text: str) -> ManifestDoc | None:
    deps = [Dep(name, version or None, "registry", None)
            for name, version in _ROCK_DEP_RE.findall(text)]
    return ManifestDoc("", "lua", tuple(deps))

def _clojure(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), m.group(2), "registry", None)
            for m in _CLOJURE_COORD_RE.finditer(text)]
    for m in _CLOJURE_MVN_MAP_RE.finditer(text):
        deps.append(Dep(_coord_before(text, m.start()), m.group(1), "registry", None))
    for m in _CLOJURE_GIT_RE.finditer(text):
        deps.append(Dep(_coord_before(text, m.start()), None, "git", _host(m.group(1))))
    return ManifestDoc("", "clojure", tuple(deps))

def _dune_project(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    for match in _DUNE_DEPS_RE.finditer(text):
        for name in match.group(1).split():
            deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "ocaml", tuple(deps))

def _rebar(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), m.group(2), "registry", None)
            for m in _REBAR_DEP_RE.finditer(text)]
    return ManifestDoc("", "elixir", tuple(deps))

def _cartfile(text: str) -> ManifestDoc | None:
    deps = [Dep("", None, "git", _host(m.group(1)))
            for m in _CART_GIT_RE.finditer(text)]
    deps += [Dep(m.group(1).rsplit("/", 1)[-1], None, "git", "github.com")
             for m in _CART_FORGE_RE.finditer(text)]
    return ManifestDoc("", "swift", tuple(deps))

def _cabal_project(text: str) -> ManifestDoc | None:
    deps = [Dep("", None, "git", _host(m.group(1)))
            for m in _CABAL_LOCATION_RE.finditer(text)]
    return ManifestDoc("", "haskell", tuple(deps))

def _cmake(text: str) -> ManifestDoc | None:
    deps = [Dep("", None, "git", _host(m.group(1)))
            for m in _CMAKE_URL_RE.finditer(text) if "://" in m.group(1)]
    return ManifestDoc("", "cpp", tuple(deps))

def _meson(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), None, "registry", None)
            for m in _MESON_DEP_RE.finditer(text)]
    return ManifestDoc("", "cpp", tuple(deps))

def _bazel(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), m.group(2), "registry", None)
            for m in _BAZEL_DEP_RE.finditer(text)]
    return ManifestDoc("", "bazel", tuple(deps))

def _perl_meta(text: str) -> ManifestDoc | None:
    try:
        data = load_json(text)
    except ManifestSyntaxError:
        data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "perl", unresolved=("not a mapping",))
    deps: list[Dep] = []
    prereqs = data.get("prereqs")
    if isinstance(prereqs, dict):
        for phase in prereqs.values():
            if isinstance(phase, dict):
                for name in (phase.get("requires") or {}):
                    deps.append(Dep(name, None, "registry", None))
    for section in ("requires", "dependencies"):
        table = data.get(section)
        if isinstance(table, dict):
            for name in table:
                deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "perl", tuple(deps))

def _dub(text: str) -> ManifestDoc | None:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "d", unresolved=("not an object",))
    deps: list[Dep] = []
    for name, value in (data.get("dependencies") or {}).items():
        if isinstance(value, str):
            deps.append(Dep(name, value, "registry", None))
        elif isinstance(value, dict):
            deps.extend(_source_dep(name, value)
                        or [Dep(name, None, "registry", None)])
    return ManifestDoc("", "d", tuple(deps))

def _stack_yaml(text: str) -> ManifestDoc | None:
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "haskell", unresolved=("not a mapping",))
    deps: list[Dep] = []
    for entry in data.get("extra-deps", ()) or ():
        if isinstance(entry, str):
            deps.append(Dep(entry.rsplit("-", 1)[0], None, "registry", None))
        elif isinstance(entry, dict):
            name = entry.get("name") or ""
            git = entry.get("git")
            github = entry.get("github")
            if git is None and github is None and entry:
                # `- evil:\n    git: ...` parses as {name: {git: ...}}
                sole_name, spec = next(iter(entry.items()))
                if isinstance(spec, dict):
                    name = name or sole_name
                    git = spec.get("git")
                    github = spec.get("github")
            if git:
                deps.append(Dep(name, None, "git", _host(str(git))))
            elif github:
                deps.append(Dep(name, None, "git", "github.com"))
    return ManifestDoc("", "haskell", tuple(deps))

def _package_yaml(text: str) -> ManifestDoc | None:
    """hpack ``package.yaml``: ``dependencies`` list of names."""
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "haskell", unresolved=("not a mapping",))
    deps: list[Dep] = []
    for value in data.get("dependencies", ()) or ():
        if isinstance(value, str):
            deps.append(Dep(value.split(" ")[0].split(">")[0], None, "registry", None))
        elif isinstance(value, dict):
            for name in value:
                deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "haskell", tuple(deps))

_PARSERS = {
    "cargo": _cargo_toml,        # overridden per-filename below
    "npm": _npm_package_json,
    "pip": _requirements,
    "go": _go_mod,
    "gem": _gemfile,
    "composer": _composer_json,
    "conda": _conda_env,
    "jvm": _maven_pom,
    "dotnet": _dotnet_project,
    "dart": _pubspec,
    "crystal": _shard_yml,
    "cpp": _conan,
    "julia": _julia_project,
}

_BY_NAME = {
    "cargo.lock": _cargo_lock,
    "cargo/config.toml": _cargo_config,
    "cargo/config": _cargo_config,
    ".cargo/config.toml": _cargo_config,
    ".cargo/config": _cargo_config,
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    ".yarnrc.yml": _yarnrc,
    ".npmrc": _npmrc,
    "pyproject.toml": _pyproject,
    "requirements.txt": _requirements,
    "constraints.txt": _requirements,
    "pipfile": _pipfile,
    "pipfile.lock": _pipfile,
    "poetry.lock": _poetry_lock,
    "uv.lock": _toml_lock,
    "pdm.lock": _toml_lock,
    "uv.toml": _uv_toml,
    "pylock.toml": _pylock,
    "pylock.*.toml": _pylock,
    "setup.py": _setup_py,
    "setup.cfg": _setup_cfg,
    "tox.ini": _tox_ini,
    "noxfile.py": _noxfile,
    "environment.yml": _conda_env,
    "environment.yaml": _conda_env,
    "meta.yaml": _conda_meta,
    "pixi.toml": _pixi,
    "pip.conf": _pip_config,
    "pip.ini": _pip_config,
    ".pip/pip.conf": _pip_config,
    ".config/pip/pip.conf": _pip_config,
    ".pypirc": _pypirc,
    "go.sum": _go_sum,
    "go.work.sum": _go_sum,
    "gemfile.lock": _gemfile_lock,
    "*.gemspec": _gemspec,
    "composer.lock": _composer_lock,
    "pom.xml": _maven_pom,
    "*.csproj": _dotnet_project,
    "*.fsproj": _dotnet_project,
    "*.vbproj": _dotnet_project,
    "directory.packages.props": _dotnet_project,
    "packages.config": _packages_config,
    "nuget.config": _nuget_config,
    "pubspec.yaml": _pubspec,
    "pubspec.lock": _pubspec_lock,
    "shard.yml": _shard_yml,
    "shard.lock": _shard_lock,
    "deno.json": _deno_json,
    "deno.jsonc": _deno_json,
    "bun.lock": _bun_lock,
    "project.toml": _julia_project,
    "manifest.toml": _julia_manifest,
    "gradle/libs.versions.toml": _gradle_libs,
    "build.gradle": _gradle_dsl,
    "build.gradle.kts": _gradle_dsl,
    "settings.gradle": _gradle_dsl,
    "settings.gradle.kts": _gradle_dsl,
    "vcpkg.json": _vcpkg,
    "*.cabal": _cabal,
    "*.opam": _opam,
    "mix.exs": _mix_exs,
    "mix.lock": _mix_lock,
    "conanfile.txt": _conan,
    "description": _r_description,
    "renv.lock": _renv_lock,
    "cpanfile": _cpanfile,
    "fpm.toml": _fpm_toml,
    "gleam.toml": _gleam_toml,
    "package.resolved": _swift_resolved,
    "package.swift": _swift_package,
    "podfile": _podfile,
    "build.zig.zon": _zig_zon,
    "dub.json": _dub,
    "*.nimble": _nimble,
    "*.rockspec": _rockspec,
    "deps.edn": _clojure,
    "project.clj": _clojure,
    "dune-project": _dune_project,
    "rebar.config": _rebar,
    "rebar.lock": _rebar,
    "cartfile": _cartfile,
    "cartfile.resolved": _cartfile,
    "cabal.project": _cabal_project,
    "cabal.project.freeze": _cabal_project,
    "cmakelists.txt": _cmake,
    "meson.build": _meson,
    "module.bazel": _bazel,
    "meta.json": _perl_meta,
    "meta.yml": _perl_meta,
    "stack.yaml": _stack_yaml,
    "stack.yaml.lock": _stack_yaml,
    "package.yaml": _package_yaml,
}

def _text_parser_for(path: str, text: str):
    lowered = path.lower()
    base = lowered.rsplit("/", 1)[-1]
    if base in _BY_NAME:
        return _BY_NAME[base]
    best_fn = None
    best_key: tuple[int, int] | None = None
    for name, fn in _BY_NAME.items():
        if not _matches(lowered, base, name):
            continue
        key = _glob_rank(name)
        if best_key is None or key < best_key:
            best_key, best_fn = key, fn
    if best_fn is not None:
        return best_fn
    fmt = manifest_format(path)
    return _PARSERS.get(fmt or "", _requirements)

def lowered_matches(path: str, name: str) -> bool:
    lowered = path.lower()
    base = lowered.rsplit("/", 1)[-1]
    return _matches(lowered, base, name.lower())
