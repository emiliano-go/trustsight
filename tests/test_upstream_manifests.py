"""The U-series: committed upstream dependency manifests.

The layer reads only repository bytes (the tree walk and the diff), so the
tests pin one parser per format, the refusals, and that a manifest change
reaches the report as the right U rule.
"""

from __future__ import annotations

import pytest

from trustsight.analysis.manifests import (
    MAX_MANIFEST_BYTES,
    manifest_format,
    parse_manifest,
)
from trustsight.analysis.pipeline import scan_diff
from trustsight.changes import change_delta

CARGO = """[package]
name = "x"
version = "0.1.0"
[dependencies]
serde = "1.0"
evil = { git = "https://evil.example/x.git", branch = "main" }
local = { path = "../local" }
"""


def _ids(fact) -> set[str]:
    return {entry.rule_id for entry in fact.score_breakdown}


@pytest.mark.parametrize("path, expected", [
    ("Cargo.toml", "cargo"),
    ("package.json", "npm"),
    ("requirements.txt", "pip"),
    ("go.mod", "go"),
    ("Gemfile", "gem"),
    ("composer.json", "composer"),
    (".cargo/config.toml", "cargo"),
])
def test_a_known_manifest_is_recognised(path, expected):
    assert manifest_format(path) == expected


def test_a_non_manifest_is_not_recognised():
    assert manifest_format("PKGBUILD") is None
    assert manifest_format("src/main.rs") is None


def test_cargo_git_and_path_dependencies():
    doc = parse_manifest("Cargo.toml", CARGO)
    by_name = {d.name: d for d in doc.dependencies}
    assert by_name["serde"].source_kind == "registry"
    assert by_name["evil"].source_kind == "git"
    assert by_name["evil"].remote == "evil.example"
    assert by_name["local"].source_kind == "path"


def test_requirements_index_redirect_and_git():
    text = ("requests==2.0\n"
            "--index-url https://evil.example/simple\n"
            "git+https://evil.example/x.git#egg=evil\n")
    doc = parse_manifest("requirements.txt", text)
    names = {d.name for d in doc.dependencies}
    assert {"requests", "evil"} <= names
    assert ("pip-index-url", "evil.example") in doc.redirects


def test_package_json_git_dependency():
    doc = parse_manifest("package.json",
                         '{"dependencies": {"evil": "git+https://evil.example/x.git"}}')
    assert doc.dependencies[0].source_kind == "git"
    assert doc.dependencies[0].remote == "evil.example"


def test_go_mod_require_and_block():
    text = ("module x\n"
            "require github.com/foo/bar v1.2.3\n"
            "require (\n  github.com/baz/qux v0.1.0\n)\n")
    names = {d.name for d in parse_manifest("go.mod", text).dependencies}
    assert names == {"github.com/foo/bar", "github.com/baz/qux"}


def test_malformed_and_oversized_manifests_are_refused_not_raised():
    assert parse_manifest("Cargo.toml", "[dependencies\nbroken").unresolved
    assert parse_manifest("package.json", "{" * 10).unresolved
    big = "x\n" * (MAX_MANIFEST_BYTES // 2 + 10)
    assert parse_manifest("requirements.txt", big).unresolved
    deep_json = "[" * 2000 + "]" * 2000
    assert parse_manifest("package.json", deep_json).unresolved
    deep_toml = "x = " + "[" * 2000 + "]" * 2000
    assert parse_manifest("Cargo.toml", deep_toml).unresolved


def test_u003_emits_and_joins_hosts_gained():
    diff = ("--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1,1 +1,2 @@\n"
            " [dependencies]\n"
            '+serde = { git = "https://evil.example/serde.git" }\n')
    fact = scan_diff(diff, package_name="p")
    assert "U003" in _ids(fact)
    assert "evil.example" in change_delta(diff).hosts_gained


def test_u001_u002_ledger_on_manifest_add():
    diff = ("--- /dev/null\n+++ b/requirements.txt\n@@ -0,0 +1,1 @@\n"
            "+evil==1.0\n")
    fact = scan_diff(diff, package_name="p")
    assert {"U001", "U002"} <= _ids(fact)
    from trustsight.reporting import evaluate_fact, report_body

    body = report_body(evaluate_fact(fact))
    visible = {finding["rule_id"] for finding in body["findings"]}
    assert {"U001", "U002", "U006"} <= visible


def test_u004_registry_redirect():
    diff = ("--- /dev/null\n+++ b/.npmrc\n@@ -0,0 +1,1 @@\n"
            "+registry=https://evil.example/npm\n")
    fact = scan_diff(diff, package_name="p")
    assert "U004" in _ids(fact)
    assert sum(e.rule_id == "U004" for e in fact.score_breakdown) == 1


def test_u004_survives_a_cargo_section_outside_the_hunk():
    diff = ("--- a/.cargo/config.toml\n+++ b/.cargo/config.toml\n"
            "@@ -5,3 +5,4 @@\n a = \"1\"\n b = \"2\"\n c = \"3\"\n"
            '+replace-with = "evil"\n')
    fact = scan_diff(diff, package_name="p")
    assert "U004" in _ids(fact)


def test_w009_refusal_is_named():
    diff = ("--- /dev/null\n+++ b/Cargo.toml\n@@ -0,0 +1,2 @@\n"
            "+[dependencies\n+broken =\n")
    fact = scan_diff(diff, package_name="p")
    assert "W009" in _ids(fact)


def test_u005_surface_jump():
    old = "\n".join(f"d{i} = \"1\"" for i in range(3))
    new = "\n".join(f"d{i} = \"1\"" for i in range(12))
    diff = ("--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1,3 +1,12 @@\n"
            " [dependencies]\n"
            + "".join(f"-{line}\n" for line in old.splitlines())
            + "".join(f"+{line}\n" for line in new.splitlines()))
    fact = scan_diff(diff, package_name="p")
    assert "U005" in _ids(fact)


def test_git_shorthands_name_a_host():
    npm = parse_manifest("package.json", (
        '{"dependencies": {"gh": "github:u/r", "loose": "u/r",'
        ' "gl": "gitlab:u/r", "plain": "1.2.3"}}'))
    by = {d.name: d for d in npm.dependencies}
    assert (by["gh"].source_kind, by["gh"].remote) == ("git", "github.com")
    assert (by["loose"].source_kind, by["loose"].remote) == ("git", "github.com")
    assert (by["gl"].source_kind, by["gl"].remote) == ("git", "gitlab.com")
    assert by["plain"].source_kind == "registry"
    gem = parse_manifest("Gemfile", 'gem "x", github: "u/r"\n')
    assert (gem.dependencies[0].source_kind, gem.dependencies[0].remote) == ("git", "github.com")


def test_host_spellings_without_a_scheme_are_read():
    variants = {
        'foo = { git = "//evil.example/x" }': "evil.example",
        'foo = { git = "evil.example/x" }': "evil.example",
        'foo = { git = "git@evil.example:x" }': "evil.example",
        'foo = { git = "git+https://evil.example/x" }': "evil.example",
    }
    for line, host in variants.items():
        doc = parse_manifest("Cargo.toml",
                             f"[dependencies]\n{line}\n")
        assert doc.dependencies[0].remote == host, line


def test_requirements_editable_and_find_links_and_continuation():
    text = ("--find-links https://evil.example/wheels\n"
            "-e git+https://evil.example/x.git#egg=evil\n"
            "requests \\\n    ==2.0\n")
    doc = parse_manifest("requirements.txt", text)
    names = {d.name for d in doc.dependencies}
    assert "evil" in names and "requests" in names
    assert ("pip-find-links", "evil.example") in doc.redirects


def test_default_registries_are_not_redirects():
    assert parse_manifest(".npmrc", "registry=https://registry.npmjs.org/\n").redirects == ()
    assert parse_manifest(
        "requirements.txt", "--index-url https://pypi.org/simple\n").redirects == ()
    assert parse_manifest(
        "Cargo.lock",
        '[[package]]\nname = "x"\nversion = "1"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
    ).dependencies[0].remote is None


def test_official_registry_text_cannot_hide_in_a_host_or_path():
    for url in (
        "https://registry.npmjs.org.evil.example/npm",
        "https://evil.example/registry.npmjs.org/",
        "https://evil.example/pypi.org/simple",
    ):
        assert parse_manifest(".npmrc", f"registry={url}\n").redirects


def test_npm_lock_preserves_real_and_scoped_package_names():
    doc = parse_manifest("package-lock.json", (
        '{"packages": {'
        '"node_modules/foo": {"version": "1"},'
        '"node_modules/@scope/bar": {"version": "2"},'
        '"node_modules/a/node_modules/b": {"version": "3"}}}'
    ))
    assert [d.name for d in doc.dependencies] == ["foo", "@scope/bar", "b"]


def test_yarn_preserves_the_npm_scope():
    doc = parse_manifest("yarn.lock", (
        '"@scope/foo@https://evil.example/foo.git":\n'
        '  version "1.0.0"\n'
        '  resolution: "@scope/foo@https://evil.example/foo.git"\n'))
    assert doc.dependencies[0].name == "@scope/foo"


def test_generic_registry_fallback_requires_a_locator():
    diff = ("--- /dev/null\n+++ b/Cargo.toml\n@@ -0,0 +1,2 @@\n"
            '+[dependencies]\n+registry = "1.0"\n')
    assert "U004" not in _ids(scan_diff(diff, package_name="p"))


def test_u011_detects_same_host_origin_changes_not_version_moves():
    diff = ("--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1,2 +1,2 @@\n"
            " [dependencies]\n"
            '-foo = { git = "https://github.com/good/foo", tag = "v1" }\n'
            '+foo = { git = "https://github.com/evil/foo", tag = "v1" }\n')
    assert "U011" in _ids(scan_diff(diff, package_name="p"))
    version_only = diff.replace("github.com/evil/foo", "github.com/good/foo") \
        .replace('tag = "v1"', 'tag = "v2"', 1)
    assert "U011" not in _ids(scan_diff(version_only, package_name="p"))


def test_u011_detects_direct_reference_to_registry_transition():
    diff = ("--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1,1 +1,1 @@\n"
            '-foo @ git+https://github.com/good/foo\n+foo==1.0\n')
    assert "U011" in _ids(scan_diff(diff, package_name="p"))


def test_removed_manifest_and_lockfile_are_visible():
    diff = ("--- a/package-lock.json\n+++ /dev/null\n@@ -1,1 +0,0 @@\n"
            '-{"packages": {"node_modules/foo": {"version": "1",'
            ' "integrity": "sha512-abc"}}}\n')
    ids = _ids(scan_diff(diff, package_name="p"))
    assert {"U001", "U012"} <= ids


def test_u012_detects_integrity_removal_not_replacement():
    old = '{"packages": {"node_modules/foo": {"version": "1", "integrity": "sha512-old"}}}'
    new = '{"packages": {"node_modules/foo": {"version": "1"}}}'
    diff = f"--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1,1 +1,1 @@\n-{old}\n+{new}\n"
    assert "U012" in _ids(scan_diff(diff, package_name="p"))
    replaced = diff.replace('"version": "1"}', '"version": "1", "integrity": "sha512-new"}')
    assert "U012" not in _ids(scan_diff(replaced, package_name="p"))


def test_u012_detects_cargo_checksum_removal():
    diff = (
        "--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,3 +1,2 @@\n"
        '-[[package]]\n-name = "foo"\n-version = "1"\n-checksum = "abc"\n'
        '+[[package]]\n+name = "foo"\n+version = "1"\n'
    )
    assert "U012" in _ids(scan_diff(diff, package_name="p"))


def test_u006_pairs_lockfiles_by_workspace_and_requirements_glob():
    sibling = (
        "--- a/frontend/package.json\n+++ b/frontend/package.json\n@@ -1,1 +1,1 @@\n"
        '-{"dependencies": {"a": "1"}}\n+{"dependencies": {"a": "2"}}\n'
        "--- /dev/null\n+++ b/backend/yarn.lock\n@@ -0,0 +1,1 @@\n+foo: 1\n"
    )
    assert "U006" in _ids(scan_diff(sibling, package_name="p"))
    root_lock = sibling.replace("backend/yarn.lock", "yarn.lock")
    assert "U006" not in _ids(scan_diff(root_lock, package_name="p"))
    requirements = (
        "--- a/requirements-dev.txt\n+++ b/requirements-dev.txt\n"
        "@@ -1,1 +1,1 @@\n-a==1\n+a==2\n"
    )
    assert "U006" in _ids(scan_diff(requirements, package_name="p"))


def test_a_custom_cargo_registry_is_a_remote():
    doc = parse_manifest("Cargo.lock", (
        '[[package]]\nname = "x"\nversion = "1"\n'
        'source = "registry+https://evil.example/index"\n'))
    assert doc.dependencies[0].remote == "evil.example"
    toml = parse_manifest(
        "Cargo.toml",
        '[dependencies]\nfoo = { version = "1", registry = "https://evil.example/i" }\n')
    assert toml.dependencies[0].remote == "evil.example"


def test_uv_source_git_dependency():
    doc = parse_manifest("pyproject.toml", (
        "[tool.uv.sources]\n"
        'evil = { git = "https://evil.example/x.git" }\n'))
    assert (doc.dependencies[0].source_kind, doc.dependencies[0].remote) == (
        "git", "evil.example")


def test_a_bom_and_crlf_do_not_defeat_parsing():
    doc = parse_manifest("package.json",
                         '\ufeff{"dependencies": {"x": "1.0"}}\r\n')
    assert [d.name for d in doc.dependencies] == ["x"]
    cargo = parse_manifest("Cargo.toml",
                           '\ufeff[dependencies]\r\nx = "1"\r\n')
    assert [d.name for d in cargo.dependencies] == ["x"]


def test_cargo_patch_and_replace_reach_a_git_source():
    text = ("[patch.crates-io]\n"
            'foo = { git = "https://evil.example/foo" }\n'
            "[replace]\n"
            '"bar:1.0" = { path = "../bar" }\n')
    by = {d.name: d for d in parse_manifest("Cargo.toml", text).dependencies}
    assert by["foo"].source_kind == "git"
    assert by["foo"].remote == "evil.example"


def test_cargo_config_registries_and_default():
    text = ('[registries.evil]\nindex = "sparse+https://evil.example/i/"\n'
            '[registry]\ndefault = "evil"\n')
    kinds = dict(parse_manifest(".cargo/config.toml", text).redirects)
    assert kinds["cargo-registries"] == "evil.example"
    assert kinds["cargo-default-registry"] == "evil"


def test_npm_overrides_and_pep735_groups():
    npm = parse_manifest("package.json", (
        '{"overrides": {"foo": "git+https://evil.example/foo.git"}}'))
    assert npm.dependencies[0].remote == "evil.example"
    groups = parse_manifest("pyproject.toml", (
        '[dependency-groups]\ndev = ["evil @ git+https://evil.example/x.git"]\n'))
    assert groups.dependencies[0].source_kind == "git"


def test_lock_line_formats_reach_git_hosts():
    yarn = parse_manifest("yarn.lock", (
        '"foo@https://evil.example/foo.git":\n'
        '  version "1.0.0"\n'
        '  resolution: "foo@https://evil.example/foo.git"\n'))
    assert yarn.dependencies and yarn.dependencies[0].remote == "evil.example"
    pnpm = parse_manifest("pnpm-lock.yaml", (
        "  /evil@https://evil.example/x.git:\n"
        "    resolution: {tarball: https://evil.example/x.tgz}\n"))
    assert pnpm.dependencies and pnpm.dependencies[0].remote == "evil.example"
    plain = parse_manifest("pnpm-lock.yaml", (
        "  /foo@1.0.0:\n"
        "    resolution: {tarball: https://registry.npmjs.org/foo/-/foo-1.0.0.tgz}\n"))
    assert plain.dependencies == ()


def test_pipfile_lock_source_redirect():
    doc = parse_manifest("Pipfile.lock", (
        '{"_meta": {"sources": [{"url": "https://evil.example/simple"}]},'
        ' "default": {}}'))
    assert ("pipfile-source", "evil.example") in doc.redirects


def test_u003_fires_when_a_dependency_host_is_swapped_in_place():
    diff = ("--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1,2 +1,2 @@\n"
            " [dependencies]\n"
            '-serde = { git = "https://github.com/serde-rs/serde" }\n'
            '+serde = { git = "https://evil.example/serde" }\n')
    fact = scan_diff(diff, package_name="p")
    assert "U003" in _ids(fact)


def test_u003_survives_a_hunk_without_its_section_header():
    diff = ("--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -20,4 +20,5 @@\n"
            ' line1 = "1"\n line2 = "2"\n line3 = "3"\n'
            '+evil = { git = "https://evil.example/x.git" }\n'
            ' line4 = "4"\n')
    fact = scan_diff(diff, package_name="p")
    assert "U003" in _ids(fact)


def test_u003_survives_a_json_hunk_fragment_without_a_false_refusal():
    diff = ("--- a/package.json\n+++ b/package.json\n@@ -20,4 +20,5 @@\n"
            '     "a": "1.0",\n     "b": "1.0",\n     "c": "1.0",\n'
            '+    "evil": "git+https://evil.example/x.git",\n'
            '     "d": "1.0"\n')
    fact = scan_diff(diff, package_name="p")
    assert "U003" in _ids(fact)
    assert "W009" not in _ids(fact)


def test_a_homepage_or_repository_url_is_not_a_dependency_source():
    diff = ("--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -5,3 +5,5 @@\n"
            ' name = "x"\n version = "1.0"\n edition = "2021"\n'
            '+homepage = "https://example.org"\n'
            '+repository = "https://example.org/repo"\n')
    fact = scan_diff(diff, package_name="p")
    assert not ({"U002", "U003"} & _ids(fact))


def test_a_default_registry_lockfile_is_not_a_new_remote():
    doc = parse_manifest("package-lock.json", (
        '{"packages": {"": {}, "node_modules/foo": {'
        '"version": "1.0", "resolved": '
        '"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"}}}'))
    assert [d.source_kind for d in doc.dependencies] == ["registry"]
    diff = ("--- /dev/null\n+++ b/package-lock.json\n@@ -0,0 +1,1 @@\n"
            '+{"packages": {"node_modules/foo": {"version": "1.0",'
            ' "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"}}}\n')
    assert "U003" not in _ids(scan_diff(diff, package_name="p"))


def test_a_non_default_lockfile_registry_is_a_remote():
    doc = parse_manifest("package-lock.json", (
        '{"packages": {"node_modules/foo": {'
        '"version": "1.0", "resolved": "https://evil.example/foo-1.0.0.tgz"}}}'))
    assert doc.dependencies[0].remote == "evil.example"


def test_uv_and_pdm_locks_reach_git_sources():
    for name in ("uv.lock", "pdm.lock"):
        doc = parse_manifest(name, (
            '[[package]]\nname = "evil"\nversion = "1.0"\n'
            'source = { git = "https://evil.example/x#main" }\n'
            '[[package]]\nname = "pd"\nversion = "2.0"\n'
            'git = "https://evil.example/pd.git"\n'))
        assert {d.remote for d in doc.dependencies} == {"evil.example"}


def test_poetry_legacy_custom_registry_is_a_remote():
    doc = parse_manifest("poetry.lock", (
        '[[package]]\nname = "foo"\nversion = "1.0"\n'
        '[package.source]\n'
        'type = "legacy"\nurl = "https://evil.example/simple"\n'))
    assert doc.dependencies[0].remote == "evil.example"


def test_pip_shorthands_and_includes_and_file_urls():
    doc = parse_manifest("requirements.txt", (
        "-i https://evil.example/simple\n"
        "-r https://evil.example/more.txt\n"
        "evil @ file:///srv/evil\n"))
    kinds = {r[0] for r in doc.redirects}
    assert {"pip-index-url", "pip-requirements-url"} <= kinds
    by = {d.name: d for d in doc.dependencies}
    assert by["evil"].source_kind == "path"


def test_npmrc_auth_host_and_yarnrc_registry():
    auth = parse_manifest(".npmrc", "//evil.example/:_authToken=SECRET\n")
    assert ("npm-registry-auth", "evil.example") in auth.redirects
    default = parse_manifest(".npmrc", "//registry.npmjs.org/:_authToken=SECRET\n")
    assert default.redirects == ()
    yarn = parse_manifest(".yarnrc.yml", 'npmRegistryServer: "https://evil.example/npm"\n')
    assert ("yarn-registry", "evil.example") in yarn.redirects


def test_go_replace_absolute_path_is_a_path():
    doc = parse_manifest("go.mod", (
        "module x\nrequire github.com/foo/bar v1.2.3\n"
        "replace github.com/foo/bar => /srv/local\n"))
    assert doc.dependencies[0].source_kind == "path"


def test_a_commented_source_fetches_nothing():
    from trustsight.analysis.manifests import upstream_source_hosts

    assert upstream_source_hosts(
        '# evil = { git = "https://evil.example/x" }') == set()
    assert upstream_source_hosts(
        '// evil = { git = "https://evil.example/x" }') == set()
    doc = parse_manifest("Cargo.toml",
                         '# evil = { git = "https://evil.example/x" }\n')
    assert doc.dependencies == ()


def test_a_tight_pep508_direct_reference_is_a_git_source():
    by = {d.name: d for d in parse_manifest(
        "requirements.txt", "evil@git+https://evil.example/x.git\n").dependencies}
    assert (by["evil"].source_kind, by["evil"].remote) == ("git", "evil.example")


def test_host_spelling_is_canonical_before_novelty():
    from trustsight.analysis.manifests import upstream_source_hosts

    assert upstream_source_hosts(
        'evil = { git = "https://EVIL.EXAMPLE.:443/x" }') == {"evil.example"}
    assert upstream_source_hosts(
        'evil = { git = "https://user:pw@evil.example/x" }') == {"evil.example"}


@pytest.mark.parametrize("path, pattern", [
    ("requirements-dev.txt", "pip"),
    ("requirements/base.txt", "pip"),
    ("dev-requirements.txt", "pip"),
    ("constraints-py312.txt", "pip"),
    ("pylock.toml", "pip"),
    ("pylock.ci.toml", "pip"),
    ("environment.yml", "conda"),
    ("pixi.toml", "conda"),
    ("Cargo.toml", "cargo"),
])
def test_glob_and_specific_matching(path, pattern):
    from trustsight.analysis.manifests import manifest_format

    assert manifest_format(path) == pattern


def test_pylock_reaches_git_and_archive_sources():
    doc = parse_manifest("pylock.toml", (
        'lock-version = "1.0"\ncreated-by = "uv"\n'
        '[[packages]]\nname = "evil"\nversion = "1.0"\n'
        '[packages.vcs]\n'
        'type = "git"\nurl = "https://evil.example/x"\ncommit-id = "abc"\n'
        '[[packages]]\nname = "arc"\nversion = "2.0"\n'
        '[packages.archive]\n'
        'url = "https://evil.example/arc.tar.gz"\n'
        '[packages.archive.hashes]\nsha256 = "00"\n'))
    by = {d.name: d for d in doc.dependencies}
    assert by["evil"].remote == "evil.example"
    assert by["arc"].remote == "evil.example"
    spec = parse_manifest("pylock.dist.toml",
                          '[[packages]]\nname = "a"\n[packages.directory]\npath = "."\n')
    assert spec.dependencies[0].source_kind == "path"


def test_uv_toml_index_and_source_redirects():
    doc = parse_manifest("uv.toml", (
        '[[index]]\nurl = "https://evil.example/simple"\n'
        '[pip]\nindex-url = "https://evil.example/pip"\n'
        '[sources]\nev = { git = "https://evil.example/ev" }\n'))
    assert doc.dependencies[0].remote == "evil.example"
    targets = {value for _kind, value in doc.redirects}
    assert "evil.example" in targets


def test_conda_environment_and_meta():
    env = parse_manifest("environment.yml", (
        "channels:\n  - conda-forge\n  - https://evil.example/channel\n"
        "dependencies:\n  - numpy=1.26\n  - pip:\n"
        "      - evil @ git+https://evil.example/x.git\n"))
    names = {d.name for d in env.dependencies}
    assert "numpy" in names and "evil" in names
    assert ("conda-channel", "evil.example") in env.redirects
    meta = parse_manifest("meta.yaml", (
        "package:\n  name: x\nrequirements:\n  host:\n    - python\n"
        "  run:\n    - numpy >=1.0\n"))
    assert {d.name for d in meta.dependencies} == {"python", "numpy"}


def test_pixi_manifest_dependencies_and_channels():
    doc = parse_manifest("pixi.toml", (
        "[workspace]\nchannels = [\"conda-forge\", \"https://evil.example/c\"]\n"
        "[dependencies]\npython = \">=3.12\"\n"
        "[pypi-dependencies]\nev = { git = \"https://evil.example/ev\" }\n"))
    names = {d.name for d in doc.dependencies}
    assert "python" in names and "ev" in names
    assert ("pixi-channel", "evil.example") in doc.redirects


def test_setup_cfg_tox_and_nox():
    cfg = parse_manifest("setup.cfg", (
        "[options]\ninstall_requires =\n    requests>=2\n    evil @ git+https://evil.example/x\n"
        "[options.extras_require]\ndev =\n    pytest\n"))
    assert {"requests", "evil", "pytest"} <= {d.name for d in cfg.dependencies}
    tox = parse_manifest("tox.ini", "[testenv]\ndeps =\n    pytest\n    coverage\n")
    assert {"pytest", "coverage"} <= {d.name for d in tox.dependencies}
    nox = parse_manifest("noxfile.py", "def t(s):\n    s.install('pytest', 'coverage')\n")
    assert {"pytest", "coverage"} <= {d.name for d in nox.dependencies}


def test_setup_py_and_pip_config():
    setup = parse_manifest("setup.py", (
        "setup(name='x', install_requires=['requests>=2', 'evil'],"
        " extras_require={'dev': ['pytest']})\n"))
    assert {"requests", "evil", "pytest"} <= {d.name for d in setup.dependencies}
    conf = parse_manifest("pip.conf", "[global]\nindex-url = https://evil.example/simple\n")
    assert ("pip-index-url", "evil.example") in conf.redirects


def test_pyproject_tool_tables_are_read():
    doc = parse_manifest("pyproject.toml", (
        "[project]\nname = 'x'\nversion = '1'\n"
        "[tool.uv]\ndev-dependencies = ['pytest']\n"
        "[tool.uv.sources]\nev = { git = 'https://evil.example/ev' }\n"
        "[tool.hatch.envs.test]\ndependencies = ['coverage']\n"
        "[tool.pdm.dev-dependencies]\nlint = ['ruff']\n"))
    names = {d.name for d in doc.dependencies}
    assert {"pytest", "ev", "coverage", "ruff"} <= names
    by = {d.name: d for d in doc.dependencies}
    assert by["ev"].remote == "evil.example"


def test_u006_fires_when_a_lockfile_is_absent():
    alone = ("--- a/go.mod\n+++ b/go.mod\n@@ -1,1 +1,2 @@\n"
             " module x\n+require github.com/a/b v1.0.0\n")
    ids = _ids(scan_diff(alone, package_name="p"))
    assert "U006" in ids and "U003" not in ids
    paired = ("--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1,1 +1,2 @@\n"
              " [dependencies]\n+serde = \"1\"\n"
              "--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1,1 +1,2 @@\n"
              " x\n+[[package]]\n")
    assert "U006" not in _ids(scan_diff(paired, package_name="p"))


def test_tree_pairs_keep_remote_dependencies_only():
    from trustsight.analysis.manifests import tree_remote_dependency_pairs

    pairs, incomplete = tree_remote_dependency_pairs([
        ("Cargo.toml", CARGO),
    ])
    assert (("evil", "evil.example")) in pairs
    assert all(name != "serde" for name, _ in pairs)
    assert not incomplete


def test_tree_pairs_report_an_unreadable_manifest_as_incomplete():
    from trustsight.analysis.manifests import tree_remote_dependency_pairs

    pairs, incomplete = tree_remote_dependency_pairs([
        ("Cargo.toml", CARGO),
        ("package.json", "{"),
    ])
    assert pairs == {("evil", "evil.example")}
    assert incomplete


def test_tree_pairs_refuse_rather_than_truncate_at_the_pair_cap(monkeypatch):
    from trustsight.analysis import manifests as m

    monkeypatch.setattr(m, "MAX_UPSTREAM_DEP_PAIRS", 1)
    text = "\n".join(
        f'x{i} = {{ git = "https://h{i}.example/x.git" }}'
        for i in range(3)
    )
    pairs, incomplete = m.tree_remote_dependency_pairs([
        ("Cargo.toml", "[dependencies]\n" + text + "\n"),
    ])
    assert pairs == set()
    assert incomplete


def _tar_with_files(files):
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, payload in files:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r")


def test_snapshot_reads_manifest_text_whole_and_keeps_heads_short():
    from trustsight.full_aur.fetch import _snapshot_manifest

    heads, texts, complete = _snapshot_manifest(_tar_with_files([
        ("demo/PKGBUILD", b"pkgname=demo\n" * 20),
        ("demo/Cargo.toml", CARGO.encode()),
    ]))
    assert complete
    assert dict(texts)["demo/Cargo.toml"] == CARGO
    head = dict(heads)["demo/Cargo.toml"]
    assert len(head) <= 64
    assert len(dict(heads)["demo/PKGBUILD"]) <= 64


def test_snapshot_refuses_an_oversize_manifest_and_flags_incomplete(monkeypatch):
    from trustsight.analysis import manifests
    from trustsight.full_aur.fetch import _snapshot_manifest

    monkeypatch.setattr(manifests, "MAX_UPSTREAM_MANIFEST_BYTES", 8)
    heads, texts, complete = _snapshot_manifest(
        _tar_with_files([("demo/Cargo.toml", CARGO.encode())]))
    assert not complete
    assert texts == []
    assert dict(heads)["demo/Cargo.toml"]
