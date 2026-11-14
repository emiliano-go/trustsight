"""Shape predicates are data, so they get synthetic metadata/tree tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import corpus_select as sel  # noqa: E402


def _pkg(name="demo", description="", keywords=(), **fields):
    return {
        "Name": name, "Description": description,
        "Keywords": list(keywords), "URL": "", **fields,
    }


def test_existing_strata_keep_their_metadata_shapes():
    assert sel.metadata_match(_pkg("foo-bin"), "bin_repack")
    assert not sel.metadata_match(_pkg("foo-bin-git"), "bin_repack")
    assert sel.metadata_match(_pkg("foo-git"), "vcs_git")
    assert sel.metadata_match(_pkg("python-foo"), "lang_ecosystem")
    assert sel.metadata_match(_pkg("ttf-foo"), "data_fonts")
    assert sel.metadata_match(_pkg("foo-dkms"), "dkms_kernel")
    assert sel.metadata_match(_pkg("foo", "autotools build"), "autotools")
    assert sel.metadata_match(_pkg("foo", "Electron app"), "large_electron")


def test_dependency_heavy_counts_every_declared_surface():
    pkg = _pkg(depends=["a", "b"], makedepends=["c"], checkdepends=["d"])
    assert sel.dependency_count(pkg) == 4
    assert not sel.metadata_match(pkg, "dependency_heavy")
    pkg["optdepends"] = [f"o{i}" for i in range(11)]
    assert sel.dependency_count(pkg) == 15
    assert sel.metadata_match(pkg, "dependency_heavy")


def test_persist_surface_reads_the_tree_not_only_the_description():
    pkg = _pkg("demo")
    assert not sel.metadata_match(pkg, "persist_surface")
    assert sel.tree_match(pkg, "persist_surface",
                          paths=["usr/lib/systemd/system/demo.service"])
    assert sel.tree_match(pkg, "persist_surface",
                          paths=["usr/lib/tmpfiles.d/demo.conf"])
    assert not sel.tree_match(pkg, "persist_surface",
                              paths=["usr/bin/demo"])


def test_signed_sources_accepts_validpgpkeys_or_detached_signature():
    pkg = _pkg("demo")
    assert sel.tree_match(pkg, "signed_sources",
                          pkgbuild="validpgpkeys=('ABCD')")
    assert sel.tree_match(pkg, "signed_sources",
                          pkgbuild="source=('demo.tar.gz' 'demo.tar.gz.asc')")
    assert not sel.tree_match(pkg, "signed_sources",
                              pkgbuild="source=('demo.tar.gz')")


def test_vcs_other_is_not_fooled_by_a_plain_git_source():
    pkg = _pkg("demo")
    assert not sel.tree_match(pkg, "vcs_other",
                              pkgbuild="source=('git+https://example/x.git')")
    assert sel.tree_match(pkg, "vcs_other",
                          pkgbuild="source=('hg+https://example/x')")
    assert sel.tree_match(pkg, "vcs_other",
                          pkgbuild="source=('svn://example/x')")


def test_lang_deep_reads_vendored_and_lockfile_shapes():
    pkg = _pkg("demo")
    assert sel.tree_match(pkg, "lang_deep",
                          paths=["vendor/foo/Cargo.toml", ".cargo/config.toml"])
    assert sel.tree_match(pkg, "lang_deep", paths=["go.mod"])
    assert not sel.tree_match(pkg, "lang_deep", paths=["src/main.rs"])


def test_runtime_carriers_need_a_unit_or_script_carrier():
    pkg = _pkg("demo", "systemd service")
    assert sel.metadata_match(pkg, "runtime_carriers")
    assert not sel.metadata_match(_pkg("demo", "font package"), "runtime_carriers")
    assert sel.tree_match(pkg, "runtime_carriers",
                          paths=["usr/lib/systemd/system/demo.service"])
    assert sel.tree_match(pkg, "runtime_carriers", paths=["usr/bin/helper.sh"])
    assert not sel.tree_match(pkg, "runtime_carriers", paths=["usr/bin/demo"])


def test_tree_strata_are_declared():
    assert sel.requires_tree("persist_surface")
    assert not sel.requires_tree("dependency_heavy")
    assert set(sel.EXISTING) | set(sel.NEW) == set(sel.EXISTING + sel.NEW)


def test_strata_file_targets_and_expectations_are_valid():
    import tomllib
    from trustsight.contract import rule_ids

    cfg = tomllib.loads(
        (Path(__file__).resolve().parent.parent / "scripts" / "strata.toml").read_text())
    strata = cfg["strata"]
    assert set(strata) == set(sel.EXISTING) | set(sel.NEW)
    targets = {name: row["target"] for name, row in strata.items()}
    assert sum(targets.values()) == 515
    live = set(rule_ids())
    for name, row in strata.items():
        for rule_id in row.get("expected_rules") or ():
            assert rule_id in live, f"{name}: {rule_id} is not a live rule"
