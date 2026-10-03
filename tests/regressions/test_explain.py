"""Tests for `inspect --explain`: the parser's own view, rendered.

The flag exists so triage and rule authoring work from what the typed
core believed (the RecipeDoc of the analysed PKGBUILD, the DiffDoc
summary of the analysed diff), not from a re-read of the raw text.
"""

from trustsight.cli.inspect import _explain_lines
from trustsight.schema import PackageFact


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


_V1 = ("pkgname=demo\npkgver=1.0\n"
       "source=('https://example.invalid/a.tar.gz')\nsha256sums=('abc')\n"
       "package() {\n  true\n}\n")
_V2 = ("pkgname=demo\npkgver=1.1\ninstall=demo.install\n"
       "source=('https://example.invalid/a.tar.gz')\nsha256sums=('abc')\n"
       "package() {\n  true\n}\n")


def test_explain_renders_the_recipe_and_diff_documents(tmp_path):
    repo, head = _repo(tmp_path, [{"PKGBUILD": _V1}, {"PKGBUILD": _V2}])
    old = str(repo.revparse_single("HEAD~1").id)
    fact = PackageFact(package_name="demo", old_commit=old, new_commit=head)
    out = "\n".join(_explain_lines(fact, repo))
    assert "scalars: install=demo.install, pkgname=demo, pkgver=1.1" in out
    assert "array source: 1 entry" in out
    assert "functions: package" in out
    assert "diff: 1 file(s), 1 hunk(s)" in out
    assert "PKGBUILD (modified, 1 hunk(s))" in out


def test_explain_without_a_diff_renders_the_recipe_alone(tmp_path):
    repo, head = _repo(tmp_path, [{"PKGBUILD": _V1}])
    fact = PackageFact(package_name="demo", old_commit="", new_commit=head)
    out = "\n".join(_explain_lines(fact, repo))
    assert "pkgname=demo" in out
    assert "diff:" not in out
