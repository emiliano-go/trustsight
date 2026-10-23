"""The AUR clone the benign corpus is built from.

The corpus is byte-stable only if every diff groups its hunks the way the
baseline was computed with.  That takes two things, and only one of them is
a command-line flag: the ``pkgbuild`` diff driver has to be *mapped* for
``PKGBUILD`` (an ``info/attributes`` line), and the driver's ``xfuncname``
has to be configured (a repo config).  ``git diff -c
diff.pkgbuild.xfuncname=...`` configures a driver that nothing uses when the
attributes line is missing, so ``-W`` falls back to git's default
function-context heuristic and the diffs come out byte-different.

``info/attributes`` is not something a clone carries: neither ``git clone
--bare`` nor ``git init --bare`` writes one.  Only the path that creates the
clone here installs it, so a clone that arrived from anywhere else - a cache
the operator filled in themselves, or one left by an older version of this
script - was used unprepared, and the corpus built from it no longer hashes
to the value ``baseline.json`` records.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_corpus as bc  # noqa: E402

PKGBUILD = """\
pkgname=demo
pkgver=1.0
build() {
  cd "$srcdir"
  make
}
package() {
  install -Dm755 demo "$pkgdir/usr/bin/demo"
}
"""


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True, capture_output=True, text=True,
    ).stdout


@pytest.fixture
def source_repo(tmp_path):
    """A repo whose PKGBUILD changes inside ``build()``.

    The change has to land *inside* a function: outside one, ``-W`` has no
    function context to show and the two groupings coincide, which would
    hide the difference the test is about.
    """
    if shutil.which("git") is None:
        pytest.skip("git is not available")
    repo = tmp_path / "src"
    repo.mkdir()
    _git(repo, "init", "-q", ".")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "PKGBUILD").write_text(PKGBUILD)
    _git(repo, "add", "PKGBUILD")
    _git(repo, "commit", "-qm", "one")
    first = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "PKGBUILD").write_text(PKGBUILD.replace("  make\n", "  make -j8\n"))
    _git(repo, "add", "PKGBUILD")
    _git(repo, "commit", "-qm", "two")
    second = _git(repo, "rev-parse", "HEAD").strip()
    return repo, first, second


def _bare_clone(source: Path, dest: Path) -> Path:
    subprocess.run(
        ["git", "clone", "--bare", "-q", str(source), str(dest)],
        check=True, capture_output=True,
    )
    return dest


def test_a_reused_clone_is_prepared_for_the_corpus_diff(
    source_repo, tmp_path, monkeypatch
):
    """A clone the script did not create must still be prepared.

    The cache is reused across runs and the operator can fill it in
    themselves - the clone is tens of gigabytes, and the script says so.
    A bare clone carries no ``info/attributes``, so without preparing the
    reused clone the corpus is built with git's default hunk grouping and
    its bytes no longer match the committed corpus hash.
    """
    source, first, second = source_repo
    cached = _bare_clone(source, tmp_path / "aur.git")
    assert not (cached / "info" / "attributes").exists(), (
        "a bare clone carries no attributes file; that is the point of the test"
    )

    monkeypatch.setattr(bc, "CACHE_DIR", tmp_path)
    assert bc.ensure_aur_clone() == cached, "the cached clone must be reused"

    attrs = cached / "info" / "attributes"
    assert attrs.exists(), (
        "a reused clone must be mapped to the pkgbuild diff driver"
    )
    assert "PKGBUILD diff=pkgbuild" in attrs.read_text(encoding="utf-8")
    assert _git(cached, "config", "--get", "diff.pkgbuild.xfuncname").strip() \
        == bc.XFUNCNAME

    # The consequence: the diff the corpus is built from is the one a
    # prepared clone produces, whatever route the clone arrived by.
    prepared = _bare_clone(source, tmp_path / "prepared.git")
    bc._ensure_xfuncname(prepared)
    assert bc.get_diff(cached, first, second) == bc.get_diff(
        prepared, first, second
    )


def test_the_mapping_is_added_to_an_existing_attributes_file(tmp_path):
    """The mapping is ensured, not merely created.

    A clone that already has an ``info/attributes`` of its own keeps it and
    gains the two lines it is missing; otherwise the driver is configured
    and unused, which is the same defect in another shape.
    """
    repo = tmp_path / "aur.git"
    (repo / "info").mkdir(parents=True)
    (repo / "info" / "attributes").write_text("*.md text\n")

    bc._ensure_xfuncname(repo)

    lines = (repo / "info" / "attributes").read_text(encoding="utf-8").splitlines()
    assert "*.md text" in lines, "an existing rule must survive"
    assert "PKGBUILD diff=pkgbuild" in lines
    assert "*.install diff=pkgbuild" in lines


def test_the_mapping_is_what_decides_the_hunk_grouping(source_repo, tmp_path):
    """The mechanism the two tests above depend on.

    Configuring ``xfuncname`` on the command line is not enough: without the
    attributes line nothing routes ``PKGBUILD`` to that driver, and the hunks
    are grouped by git's default heuristic instead.
    """
    source, first, second = source_repo
    raw = _bare_clone(source, tmp_path / "raw.git")
    before = bc.get_diff(raw, first, second)

    bc._ensure_xfuncname(raw)
    after = bc.get_diff(raw, first, second)

    assert before != after, (
        "the pkgbuild driver must change how the hunks are grouped"
    )
    prepared = _bare_clone(source, tmp_path / "prepared.git")
    bc._ensure_xfuncname(prepared)
    assert after == bc.get_diff(prepared, first, second)
