"""The release automation must survive its own procedure.

A release moves ``pkgver`` and the recorded checksum in two separate
commits, and it cannot do otherwise: the checksum is of the tarball GitHub
builds from the tag, so it is unknowable until the tag exists.  Between
those two commits the PKGBUILD names a version whose recorded checksum is
still the previous release's.  ``pkgbuild.yml`` runs on every push and
asserts that the two agree, so for two pushes per release that assertion
cannot hold, and it failed the build for a state the procedure guarantees.

The guard added in v0.13.1 identifies the window from the tag alone.  These
tests run the **shipped** script, extracted from the workflow, against
synthetic repositories in each state.  A copy of the logic would drift from
the workflow and pass while the workflow failed, which is the whole failure
this pins.

The structural checks matter as much as the behavioural ones.  The guard
depends on the checkout carrying tags: under a shallow clone every tag
lookup misses, so the gate reports "release in flight" forever and the
tarball checks silently stop running.  That failure is invisible in a green
build, which is why ``fetch-depth: 0`` is asserted here.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
PKGBUILD_WORKFLOW = WORKFLOWS / "pkgbuild.yml"
RELEASE_WORKFLOW = WORKFLOWS / "release-pkgbuild.yml"

pytestmark = [
    pytest.mark.skipif(
        not PKGBUILD_WORKFLOW.exists(), reason="workflows not present"
    ),
    pytest.mark.skipif(not shutil.which("git"), reason="git not available"),
]

# The step whose script decides whether the tarball checks can run.
GATE_STEP_ID = "release"
GUARD = "if: steps.release.outputs.ready == 'true'"


def _step_script(workflow: str, step_id: str) -> str:
    """Return the ``run:`` script of the step carrying ``id: <step_id>``.

    Text extraction rather than a YAML parse on purpose: PyYAML is not a
    declared test dependency (``dev = ["pytest", "ruff"]``) and CI installs
    exactly that, so importing it would pass here and fail there.
    """
    lines = workflow.split("\n")
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == f"id: {step_id}"),
        None,
    )
    assert start is not None, f"no step with id: {step_id} in the workflow"

    run_at = None
    for i in range(start + 1, len(lines)):
        # A new step begins; the id'd step had no run block.
        if re.match(r"^\s*- \w", lines[i]):
            break
        if lines[i].strip().startswith("run: |"):
            run_at = i
            break
    assert run_at is not None, f"step {step_id} has no run block"

    indent = len(lines[run_at]) - len(lines[run_at].lstrip()) + 2
    body = []
    for line in lines[run_at + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:] if len(line) >= indent else line)
    script = "\n".join(body).rstrip() + "\n"

    # If the extraction silently grabbed the wrong text the behavioural
    # tests below would assert against nothing, so prove it is the gate.
    assert "ready=" in script and "refs/tags/" in script, (
        f"extracted script for {step_id} does not look like the gate:\n{script}"
    )
    return script


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=repo, check=True,
        capture_output=True, text=True,
    )


def _repo(tmp_path: Path, pkgver: str, *, tag: str | None = None,
          commits_after_tag: int = 0) -> Path:
    """A repository shaped like this one at a point in the release."""
    repo = tmp_path / "repo"
    (repo / "packaging" / "aur").mkdir(parents=True)
    (repo / "packaging" / "aur" / "PKGBUILD").write_text(
        f"pkgname=trustsight\npkgver={pkgver}\npkgrel=1\n"
        "sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')\n"
    )
    _git(repo, "init", "-q", "-b", "master")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    # The developer running this has commit.gpgsign on; a synthetic repo
    # must not reach for a signing key.
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", f"chore(release): bump to v{pkgver}")
    if tag is not None:
        _git(repo, "tag", "-a", tag, "-m", tag)
    for n in range(commits_after_tag):
        (repo / "packaging" / "aur" / f"note-{n}").write_text("x\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", f"packaging: set checksum ({n})")
    return repo


def _run_gate(tmp_path: Path, repo: Path) -> tuple[subprocess.CompletedProcess, dict]:
    """Run the shipped gate script the way the runner would."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    output = tmp_path / "github_output"
    output.write_text("")

    script = _step_script(PKGBUILD_WORKFLOW.read_text(), GATE_STEP_ID)
    result = subprocess.run(
        ["sh", "-c", script], cwd=repo, capture_output=True, text=True,
        env={
            **os.environ,
            # The script runs `git config --global --add safe.directory`.
            # Without an isolated HOME every run of this test would append a
            # line to the developer's own ~/.gitconfig.
            "HOME": str(home),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_WORKSPACE": str(repo),
        },
    )
    parsed = dict(
        line.split("=", 1)
        for line in output.read_text().splitlines() if "=" in line
    )
    return result, parsed


# --- the three states of a release ---------------------------------------


def test_gate_skips_on_the_version_bump_commit(tmp_path):
    """First push of a release: the tag does not exist yet, so the tarball
    the checksum would be compared against cannot be fetched at all."""
    repo = _repo(tmp_path, "9.9.9")
    result, out = _run_gate(tmp_path, repo)

    assert result.returncode == 0, result.stderr
    assert out["ready"] == "false"
    assert "does not exist yet" in result.stdout


def test_gate_skips_when_head_is_the_tag_itself(tmp_path):
    """Second push of a release: the tag now exists, but it points at the
    bump commit, whose recorded checksum is still the previous release's."""
    repo = _repo(tmp_path, "9.9.9", tag="v9.9.9")
    result, out = _run_gate(tmp_path, repo)

    assert result.returncode == 0, result.stderr
    assert out["ready"] == "false"
    assert "HEAD is v9.9.9" in result.stdout


def test_gate_runs_once_the_checksum_commit_lands(tmp_path):
    """The state the assertion exists for: the tag is in history and the
    checksum commit sits after it."""
    repo = _repo(tmp_path, "9.9.9", tag="v9.9.9", commits_after_tag=1)
    result, out = _run_gate(tmp_path, repo)

    assert result.returncode == 0, result.stderr
    assert out["ready"] == "true"


def test_gate_runs_on_ordinary_commits_long_after_a_release(tmp_path):
    """The common case: every push that is not part of a release still gets
    the full check, so the guard cannot be used to skip it wholesale."""
    repo = _repo(tmp_path, "9.9.9", tag="v9.9.9", commits_after_tag=5)
    result, out = _run_gate(tmp_path, repo)

    assert result.returncode == 0, result.stderr
    assert out["ready"] == "true"


def test_gate_never_fails_the_job(tmp_path):
    """The gate decides; it never itself ends the build. A non-zero exit
    here would reintroduce the failure it was written to remove."""
    for kwargs in ({}, {"tag": "v9.9.9"}, {"tag": "v9.9.9", "commits_after_tag": 2}):
        state = tmp_path / f"state-{len(kwargs)}"
        state.mkdir()
        repo = _repo(state, "9.9.9", **kwargs)
        result, _ = _run_gate(state, repo)
        assert result.returncode == 0, f"{kwargs}: {result.stderr}"


# --- structure the behaviour depends on ----------------------------------


def test_the_checkout_fetches_tags(tmp_path):
    """The guard reads tags. Under the default shallow checkout every tag
    lookup misses, the gate reports "release in flight" on every push, and
    the tarball checks stop running without anything turning red."""
    text = PKGBUILD_WORKFLOW.read_text()
    assert "fetch-depth: 0" in text, (
        "pkgbuild.yml must checkout with fetch-depth: 0, or the release "
        "guard silently disables the checksum verification for good"
    )


def test_every_step_after_the_gate_is_guarded():
    """A step added below the gate without the `if:` runs during the window
    the gate exists to sit out, which is exactly the original failure."""
    lines = PKGBUILD_WORKFLOW.read_text().split("\n")
    id_at = next(
        i for i, line in enumerate(lines) if line.strip() == f"id: {GATE_STEP_ID}"
    )
    # `id:` sits inside the gate step, below its `- name:`. Splitting from
    # there would make the step *after* the gate look like the gate and
    # exempt it, so walk back to the gate's own boundary first.
    gate_at = max(
        i for i in range(id_at + 1) if re.match(r"^\s*- \w", lines[i])
    )

    steps: list[list[str]] = []
    for line in lines[gate_at:]:
        if re.match(r"^\s*- \w", line):
            steps.append([])
        if steps:
            steps[-1].append(line)

    # steps[0] is the gate itself, which must not guard on its own output.
    assert any(f"id: {GATE_STEP_ID}" in line for line in steps[0]), (
        "failed to locate the gate step; the guard check is not looking at "
        "what it thinks it is"
    )
    unguarded = [
        next((ln.strip() for ln in step if "name:" in ln), "<unnamed>")
        for step in steps[1:]
        if not any(line.strip() == GUARD for line in step)
    ]
    assert unguarded == [], f"steps after the gate missing {GUARD!r}: {unguarded}"


def test_the_release_workflow_builds_the_artifact_it_publishes():
    """pkgbuild.yml cannot cover the release it guards: the only commit
    where its assertion can pass is pushed with GITHUB_TOKEN, and GitHub
    does not trigger workflows from those pushes. The release workflow
    therefore has to build the tarball itself."""
    text = RELEASE_WORKFLOW.read_text()
    assert "makepkg -si" in text, (
        "release-pkgbuild.yml must build and install the release tarball, or "
        "no CI run ever executes check() against the artifact being published"
    )


@pytest.mark.parametrize("flag", ["--nocheck", "--skipchecksums"])
def test_no_workflow_weakens_the_release_build(flag):
    """`--nocheck` skips the shipped test suite and `--skipchecksums` skips
    the integrity check. Either one turns the build into a formality.

    Comment lines are excluded: both workflows carry a "No --nocheck:"
    comment stating why the flag is absent, and matching on that would fail
    the test for saying the right thing.
    """
    offenders = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        for lineno, line in enumerate(workflow.read_text().splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            if flag in line:
                offenders.append(f"{workflow.name}:{lineno}")
    assert offenders == [], f"{flag} used in: {offenders}"
