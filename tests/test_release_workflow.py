"""Regression checks for release workflow separation and packaging integrity."""

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
PKGBUILD_WORKFLOW = WORKFLOWS / "pkgbuild.yml"
RELEASE_WORKFLOW = WORKFLOWS / "release-pkgbuild.yml"
PUBLISHING_WORKFLOW = WORKFLOWS / "publishing.yml"
SOFTWARE_TAG_PATTERN = r'^v[0-9]+\.[0-9]+\.[0-9]+$'


def _classifier_script(workflow: Path) -> str:
    lines = workflow.read_text().splitlines()
    tag_step = next(i for i, line in enumerate(lines) if line.strip().endswith("id: tag"))
    run_at = next(
        i for i in range(tag_step + 1, len(lines)) if lines[i].strip() == "run: |"
    )
    indent = len(lines[run_at]) - len(lines[run_at].lstrip()) + 2
    body = []
    for line in lines[run_at + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:])
    return "\n".join(body)


@pytest.mark.parametrize("workflow", [RELEASE_WORKFLOW, PUBLISHING_WORKFLOW])
@pytest.mark.parametrize(
    ("tag", "expected"),
    [("v1.2.3", "true"), ("baseline-2026-08-17", "false"), ("v1.2", "false")],
)
def test_software_tag_classifier_is_exact(workflow, tag, expected, tmp_path):
    output = tmp_path / "github-output"
    result = subprocess.run(
        ["bash", "-c", _classifier_script(workflow)],
        env={**os.environ, "TAG": tag, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert f"is_software_release={expected}" in output.read_text()


def test_release_artifact_verification_only_runs_for_software_tags():
    text = RELEASE_WORKFLOW.read_text()

    assert "workflow_dispatch:" in text
    assert SOFTWARE_TAG_PATTERN in text
    assert "needs: classify" in text
    assert "if: needs.classify.outputs.is_software_release == 'true'" in text
    assert "ref: ${{ needs.classify.outputs.tag }}" in text


def test_pypi_publishing_only_runs_for_software_tags():
    text = PUBLISHING_WORKFLOW.read_text()

    assert SOFTWARE_TAG_PATTERN in text
    assert "needs: classify" in text
    assert text.count("if: needs.classify.outputs.is_software_release == 'true'") == 3
    assert "needs: [classify, preflight, aur]" in text


def test_pkgbuild_verifies_the_pre_tag_deterministic_tarball_on_every_run():
    text = PKGBUILD_WORKFLOW.read_text()

    assert "fetch-depth: 0" in text
    assert "scripts/build_release_tarball.py" in text
    assert '--output "packaging/aur/trustsight-${pkgver}.tar.gz"' in text
    assert "steps.release.outputs.ready" not in text
    assert "refs/tags/" not in text
    assert "release in flight" not in text
    assert "releases/download/" not in text


@pytest.mark.parametrize("flag", ["--nocheck", "--skipchecksums"])
def test_no_workflow_weakens_the_release_build(flag):
    offenders = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        for lineno, line in enumerate(workflow.read_text().splitlines(), start=1):
            if not line.lstrip().startswith("#") and flag in line:
                offenders.append(f"{workflow.name}:{lineno}")
    assert offenders == [], f"{flag} used in: {offenders}"


def test_a_worktree_build_refuses_untracked_files(tmp_path):
    """An untracked scratch directory may not reach the release tarball.

    ``_worktree_tree`` stages with ``git add -A``, which is wider than "the
    content that will be tagged": anything the ignore rules do not cover is
    swept in.  A stray directory left in a checkout therefore shipped
    unreviewed files inside the archive, and the recorded checksum
    described that archive, so the two agreed with each other and disagreed
    with every clean tree.  v0.13.2 recorded such a checksum, and it
    surfaced only on CI, whose checkout has nothing stray in it.
    """
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    from build_release_tarball import _untracked, _worktree_tree

    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *args: subprocess.run(  # noqa: E731
        args, cwd=repo, check=True, capture_output=True,
    )
    run("git", "init", "-q")
    run("git", "config", "user.email", "t@example.invalid")
    run("git", "config", "user.name", "t")
    (repo / "kept.txt").write_text("shipped\n")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "c")

    import build_release_tarball as brt

    monkey = brt.ROOT
    try:
        brt.ROOT = repo
        assert _untracked() == []
        # A clean tree still builds.
        assert _worktree_tree()

        (repo / "scratch").mkdir()
        (repo / "scratch" / "stray.bin").write_bytes(b"unreviewed")
        assert _untracked() == ["scratch/"]
        with pytest.raises(SystemExit, match="untracked files"):
            _worktree_tree()

        # Staging it is the operator saying it belongs in the release.
        run("git", "add", "-A")
        assert _untracked() == []
        assert _worktree_tree()
    finally:
        brt.ROOT = monkey
