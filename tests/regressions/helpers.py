"""Recipe builders shared by more than one regression group.

A helper used by a single module stays in that module; these are the ones
whose call sites crossed the group boundaries when this suite was one file.
"""

import gzip
import hashlib
import json
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

_PK = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,20 +1,60 @@\n"

_MANIFEST = {
    "version": 1, "ruleset_version": "t", "scorer_version": "t",
    "corpus_cutoff": "",
}


def _metadata_hash(metadata_list) -> str:
    raw = json.dumps(metadata_list, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _write_artifact(tmp_path, payload, name="ragged.gz") -> Path:
    from trustsight.full_aur.export import canonical_artifact_bytes

    metadata = [{"Name": "demo"}]
    canonical = canonical_artifact_bytes(
        [], [], _metadata_hash(metadata), _MANIFEST
    )
    artifact = {"signature": None, **json.loads(canonical), **payload,
                "metadata_snapshot": metadata}
    path = tmp_path / name
    path.write_bytes(gzip.compress(json.dumps(artifact).encode()))
    return path


def _recipe(*lines):
    return _PK + "".join("+" + ln + "\n" for ln in lines)


def _ids(diff, **kw):
    from trustsight.analysis import scan_diff

    return {e.rule_id for e in scan_diff(diff, package_name="p", **kw).score_breakdown}


def _score(diff, **kw):
    from trustsight.analysis import scan_diff

    return scan_diff(diff, package_name="p", **kw).final_score


def _repo_with(files):
    import pygit2
    import tempfile

    repo = pygit2.init_repository(tempfile.mkdtemp(), bare=True)
    builder = repo.TreeBuilder()
    for name, content in files:
        builder.insert(name, repo.create_blob(content), pygit2.GIT_FILEMODE_BLOB)
    sig = pygit2.Signature("t", "t@example.invalid")
    commit = repo.create_commit(
        "refs/heads/master", sig, sig, "c", builder.write(), [],
    )
    return repo, str(commit)


def _shipped_ids(command_lines, declared=True, manifest=None, fn="build",
                 source=None):
    """Rule ids for a recipe body, against the **shipped** rules.

    `conftest.SHARED_RULES` is a small hand-written fixture set, and
    `load_rules()` reads whatever `rules.toml` the developer's machine
    happens to hold - which, as the drift check now reports, is often an
    older generation.  Neither answers "what does this build ship", which is
    the only question these regressions are about.
    """
    import sys

    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.config import load_config, load_rules

    url = source or "https://github.com/u/p/releases/download/v1/p.zip"
    head = ([f'source=("{url}")', "sha256sums=('SKIP')"]
            if declared or source else [])
    body = "".join(
        "+" + ln + "\n"
        for ln in head + [f"{fn}() {{"] + list(command_lines) + ["}"]
    )
    diff = _PK + body
    with shipped_config():
        fact = scan_diff(diff, package_name="p", tree_manifest=manifest,
                         rules=load_rules(), config=load_config())
    return {e.rule_id for e in fact.score_breakdown}


def _fires(command_lines, declared=True, manifest=None):
    from trustsight.analysis import scan_diff

    head = ['source=("https://github.com/u/p/releases/download/v1/p.zip")',
            "sha256sums=('SKIP')"] if declared else []
    body = "".join(
        "+" + ln + "\n"
        for ln in head + ["build() {"] + list(command_lines) + ["}"]
    )
    diff = _PK + body
    return {e.rule_id for e in
            scan_diff(diff, package_name="p", tree_manifest=manifest).score_breakdown}


def _x(command_lines, head=(), fn="build"):
    """Crossfire techniques for a recipe body."""
    from trustsight.analysis.crossfire import crossfire_techniques

    body = "".join("+" + ln + "\n" for ln in
                   list(head) + [f"{fn}() {{"] + list(command_lines) + ["}"])
    return crossfire_techniques(_PK + body)
