import re

import pygit2

from .schema import DiffSummary, SourceChanges


def generate_diff(
    repo: pygit2.Repository, old_oid: str, new_oid: str, context_lines: int = 3
) -> tuple[str, DiffSummary]:
    old_commit = repo.get(old_oid)
    new_commit = repo.get(new_oid)
    diff = repo.diff(old_commit.tree, new_commit.tree, context_lines=context_lines)

    filtered_patches = []
    for patch in diff:
        delta = patch.delta
        path = delta.new_file.path
        if path == "PKGBUILD" or path.endswith(".install"):
            filtered_patches.append(patch.text)

    unified = "\n".join(filtered_patches)
    lines_added = diff.stats.insertions
    lines_removed = diff.stats.deletions
    files_changed = list({delta.new_file.path for delta in diff.deltas})

    summary = DiffSummary(
        lines_added=lines_added,
        lines_removed=lines_removed,
        files_changed=files_changed,
    )

    return unified, summary


def extract_urls_from_diff(diff_text: str) -> SourceChanges:
    added_urls: set[str] = set()
    removed_urls: set[str] = set()

    for line in diff_text.splitlines():
        if line.startswith("+") and "http" in line:
            urls = re.findall(r"https?://[^\s\'\"\)]+", line)
            added_urls.update(urls)
        elif line.startswith("-") and "http" in line:
            urls = re.findall(r"https?://[^\s\'\"\)]+", line)
            removed_urls.update(urls)

    checksum_behavior = detect_checksum_changes(diff_text)

    return SourceChanges(
        added_urls=list(added_urls),
        removed_urls=list(removed_urls),
        checksum_behavior=checksum_behavior,
    )


def detect_checksum_changes(diff_text: str) -> str:
    has_skip = re.search(
        r"^\+.*sha256sums\s*=\s*\(?\s*[\'\"]?(?:SKIP|NONE)[\'\"]?",
        diff_text,
        re.MULTILINE,
    )
    if has_skip:
        return "changed_from_sha256_to_skip"

    has_empty = re.search(
        r"^\+.*sha256sums\s*=\s*\(\s*\)", diff_text, re.MULTILINE
    )
    if has_empty:
        return "checksum_array_emptied"

    has_new = re.search(
        r"^\+.*sha256sums\s*=\s*\('",
        diff_text,
        re.MULTILINE,
    )
    if has_new:
        return "checksum_added_or_changed"

    return "unchanged"
