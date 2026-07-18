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
        if path in ("PKGBUILD", ".SRCINFO") or path.endswith(".install"):
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


_VCS_SOURCE_RE = re.compile(
    r"^\+(?:.*\b(?:git\+https?://|git://|svn://|hg://|bzr://|svn\+https?://|git\+ssh://))",
    re.IGNORECASE,
)
_GIT_PKG_RE = re.compile(r"^\+\s*source\s*=.*\.git\b", re.IGNORECASE)
_SIG_SRC_RE = re.compile(r"\.(?:sig|asc)[\'\"]?\s*$", re.IGNORECASE)
_VALIDPGPKEYS_RE = re.compile(r"^\+\s*validpgpkeys\s*=\s*\(", re.IGNORECASE)
_DKMS_RE = re.compile(r"^\+\s*DKMS", re.IGNORECASE)

_SKIP_JUSTIFICATION_CHECKS = [
    ("vcs source", lambda t: bool(_VCS_SOURCE_RE.search(t) or _GIT_PKG_RE.search(t) or _DKMS_RE.search(t))),
    ("signature file", lambda t: bool(_SIG_SRC_RE.search(t))),
    ("validpgpkeys present", lambda t: bool(_VALIDPGPKEYS_RE.search(t))),
]


def is_skip_justified(diff_text: str) -> str:
    """Check whether a ``SKIP`` checksum has a valid justification.

    Returns a short reason string (truthy) or ``""`` (falsy).
    """
    for reason, check in _SKIP_JUSTIFICATION_CHECKS:
        if any(check(line) for line in diff_text.splitlines()):
            return reason
    return ""


def extract_urls_from_diff(diff_text: str) -> SourceChanges:
    added_urls: set[str] = set()
    removed_urls: set[str] = set()

    for line in diff_text.splitlines():
        if line.startswith("+") and "http" in line:
            urls = re.findall(r"https?://[^\s\'\"\)]+", line)
            for u in urls:
                u = re.sub(r"[\)]+$", "", u)
                u = re.sub(r"[\)]+", ")", u)
                added_urls.add(u)
        elif line.startswith("-") and "http" in line:
            urls = re.findall(r"https?://[^\s\'\"\)]+", line)
            for u in urls:
                u = re.sub(r"[\)]+$", "", u)
                removed_urls.add(u)

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


_GPG_VERIFY_RE = re.compile(
    r"(?:gpg|gpgv|openpgp)\s+(?:--verify|--decrypt|\-\-check-signatures)",
    re.IGNORECASE,
)
_VALIDPGPKEYS_WITH_CONTENT_RE = re.compile(
    r"validpgpkeys\s*=\s*\(\s*['\"]?[A-Fa-f0-9]{16,}",
)
_CHECKSUM_ARRAY_RE = re.compile(
    r"(?:sha256sums|sha512sums|sha1sums|b2sums|md5sums)\s*=\s*(?:\(|['\"]?[A-Fa-f0-9])",
)


def _post_diff_lines(diff_text: str) -> list[str]:
    """Reconstruct the post-diff file content lines.

    Applies the diff: keeps context (`` ``) and addition (``+``) lines,
    drops removal (``-``) and header lines.  Returns lines with their
    diff prefix stripped.
    """
    out: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("-"):
            continue
        if line.startswith("+") or line.startswith(" "):
            out.append(line.lstrip("+ "))
    return out


def _has_checksum_in_post_diff(diff_text: str) -> bool:
    """Check whether the post-diff end-state declares checksums."""
    post = "\n".join(_post_diff_lines(diff_text))
    return bool(_CHECKSUM_ARRAY_RE.search(post))


def detect_verification_evidence(diff_text: str, checksum_behavior: str = "") -> list[str]:
    """Return a list of verification evidence strings present in the post-diff end-state.

    Each item is a key into ``config.verification_evidence`` weights.
    Evidence is computed over the resolved PKGBUILD-as-it-will-be-installed,
    not over the diff delta — a checksum's protective value doesn't depend
    on whether it changed in this commit.
    """
    evidence: list[str] = []

    if checksum_behavior not in ("changed_from_sha256_to_skip", "checksum_array_emptied"):
        if _has_checksum_in_post_diff(diff_text):
            evidence.append("checksum_present")

    post = "\n".join(_post_diff_lines(diff_text))
    if _VALIDPGPKEYS_WITH_CONTENT_RE.search(post):
        evidence.append("validpgpkeys_declared")
    if _GPG_VERIFY_RE.search(post):
        evidence.append("gpg_verify_present")

    return evidence
