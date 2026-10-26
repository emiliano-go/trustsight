"""Extracted from differ.py: _verification."""

import re
from ..coverage import unpinned_source_refs
from ._checksums import _CHECKSUM_ARRAY_RE
from ._common import _post_diff_lines, _pre_diff_lines, _without_comments

__all__ = ['_GPG_VERIFY_RE', '_VALIDPGPKEYS_WITH_CONTENT_RE', '_has_checksum_in_post_diff', 'detect_gpg_verification_removed', 'detect_verification_evidence']

_GPG_VERIFY_RE = re.compile(
    r"(?:gpg|gpgv|openpgp)\s+(?:--verify|--decrypt|\-\-check-signatures)",
    re.IGNORECASE,
)

_VALIDPGPKEYS_WITH_CONTENT_RE = re.compile(
    r"validpgpkeys\s*=\s*\(\s*['\"]?[A-Fa-f0-9]{16,}",
)

def _has_checksum_in_post_diff(diff_text: str) -> bool:
    """Check whether the post-diff end-state declares checksums."""
    post = _without_comments("\n".join(_post_diff_lines(diff_text)))
    return bool(_CHECKSUM_ARRAY_RE.search(post))

def detect_gpg_verification_removed(diff_text: str) -> bool:
    """Detect whether GPG verification was removed in a diff.

    Reads the reconstructed pre-state and post-state rather than looking for
    a ``-`` line that carries a key.  When ``validpgpkeys=(`` is context and
    only the key entries are deleted, no removed line matches the
    declaration, so the old check missed the removal entirely and H024/H078
    stayed silent while verification was gone.
    """
    pre = _without_comments("\n".join(_pre_diff_lines(diff_text)))
    if not _VALIDPGPKEYS_WITH_CONTENT_RE.search(pre):
        return False
    post = _without_comments("\n".join(_post_diff_lines(diff_text)))
    return not bool(_VALIDPGPKEYS_WITH_CONTENT_RE.search(post))

def detect_verification_evidence(diff_text: str, checksum_behavior: str = "") -> list[str]:
    """Return a list of verification evidence strings present in the post-diff end-state.

    Each item is a key into ``scoring.DECLARED_REASONS``.  These are
    *declared* facts, reported at weight 0 (B10), never credited.
    Evidence is computed over the resolved PKGBUILD-as-it-will-be-installed,
    not over the diff delta; a checksum's protective value doesn't depend
    on whether it changed in this commit.
    """
    evidence: list[str] = []

    if checksum_behavior not in (
        "changed_from_sha256_to_skip",
        "checksum_array_emptied",
        "checksum_entry_removed",
        "checksum_array_removed",
    ):
        if _has_checksum_in_post_diff(diff_text):
            evidence.append("checksum_present")

    post = _without_comments("\n".join(_post_diff_lines(diff_text)))
    if _VALIDPGPKEYS_WITH_CONTENT_RE.search(post):
        evidence.append("validpgpkeys_declared")
    if _GPG_VERIFY_RE.search(post):
        evidence.append("gpg_verify_present")
    # The absence of a pin, stated.  P005/P006 report a commit or tag pin,
    # so a recipe tracking a branch produced no line at all and read the
    # same as one that pins.  Computed over the end-state for the reason
    # given above: what will be fetched does not depend on whether the ref
    # changed in this commit.
    if unpinned_source_refs(post):
        evidence.append("no_commit_pin")

    return evidence
