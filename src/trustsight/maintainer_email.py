"""Maintainer address parsing shared by the analysis and storage paths."""

import re
from email.utils import parseaddr

__all__ = ["maintainer_domain", "normalize_domain"]

_ANGLE_EMAIL_RE = re.compile(r"<([^<>]+)>")
_EDGE_CHARS = "<>()[],;:"


def normalize_domain(value: str) -> str:
    """Return the bare host part of a stored or extracted domain.

    A previous extractor kept whatever followed ``@``, so rows can carry the
    closing angle bracket or a trailing comment.  Collapse them to one key.
    """
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = text.split()[0]
    return text.strip(_EDGE_CHARS)[:253]


def maintainer_domain(value: str) -> str:
    """Return the email domain of an AUR maintainer string, or ``""``.

    AUR writes maintainers as ``Name <user@domain>``.  ``parseaddr`` covers
    that form and the ``user@domain (comment)`` form; the regexes are the
    fallback for the malformed brackets a recipe can still contain.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    match = _ANGLE_EMAIL_RE.search(text)
    address = match.group(1).strip() if match else parseaddr(text)[1]
    if "@" not in address:
        for token in text.split():
            candidate = token.strip(_EDGE_CHARS)
            if "@" in candidate:
                address = candidate
                break
    if "@" not in address:
        return ""
    return normalize_domain(address.rsplit("@", 1)[1])
