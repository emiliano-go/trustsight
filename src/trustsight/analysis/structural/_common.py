"""Extracted from structural.py: _common."""

import re

__all__ = ['_BINARY_ARTIFACT_RE', '_TRUSTED_BUCKETS']

_BINARY_ARTIFACT_RE = re.compile(
    r"\.(?:bin|exe|elf|so|dll|dylib|appimage|deb|rpm|apk|msi|jar|run)"
    r"(?:\?|#|$)",
    re.IGNORECASE,
)

#: Buckets a source may sit in without C005 firing.  ``declared_upstream`` is
#: trusted: a source on the registered domain of the package's own declared
#: ``url=`` is the project's own host, which is what C005 (binary artifact from
#: an untrusted source) exists to distinguish from a third party's.
_TRUSTED_BUCKETS = frozenset({"trusted_forge", "official", "declared_upstream"})
