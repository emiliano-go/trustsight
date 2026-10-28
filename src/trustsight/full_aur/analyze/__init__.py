"""No-git analysis path (package facade)."""

from ...schema import TemporalContext
from ._fact import analyze_package_text
from ._helpers import (
    _corpus_dependency_fact,
    _diff_summary,
    _extract_pkgver,
    _install_diff_text,
    _install_hunk_findings,
    _make_diff_text,
    _temporal_findings,
    _walk_corpus_dependencies,
)

__all__ = [
    "TemporalContext",
    "analyze_package_text",
    "_corpus_dependency_fact",
    "_diff_summary",
    "_extract_pkgver",
    "_install_diff_text",
    "_install_hunk_findings",
    "_make_diff_text",
    "_temporal_findings",
    "_walk_corpus_dependencies",
]
