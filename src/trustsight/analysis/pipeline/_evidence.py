"""The evidence block every PackageFact producer must compute the same way.

The git path and the corpus path each assembled this by hand.  They already
drifted once (a first-seen producer missed four coverage signals), so the
block lives here: declared pinning, verification evidence, unresolved
sources/substitutions/assignments, partial install files, cut hunks and the
prebuilt declaration.  A producer supplies the diff and the post-state
recipe; the definition of "what this run could see" stays one.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...coverage import (
    parse_time_substitution_lines,
    unresolved_assignment_rows,
    unresolved_source_lines,
)
from ...diffdoc import parse_diff_lines
from ...differ import detect_verification_evidence, resolved_source_urls
from ...rules import clamp_text
from ...scoring import prebuilt_declared
from ..structural import partial_install_files
from ..base import _aggregate_pinning


@dataclass(frozen=True)
class Evidence:
    """The declared/coverage facts shared by the git and corpus paths."""

    aggregate_pinning: str
    verification_evidence: list[str]
    unresolved_sources: list[str]
    parse_time_substitutions: list[str]
    unresolved_assignments: list[dict]
    partial_files: list[str]
    cut_hunks: list
    prebuilt: bool


def collect_evidence(
    diff_text: str,
    recipe_text: str,
    *,
    added_urls,
    checksum_behavior: str,
) -> Evidence:
    """Compute the evidence block for one analysis."""
    from ...tokenizer import split_lines

    unresolved_sources = unresolved_source_lines(diff_text)
    parse_time_subs = parse_time_substitution_lines(diff_text, recipe_text)
    return Evidence(
        aggregate_pinning=_aggregate_pinning(
            diff_text, added_urls, checksum_behavior,
            declared_urls=resolved_source_urls(recipe_text),
        ),
        verification_evidence=detect_verification_evidence(
            diff_text, checksum_behavior),
        unresolved_sources=unresolved_sources,
        parse_time_substitutions=parse_time_subs,
        unresolved_assignments=unresolved_assignment_rows(
            clamp_text(recipe_text) or "", file="PKGBUILD",
            extra_lines=[*unresolved_sources, *parse_time_subs]),
        partial_files=partial_install_files(diff_text),
        cut_hunks=parse_diff_lines(split_lines(diff_text)).cut_hunks(),
        prebuilt=prebuilt_declared(recipe_text),
    )
