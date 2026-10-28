"""Helpers for the no-git corpus analysis path."""

import difflib
import logging
import re
import time

from ...analysis.structural import (
    _structural_findings,
)
from ...analysis.version import full_version_from_pkgbuild
from ...changes import change_delta
from ...differ import (
    extract_urls_from_diff,
    map_diff_lines,
)
from ...findings import stamp
from ...analysis.structural_rules import apply_structural_rules
from ...rules import (
    apply_rules,
    get_raw_diff_lines_indexed,
)
from ...schema import (
    DiffSummary,
    TemporalContext,
)
from ...tokenizer import tokenize_and_resolve_indexed
from ...tokenizer import split_lines

log = logging.getLogger(__name__)
def _extract_pkgver(pkgbuild: str | None) -> str:
    """The declared full version, using the shared resolver.

    The old local regex read the first ``pkgver=`` line anywhere in the
    file, including inside a function or heredoc, and returned dynamic
    values literally.  The shared reader resolves the recipe's own fields
    and includes epoch/pkgrel, matching the review path.
    """
    return full_version_from_pkgbuild(pkgbuild or "")


def _make_diff_text(old_text: str, new_text: str, context_lines: int = 3) -> str:
    """Build the unified diff for the corpus path.

    Uses the same shell-aware ``split_lines`` (and newline join) as
    ``analysis.pipeline.analyze_package_text``.  Python's ``splitlines``
    breaks on U+2028 and friends, which a PKGBUILD treats as an ordinary
    character in a word, so identical recipe texts produced different hunk
    boundaries depending on which adapter built the diff - and rules that
    scan the diff could fire on one path and not the other.
    """
    old_lines = split_lines(old_text) if old_text else []
    new_lines = split_lines(new_text) if new_text else []
    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile="PKGBUILD",
            tofile="PKGBUILD",
            n=context_lines,
        )
    )
    return "\n".join(diff_lines) + ("\n" if diff_lines else "")


_INSTALL_NAME_RE = re.compile(r"^[A-Za-z0-9@._+-]{1,255}$")


def _install_diff_text(install_text: str, filename: str) -> str:
    """An added-file hunk for the ``.install`` scriptlet, for the corpus diff.

    The corpus diff holds only the PKGBUILD, so an install scriptlet is
    invisible to the structural rules.  Presenting its whole current content
    as an added file - the way the git path presents a committed ``.install``
    - lets every content rule read it, including the unconditional
    root-fetch/write shapes a trojanised repackage hides there.

    ``filename`` is the hunk's path verbatim and must be the scriptlet's real
    committed name: structural rules (C024) compare it against ``install=``,
    and an invented name (e.g. the package name) reads as a dead hook.
    """
    if not isinstance(install_text, str) or not install_text:
        return ""
    filename = str(filename or "").replace("\r", "").replace("\n", "").strip()
    if not _INSTALL_NAME_RE.match(filename):
        # A tar member name is not a trusted diff path: a newline or header
        # in it could forge another file's hunk.  Refuse the synthetic hunk
        # rather than analyse an invented path.
        return ""
    lines = split_lines(install_text)
    if not lines:
        return ""
    body = "\n".join("+" + line for line in lines)
    return (
        f"--- /dev/null\n+++ b/{filename}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n{body}\n"
    )


def _install_hunk_findings(
    install_text: str | None,
    install_name: str | None,
    pkg_name: str,
    new_pkgbuild: str,
    tree_manifest: list[tuple[str, bytes]] | None,
    config: dict,
) -> list[dict]:
    """Run the diff rules over the scriptlet on a first-seen package.

    The update path appends the hook to the PKGBUILD diff; the first-seen
    path has no PKGBUILD diff, but the scriptlet still ships and can still
    run root commands.  Only the synthetic install hunk is fed here.
    """
    diff = _install_diff_text(install_text or "", install_name or f"{pkg_name}.install")
    if not diff:
        return []
    source_changes = extract_urls_from_diff(diff)
    resolved, _unresolved, resolved_indices = tokenize_and_resolve_indexed(diff)
    raw_lines, raw_indices = get_raw_diff_lines_indexed(diff)
    findings = apply_rules(
        resolved,
        raw_lines,
        include_experimental=config.get("rules", {}).get("experimental", False),
        line_map=map_diff_lines(diff),
        resolved_indices=resolved_indices,
        raw_indices=raw_indices,
    )
    findings.extend(_structural_findings(
        diff, source_changes, {},
        package_name=pkg_name,
        config=config,
        current_text=new_pkgbuild,
        tree_manifest=tree_manifest,
        delta=change_delta(diff, pkg_name, current_text=new_pkgbuild),
    ))
    findings.extend(apply_structural_rules(
        diff, current_text=new_pkgbuild, package_name=pkg_name,
    ))
    return findings


def _diff_summary(diff_text: str) -> DiffSummary:
    from ...differ import diff_summary_from_text

    return diff_summary_from_text(diff_text)


def _temporal_findings(
    temporal: TemporalContext,
    pkg_name: str,
    is_new_package: bool,
) -> list[dict]:
    """Generate temporal findings (H020, H021, H022) from TemporalContext."""
    findings: list[dict] = []
    now = time.time()

    if temporal.last_modified is not None and temporal.last_modified > 0:
        hours_ago = (now - temporal.last_modified) / 3600
        if 0 <= hours_ago < 72:
            findings.append(stamp({
                "rule_id": "H020",
                "name": "Very Recent Update",
                "severity": "INFO",
                "category": "temporal",
                "match": f"updated {int(hours_ago)}h ago (< 72h)",
                "params": {"detail": f"updated {int(hours_ago)}h ago (< 72h)"},
            }))

    if temporal.first_seen is not None and is_new_package:
        days_ago = (now - temporal.first_seen) / 86400
        if 0 <= days_ago < 30:
            findings.append(stamp({
                "rule_id": "H021",
                "name": "Brand New Package",
                "severity": "INFO",
                "category": "temporal",
                "match": f"first AUR submission {int(days_ago)} days ago (< 30)",
                "params": {"detail": f"first AUR submission {int(days_ago)} days ago (< 30)"},
            }))

    if (temporal.last_modified is not None
            and temporal.previous_modified is not None
            and temporal.last_modified > 0
            and temporal.previous_modified > 0):
        gap_days = (temporal.last_modified - temporal.previous_modified) / 86400
        if gap_days > 365:
            findings.append(stamp({
                "rule_id": "H022",
                "name": "Stale Package Revived",
                "severity": "MEDIUM",
                "category": "temporal",
                "match": f"dormant {int(gap_days)} days, now has a new update (> 1 year)",
                "params": {"detail": f"dormant {int(gap_days)} days, now has a new update (> 1 year)"},
            }))

    return findings


def _corpus_dependency_fact(name: str, record: bool = False):
    """A dependency's result, preferring what the corpus already computed.

    On the corpus path every package is analysed in its own right during the
    same cycle, so re-running the pipeline for a dependency would compute a
    number the database already holds. The stored profile is therefore the
    first source, the stored PKGBUILD snapshot the fallback, and a package
    with neither is reported as not vetted rather than fetched: the bootstrap
    owns its own fetch order, and re-entering it from inside one package's
    analysis would both fight that ordering and turn a corpus pass into an
    unbounded crawl.
    """
    from ...db import get_package_profile, get_pkgbuild_snapshot

    profile = get_package_profile(name)
    if profile and profile.get("last_score") is not None:
        return _StoredFact(
            final_score=int(profile["last_score"] or 0),
            risk=str(profile.get("last_risk") or ""),
        )

    row = get_pkgbuild_snapshot(name)
    if not row or not row["pkgbuild_text"]:
        raise LookupError(f"no stored result or PKGBUILD for {name}")
    from ._fact import analyze_package_text

    return analyze_package_text(
        pkg_name=name,
        old_pkgbuild=None,
        new_pkgbuild=row["pkgbuild_text"],
        maintainer="",
        temporal=TemporalContext(source="corpus_depth"),
        depth=0,
        record=record,
    )


class _StoredFact:
    """The shape ``walk_dependencies`` reads, from a stored profile.

    A profile records the score and band, not the breakdown, so
    ``score_breakdown`` is empty and ``finding_count`` reads 0. The score and
    band are what a dependency card shows; the reader following the card runs
    ``inspect`` on the dependency for its findings.
    """

    __slots__ = ("final_score", "risk", "score_breakdown", "coverage_gaps")

    def __init__(self, final_score: int, risk: str):
        self.final_score = final_score
        self.risk = risk
        self.score_breakdown = ()
        self.coverage_gaps = ()


def _walk_corpus_dependencies(
    pkg_name, depth, config, seen, record: bool = False,
    added_names: set[str] | None = None,
):
    """The dependency closure, from results the corpus already has.

    ``seen`` is deliberately **not** shared across the packages of a corpus
    cycle. On the review path sharing it is a clear win: a handful of roots,
    each dependency cloned and analysed once. On the corpus path every
    package is a root, so a shared set would hand each dependency to
    whichever parent happened to be processed first and leave every other
    parent reporting an empty closure - an arbitrary attribution that reads
    as "this package has no AUR dependencies". Lookups are cheap enough that
    per-package walks are the right trade here.

    ``added_names`` is the same added-dependency set the review path uses to
    distinguish "not in the AUR" from "AUR package not reached".  Without it
    a depth ceiling can leave a newly added dependency unread while the
    report says the closure was complete.
    """
    from ...depth import DepthResult, default_metadata, resolve_depth, walk_dependencies

    resolved = resolve_depth(depth, config)
    provider = default_metadata()
    if resolved == 0:
        result = DepthResult()
    else:
        result = walk_dependencies(
            pkg_name,
            depth=resolved,
            metadata=provider,
            analyse=lambda name: _corpus_dependency_fact(name, record=record),
            already_seen=set(seen) if seen else None,
        )
    if added_names:
        reported = {report.name for report in result.reports}
        try:
            result.added_aur_unreported = any(
                name not in reported and provider.is_aur(name)
                for name in added_names
            )
        except Exception:
            log.debug("added-dependency metadata check failed", exc_info=True)
            result.metadata_unavailable = True
    result.metadata_unavailable = (
        result.metadata_unavailable
        or not getattr(provider, "available", True)
    )
    return result
