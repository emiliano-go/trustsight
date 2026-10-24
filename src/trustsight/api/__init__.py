"""The supported programmatic interface to TrustSight.

``trustsight inspect``, ``review``, ``full-aur --watch`` and the rest are
thin renderers over an engine that has no terminal in it.  This module is
that engine's front door: it runs the same flows, in the same order, with
the same defaults, and hands back plain dataclasses instead of printing.

Everything else under ``trustsight.`` is internal.  ``schema.PackageFact``,
``db``, ``analysis`` and ``full_aur`` change shape between releases without
notice; the names exported here do not, and anything they return can be
turned back into the exact JSON the corresponding ``--json`` flag emits via
``to_dict()``.

    from trustsight import TrustSight

    ts = TrustSight()
    report = ts.inspect("some-package")
    if report.flagged:
        print(report.verdict)
        for finding in report.findings:
            print(finding.rule_id, finding.description)

Two properties of the CLI that this interface keeps, because dropping them
would make a caller's result mean something different from the one a person
would see:

* **Coverage qualifies the verdict.**  ``Report.risk`` is the band the
  analysis actually supports, not a re-derivation from the score.  When the
  run could not read the whole change, ``coverage_gaps`` is non-empty and
  the band is downgraded.  Never re-derive a band from ``score``.
* **A failed analysis is a result, not a gap.**  ``ReviewResult.failures``
  lists the packages that could not be vetted.  A caller that iterates
  ``reports`` alone is looking at a partial review, so
  ``ReviewResult.complete`` says whether it was one.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Sequence
from ._models import (
    AcknowledgedUrl,
    ClusterFinding,
    CycleReport,
    FailedPackage,
    FileChange,
    Finding,
    HistoryEntry,
    PivotMatch,
    PivotResult,
    Progress,
    ProgressHook,
    Report,
    ReviewResult,
    Status,
    SuppressedRule,
    TrackedPackage,
    _evaluate_fact_dict_fallback,
)
from ._reports import (
    COVERAGE_GAP_REASONS,
    _LazyGapReasons,
    _body_source,
    _clean,
    _cycle_report,
    _evaluate_fact,
    _file_changes,
    _findings_from_breakdown,
    _findings_from_evaluation,
    _gap_reasons,
    _hook,
    _report_from_fact,
    _report_from_result,
    _suppressed,
)
from ._validation import (
    FLAG_THRESHOLD,
    MAX_API_HISTORY,
    MAX_API_NAME_BYTES,
    MAX_API_PACKAGES,
    MAX_API_REPOS,
    MAX_API_TEXT_BYTES,
    PackageNotFound,
    RISK_LEVELS,
    TrustSightError,
    _validate_limit,
    _validate_name,
    _validate_names,
    _validate_nonnegative,
    _validate_text,
)
from .client import (
    TrustSight,
)
from ..depth import DependencyReport

__all__ = [
    "TrustSight",
    "Report",
    "Finding",
    "FileChange",
    "SuppressedRule",
    "ReviewResult",
    "FailedPackage",
    "HistoryEntry",
    "TrackedPackage",
    "Status",
    "CycleReport",
    "ClusterFinding",
    "PivotResult",
    "PivotMatch",
    "Progress",
    "DependencyReport",
    "TrustSightError",
    "PackageNotFound",
    "FLAG_THRESHOLD",
    "RISK_LEVELS",
    "COVERAGE_GAP_REASONS",
    "MAX_API_PACKAGES",
    "MAX_API_HISTORY",
    "MAX_API_REPOS",
    "MAX_API_TEXT_BYTES",
    "MAX_API_NAME_BYTES",
]

