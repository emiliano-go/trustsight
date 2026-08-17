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
    "TrustSightError",
    "PackageNotFound",
    "FLAG_THRESHOLD",
    "RISK_LEVELS",
    "COVERAGE_GAP_REASONS",
]

# Bands, worst last.  ``Inconclusive`` is not on the scale: it is what a
# band becomes when the analysis could not support one.
RISK_LEVELS = ("Low", "Medium", "High", "Critical")

# Above this score the CLI counts a package as flagged in its summary line.
FLAG_THRESHOLD = 20
MAX_API_PACKAGES = 10_000
MAX_API_HISTORY = 10_000
MAX_API_REPOS = 256
MAX_API_TEXT_BYTES = 5 * 1024 * 1024
MAX_API_NAME_BYTES = 256


class TrustSightError(Exception):
    """Base class for every error this module raises deliberately."""


def _validate_limit(value: int, *, name: str, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if value < 0 or value > maximum:
        raise ValueError(f"{name} must be between 0 and {maximum}")


def _validate_nonnegative(value: int, *, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _validate_text(value: str, *, name: str, maximum: int = MAX_API_TEXT_BYTES) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} must be at most {maximum} UTF-8 bytes")


def _validate_name(value: str, *, name: str = "package") -> None:
    _validate_text(value, name=name, maximum=MAX_API_NAME_BYTES)
    if not value:
        raise ValueError(f"{name} must not be empty")


def _validate_names(value: Sequence[str], *, name: str, maximum: int) -> None:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{name} must be a sequence of strings")
    if len(value) > maximum:
        raise ValueError(f"{name} must contain at most {maximum} names")
    item_name = name[:-1] if name.endswith("s") else name
    for item in value:
        _validate_name(item, name=f"{item_name} name")


class PackageNotFound(TrustSightError):
    """The package is neither in the AUR nor in the local database."""

    def __init__(self, package: str):
        super().__init__(f"Package {package!r} not found in the AUR.")
        self.package = package


@dataclass(frozen=True)
class Progress:
    """One progress tick from a long-running flow.

    ``current`` is -1 when the phase changed but there is nothing countable
    yet (the AUR metadata download reports no total until it starts).
    """

    current: int
    total: int
    phase: str

    @property
    def indeterminate(self) -> bool:
        return self.current < 0 or not self.total


ProgressHook = Callable[[Progress], None]


@dataclass(frozen=True)
class Finding:
    """One rule that fired, with the evidence that made it fire."""

    rule_id: str
    severity: str
    weight: int
    description: str
    file: str = ""
    line: Optional[int] = None
    template: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class SuppressedRule:
    """A rule that matched but was silenced by an override.

    It contributed nothing to the score.  It is reported anyway: a
    suppression a caller cannot see is a suppression it cannot audit.
    """

    rule_id: str
    severity: str = ""
    override_reason: str = ""
    override_package: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FileChange:
    path: str
    status: str
    """One of "added", "removed", "modified"."""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Report:
    """The analysis of one package: what ``trustsight inspect`` shows."""

    package: str
    old_version: str = ""
    new_version: str = ""
    old_commit: str = ""
    new_commit: str = ""

    score: int = 0
    risk: str = ""
    """The band the analysis supports.  Use this, never ``risk_level(score)``."""
    risk_label: str = ""
    """``risk``, qualified in prose when coverage was incomplete."""
    verdict: str = ""
    """Plain-English summary.  Always ends with a direction to review."""

    findings: tuple[Finding, ...] = ()
    suppressed: tuple[SuppressedRule, ...] = ()
    changes: tuple[str, ...] = ()
    """What the diff did, whether or not a rule matched.  Context, not findings."""

    coverage_gaps: tuple[str, ...] = ()
    """Non-empty means part of the change was not read.  See ``COVERAGE_GAP_REASONS``."""

    file_changes: tuple[FileChange, ...] = ()
    added_urls: tuple[str, ...] = ()
    removed_urls: tuple[str, ...] = ()
    source_buckets: dict = field(default_factory=dict)
    checksum_behavior: str = ""
    resolved_commands: tuple[str, ...] = ()

    maintainer: str = ""
    previous_maintainer: str = ""
    maintainer_changed: bool = False

    dependency_changes: dict = field(default_factory=dict)

    first_seen: bool = False
    """No prior history: novelty signals carry no weight yet."""
    is_trivial: bool = False
    diff_truncated: bool = False
    tree_analyzed: bool = False
    version_comparison: str = ""
    """How the installed version relates to the AUR pkgver, or "" if nothing compared them."""
    adapter: str = "git"
    config_fingerprint: str = ""
    """Which rules, weights and overrides produced this.  Results are only
    comparable across runs with the same fingerprint."""

    dependencies: tuple = ()
    """Analysed AUR dependencies, each with its own score and band.

    Never folded into this package's ``score``: depth is not part of the
    config fingerprint, so a score that moved with ``--depth`` would break
    B1 for anyone comparing two runs.
    """
    depth_truncated: bool = False
    """The dependency walk stopped before the closure was exhausted."""

    required_by: tuple = ()
    """Packages in the reviewed set that declare this one as a dependency.

    The reverse of :attr:`dependencies`, and populated by
    ``review --deps``, where the subject of the report is a dependency and
    the useful question is who needs it. Empty on an ordinary review, where
    the subject is the thing that was asked for.
    """

    _raw: dict = field(default_factory=dict, repr=False, compare=False)
    _evaluated: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def flagged(self) -> bool:
        """True when the score clears the threshold the CLI summary counts."""
        return self.score > FLAG_THRESHOLD

    @property
    def flagged_dependencies(self) -> tuple:
        """Analysed dependencies that cleared the threshold on their own."""
        return tuple(d for d in self.dependencies if d.flagged)

    @property
    def fully_vetted(self) -> bool:
        """False when the run could not read the whole change."""
        return not self.coverage_gaps

    @property
    def comparable_versions(self) -> bool:
        """False for a VCS package, whose AUR pkgver is a build-time placeholder."""
        from .analysis.version import COMPARISON_INCONCLUSIVE

        return self.version_comparison != COMPARISON_INCONCLUSIVE

    @property
    def coverage_note(self) -> str:
        """The one-line caveat prefixed to the verdict, or "" when there is none."""
        from .coverage import describe

        return describe(list(self.coverage_gaps))

    @property
    def raw(self) -> dict:
        """The serialised ``PackageFact``, as stored in the database.

        This is the internal record, not the report: it uses the storage
        naming (``package_name``, ``final_score``) and always carries the
        score. Use :meth:`to_dict` for the body the CLI emits.
        """
        return dict(self._raw)

    def to_dict(self, *, include_score: bool = False, verbose: bool = False) -> dict:
        """The same JSON body ``trustsight review --json`` writes.

        Byte-for-byte the same key set as the CLI, and the same defaults:
        ``score``, ``risk`` and ``risk_label`` are withheld unless asked
        for, exactly as the CLI withholds them without ``--score`` or
        ``--risk``. ``include_score=True`` is this API's spelling of that
        flag, and ``verbose=True`` of ``--verbose``.

        Attribute access is a different act: ``report.score`` is always
        available, because reading a named field *is* the explicit request.
        What this method will not do is volunteer the number to a caller who
        only asked to serialise the result.
        """
        from .reporting import report_body

        return report_body(
            self._evaluated or _evaluate_fact_dict_fallback(self),
            include_score=include_score,
            verbose=verbose,
        )

    def to_json(self, indent: int | None = 2, **kwargs) -> str:
        return json.dumps(self.to_dict(**kwargs), indent=indent)


@dataclass(frozen=True)
class FailedPackage:
    """A package whose analysis raised.  It was NOT vetted."""

    package: str
    old_version: str = ""
    new_version: str = ""
    error: str = ""
    error_type: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ReviewResult:
    """The outcome of one ``review`` call."""

    reports: tuple[Report, ...] = ()
    failures: tuple[FailedPackage, ...] = ()
    total_installed: int = 0
    """Installed packages considered, whether or not they needed a review."""
    metadata_bootstrapped: bool = False
    """This call did nothing but download the first AUR metadata snapshot.
    There was no prior copy to diff against, so there is no delta yet; call
    ``review`` again."""

    @property
    def complete(self) -> bool:
        """False when at least one package could not be vetted."""
        return not self.failures

    @property
    def flagged(self) -> tuple[Report, ...]:
        return tuple(r for r in self.reports if r.flagged)

    def __iter__(self) -> Iterator[Report]:
        return iter(self.reports)

    def __len__(self) -> int:
        return len(self.reports)

    def to_dict(
        self, *, include_score: bool = False, verbose: bool = False,
    ) -> list[dict]:
        """The JSON list ``trustsight review --json`` writes.

        ``include_score=True`` corresponds to ``--score`` or ``--risk``;
        ``verbose=True`` corresponds to ``--verbose``.
        """
        from .reporting import report_body

        failures = [report_body({
            "package": failure.package,
            "old_version": failure.old_version,
            "new_version": failure.new_version,
            "verdict": (
                f"Analysis failed ({failure.error_type}): this package was NOT vetted."
            ),
            "failed": True,
        }, include_score=include_score, verbose=verbose) for failure in self.failures]
        return [
            report.to_dict(include_score=include_score, verbose=verbose)
            for report in self.reports
        ] + failures


@dataclass(frozen=True)
class HistoryEntry:
    timestamp: str
    old_version: str
    new_version: str
    score: int
    risk: str
    triggered_rules: tuple[dict, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TrackedPackage:
    name: str
    version: str
    last_checked: str
    score: Optional[int]
    risk: str
    maintainer: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Status:
    packages_tracked: int
    total_analyses: int
    effective_observations: int
    seed_observations: int
    dependency_corpus_loaded: bool
    config_dir: Path
    database_path: Path
    config_fingerprint: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["config_dir"] = str(self.config_dir)
        data["database_path"] = str(self.database_path)
        return data


@dataclass(frozen=True)
class ClusterFinding:
    """A corpus-wide pattern spanning several packages."""

    rule_id: str
    name: str
    severity: str
    match: str
    members: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class CycleReport:
    """One corpus cycle: what ``full-aur`` does once, or ``--watch`` repeats."""

    added: int = 0
    changed: int = 0
    removed: int = 0
    processed: int = 0
    bootstrap: bool = False
    elapsed: float = 0.0
    flagged: tuple[tuple[str, int], ...] = ()
    """``(package, score)`` for everything this cycle scored 40 or above, worst first."""
    cluster_findings: tuple[ClusterFinding, ...] = ()
    new_alerts: tuple[tuple[str, str], ...] = ()
    """``(package, rule_id)`` for clusters seen for the first time.  A cluster
    already reported on an earlier cycle is counted, not re-announced."""

    def to_dict(self) -> dict:
        return {
            "added": self.added,
            "changed": self.changed,
            "removed": self.removed,
            "processed": self.processed,
            "bootstrap": self.bootstrap,
            "elapsed": self.elapsed,
            "flagged": [list(f) for f in self.flagged],
            "cluster_findings": [c.to_dict() for c in self.cluster_findings],
            "new_alerts": [list(a) for a in self.new_alerts],
        }


@dataclass(frozen=True)
class PivotMatch:
    package: str
    surface: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class PivotResult:
    """Which corpus packages reference one indicator.

    The match is exact and reads only stored corpus material, never the
    network.  An empty ``matches`` means the corpus holds no reference, not
    that the indicator is harmless; if ``sources`` is empty there was no
    corpus to search at all.
    """

    indicator: str
    type: str
    listed: bool = False
    confidence: str = ""
    matches: tuple[PivotMatch, ...] = ()
    sources: tuple[str, ...] = ()

    @property
    def searched(self) -> bool:
        return bool(self.sources)

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "type": self.type,
            "listed": self.listed,
            "confidence": self.confidence,
            "matches": [m.to_dict() for m in self.matches],
            "sources": list(self.sources),
        }


def _gap_reasons() -> dict:
    from .coverage import GAP_REASONS

    return dict(GAP_REASONS)


class _LazyGapReasons(dict):
    """``COVERAGE_GAP_REASONS`` without importing coverage at module import."""

    def _load(self):
        if not dict.__len__(self):
            self.update(_gap_reasons())
        return self

    def __getitem__(self, key):
        return dict.__getitem__(self._load(), key)

    def get(self, key, default=None):
        return dict.get(self._load(), key, default)

    def __iter__(self):
        return dict.__iter__(self._load())

    def __len__(self):
        return dict.__len__(self._load())

    def items(self):
        return dict.items(self._load())

    def keys(self):
        return dict.keys(self._load())

    def values(self):
        return dict.values(self._load())


COVERAGE_GAP_REASONS = _LazyGapReasons()
"""Gap identifier -> the plain-English reason a run could not read something."""


def _hook(callback: Optional[ProgressHook]):
    """Adapt a ``Progress`` hook to the engine's ``(cur, total, phase)`` form."""
    if callback is None:
        return None

    def _cb(current: int, total: int, phase: str) -> None:
        callback(Progress(current=current, total=total, phase=phase))

    return _cb


def _findings_from_breakdown(fact) -> tuple[Finding, ...]:
    return _findings_from_evaluation(_evaluate_fact(fact))


def _findings_from_evaluation(evaluated: dict) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            rule_id=row["rule_id"],
            severity=row["severity"],
            weight=row["weight"],
            description=row["description"],
            file=row["file"],
            line=row["line"],
            template=row["template"],
            evidence=row["evidence"],
        )
        for row in evaluated["findings"]
    )


def _evaluate_fact(fact) -> dict:
    from .reporting import evaluate_fact

    return evaluate_fact(fact)


def _suppressed(rows: Sequence[dict]) -> tuple[SuppressedRule, ...]:
    return tuple(
        SuppressedRule(
            rule_id=r.get("rule_id", ""),
            severity=r.get("severity", ""),
            override_reason=r.get("override_reason", ""),
            override_package=r.get("override_package"),
        )
        for r in rows or ()
    )


def _file_changes(rows: Sequence[dict]) -> tuple[FileChange, ...]:
    return tuple(
        FileChange(path=r.get("path", ""), status=r.get("status", ""))
        for r in rows or ()
    )


def _body_source(evaluated: dict, *, row: Optional[dict]) -> dict:
    """The evaluated dict as ``report_body`` wants it.

    ``failed`` lives on a review row rather than on a fact - a fact exists
    only when the analysis produced one - so it is folded in here. Nothing
    else is transformed: the whole point is that one dict feeds every
    surface.
    """
    source = dict(evaluated)
    source.pop("fact", None)
    if row is not None:
        source["failed"] = bool(row.get("failed", False))
    source.setdefault("failed", False)
    return source


def _evaluate_fact_dict_fallback(report: "Report") -> dict:
    """An evaluated dict rebuilt from a Report's own fields.

    Only reached for a Report constructed directly rather than by one of the
    builders above, which is a thing callers and tests do. Rebuilt rather
    than refused so ``to_dict()`` never raises on a hand-made object.
    """
    return {
        "package": report.package,
        "old_version": report.old_version,
        "new_version": report.new_version,
        "old_commit": report.old_commit,
        "new_commit": report.new_commit,
        "version_comparison": report.version_comparison,
        "verdict": report.verdict,
        "score": report.score,
        "risk": report.risk,
        "risk_label": report.risk_label,
        "findings": [
            {
                "rule_id": f.rule_id, "severity": f.severity, "weight": f.weight,
                "file": f.file, "line": f.line, "description": f.description,
                "template": f.template, "evidence": dict(f.evidence),
            }
            for f in report.findings
        ],
        "suppressed_rules": [s.to_dict() for s in report.suppressed],
        "changes": list(report.changes),
        "coverage_gaps": list(report.coverage_gaps),
        "file_changes": [c.to_dict() for c in report.file_changes],
        "ioc_matches": list(report._raw.get("ioc_matches", ())),
        "first_seen": report.first_seen,
        "is_trivial": report.is_trivial,
        "diff_truncated": report.diff_truncated,
        "failed": False,
        "config_fingerprint": report.config_fingerprint,
        "raw": dict(report._raw),
    }


def _report_from_fact(fact) -> Report:
    """Build a Report from an internal PackageFact."""
    evaluated = _evaluate_fact(fact)
    findings = _findings_from_evaluation(evaluated)
    raw = evaluated["raw"]

    return Report(
        package=evaluated["package"],
        old_version=evaluated["old_version"],
        new_version=evaluated["new_version"],
        old_commit=evaluated["old_commit"],
        new_commit=evaluated["new_commit"],
        score=evaluated["score"],
        risk=evaluated["risk"],
        risk_label=evaluated["risk_label"],
        verdict=evaluated["verdict"],
        findings=findings,
        suppressed=_suppressed(evaluated["suppressed_rules"]),
        changes=tuple(evaluated["changes"]),
        coverage_gaps=tuple(evaluated["coverage_gaps"]),
        file_changes=_file_changes(evaluated["file_changes"]),
        added_urls=tuple(fact.source_changes.added_urls),
        removed_urls=tuple(fact.source_changes.removed_urls),
        source_buckets=dict(fact.source_buckets),
        checksum_behavior=fact.source_changes.checksum_behavior,
        resolved_commands=tuple(fact.execution_changes.resolved_commands),
        maintainer=fact.current_maintainer,
        previous_maintainer=fact.previous_maintainer,
        maintainer_changed=fact.maintainer_changed,
        dependency_changes={k: sorted(v) for k, v in fact.dependency_changes.items()},
        dependencies=tuple(getattr(fact, "dependencies", ())),
        depth_truncated=bool(getattr(fact, "depth_truncated", False)),
        required_by=tuple(raw.get("required_by", ()) if raw else ()),
        first_seen=fact.first_seen,
        is_trivial=evaluated["is_trivial"],
        diff_truncated=evaluated["diff_truncated"],
        tree_analyzed=fact.tree_analyzed,
        version_comparison=evaluated["version_comparison"],
        adapter=fact.adapter,
        config_fingerprint=evaluated["config_fingerprint"],
        _raw=raw,
        _evaluated=_body_source(evaluated, row=None),
    )


def _report_from_result(row: dict) -> Report:
    """Build a Report from a review-engine result dict.

    When the row carries the underlying fact, the report is built from it,
    so a report from ``review`` and one from ``inspect`` describe the same
    package identically.  The versions still come from the row: ``review``
    compares what pacman has installed against what the AUR advertises,
    which is not the same pair the fact holds.
    """
    fact = row.get("_verbose_fact")
    if fact is not None:
        report = _report_from_fact(fact)
        raw = dict(report._raw)
        raw["old_version"] = row.get("old_version", "")
        raw["new_version"] = row.get("new_version", "")
        evaluated = dict(report._evaluated)
        evaluated["old_version"] = row.get("old_version", "")
        evaluated["new_version"] = row.get("new_version", "")
        evaluated["failed"] = bool(row.get("failed", False))
        # `--deps` is a property of the run, not of the fact: the fact knows
        # what this package depends on, and the row knows who depends on it.
        evaluated["required_by"] = list(row.get("required_by", ()))
        raw["required_by"] = list(row.get("required_by", ()))
        return replace(
            report,
            old_version=row.get("old_version", ""),
            new_version=row.get("new_version", ""),
            required_by=tuple(row.get("required_by", ())),
            _raw=raw,
            _evaluated=evaluated,
        )

    from .reporting import evaluate_review_row

    evaluated = evaluate_review_row(row)
    findings = _findings_from_evaluation(evaluated)
    raw = evaluated["raw"]
    return Report(
        package=evaluated["package"],
        old_version=evaluated["old_version"],
        new_version=evaluated["new_version"],
        score=evaluated["score"],
        risk=evaluated["risk"],
        risk_label=evaluated["risk_label"],
        verdict=evaluated["verdict"],
        findings=findings,
        suppressed=_suppressed(evaluated["suppressed_rules"]),
        changes=tuple(evaluated["changes"]),
        coverage_gaps=tuple(evaluated["coverage_gaps"]),
        file_changes=_file_changes(evaluated["file_changes"]),
        first_seen=evaluated["first_seen"],
        is_trivial=evaluated["is_trivial"],
        diff_truncated=evaluated["diff_truncated"],
        version_comparison=evaluated["version_comparison"],
        required_by=tuple(evaluated.get("required_by", ())),
        _raw=raw,
        _evaluated=_body_source(evaluated, row=row),
    )


def _cycle_report(result) -> CycleReport:
    return CycleReport(
        added=result.added,
        changed=result.changed,
        removed=result.removed,
        processed=result.processed,
        bootstrap=result.bootstrap,
        elapsed=result.elapsed,
        flagged=tuple((name, score) for name, score in result.flagged),
        cluster_findings=tuple(
            ClusterFinding(
                rule_id=f.get("rule_id", ""),
                name=f.get("name", ""),
                severity=f.get("severity", ""),
                match=f.get("match", ""),
                members=tuple(f.get("params", {}).get("members", ())),
            )
            for f in result.cluster_findings
        ),
        new_alerts=tuple((p, r) for p, r in result.new_alerts),
    )


class TrustSight:
    """A configured TrustSight instance.

    Construction does no I/O.  The config directory, the database and the
    bundled seed are prepared on the first call that needs them, so a
    process that builds one of these and never uses it pays nothing.

    :param auto_import_seed: whether to import the bundled observation seed
        on first use.  ``None`` (the default) follows ``seed.auto_import``
        in the config file, which is what the CLI does.  Set ``False`` to
        run against a cold database on purpose; note that a cold database
        makes every novelty signal meaningless, and TrustSight reports the
        band as ``Inconclusive`` rather than pretending otherwise.
    """

    def __init__(self, *, auto_import_seed: Optional[bool] = None):
        self._auto_import_seed = auto_import_seed
        self._ready = False

    # -- lifecycle ---------------------------------------------------

    def _ensure_ready(self, quiet: bool = True) -> None:
        if self._ready:
            return
        from .config import ensure_default_configs, load_config
        from .db import init_db, maybe_auto_import_seed

        ensure_default_configs()
        init_db()
        wanted = self._auto_import_seed
        if wanted is None:
            wanted = load_config().get("seed", {}).get("auto_import", True)
        if wanted:
            maybe_auto_import_seed(quiet=quiet)
        self._ready = True

    def close(self) -> None:
        """Release the database connections held by this thread.

        Not required for a short-lived process; useful in a long-running
        one, or in tests that swap the database out underneath.
        """
        from .db import close_connections

        close_connections()

    def __enter__(self) -> "TrustSight":
        self._ensure_ready()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- introspection -----------------------------------------------

    @property
    def config_dir(self) -> Path:
        from .config import CONFIG_DIR

        return CONFIG_DIR

    @property
    def database_path(self) -> Path:
        from .db import get_db_path

        return get_db_path()

    @property
    def config_fingerprint(self) -> str:
        """Identifies the rules, weights and overrides in force.

        Two reports are only comparable when their fingerprints match.
        """
        from .config import config_fingerprint

        self._ensure_ready()
        return config_fingerprint()

    def config(self) -> dict:
        """The effective configuration, defaults merged with the user's file."""
        from .config import load_config

        self._ensure_ready()
        return load_config()

    def status(self) -> Status:
        """Database and corpus health: what ``trustsight status`` reports."""
        from .config import config_fingerprint
        from .db import (
            count_observations,
            dependency_table_populated,
            effective_observation_count,
            get_all_packages,
            seed_observation_count,
        )

        self._ensure_ready()
        return Status(
            packages_tracked=len(get_all_packages()),
            total_analyses=count_observations(),
            effective_observations=effective_observation_count(),
            seed_observations=seed_observation_count(),
            dependency_corpus_loaded=dependency_table_populated(),
            config_dir=self.config_dir,
            database_path=self.database_path,
            config_fingerprint=config_fingerprint(),
        )

    # -- analysis ----------------------------------------------------

    def inspect(self, package: str, *, check_aur: bool = True,
                depth: Optional[int] = None) -> Report:
        """Analyse one package: what ``trustsight inspect`` shows.

        Fetches the package's AUR git repository, diffs it against the last
        state this database saw, runs every rule, and records the run as an
        observation, which is what makes the *next* call's novelty signals
        mean anything.

        :param check_aur: verify the package exists before analysing.  Set
            ``False`` to skip the RPC round trip when you already know it
            does; analysis of a name that does not exist then returns a
            first-seen report with nothing in it rather than raising.
        :param depth: AUR dependency levels to analyse: ``0`` off, ``1``
            (the default) direct dependencies, ``n`` levels, ``-1`` every
            level, bounded by ``depth.MAX_DEPTH_LEVELS`` and
            ``depth.MAX_DEPTH_NODES``.  ``None`` uses ``[depth] levels`` from
            the config.  Each dependency is a full analysis with its own
            score on ``Report.dependencies``; none of it moves this
            report's ``score``.
        :raises PackageNotFound: the name is in neither the AUR nor the
            local database.
        """
        from .analysis import analyze_package

        _validate_name(package)
        self._ensure_ready()

        if check_aur:
            from .db import get_package
            from .discovery import get_aur_package_info

            if package not in get_aur_package_info([package]) and get_package(package) is None:
                raise PackageNotFound(package)

        return _report_from_fact(analyze_package(package, depth=depth))

    def analyze_text(
        self,
        package: str,
        new_pkgbuild: str,
        old_pkgbuild: Optional[str] = None,
        *,
        maintainer: str = "",
        srcinfo: Optional[str] = None,
        last_modified: Optional[int] = None,
        first_submitted: Optional[int] = None,
        previous_modified: Optional[int] = None,
    ) -> Report:
        """Analyse PKGBUILD text directly, with no git and no network.

        For vetting a PKGBUILD you already hold: a pull request, a
        generated file, a CI checkout.  Nothing is fetched and nothing is
        recorded as an observation, so the novelty signals see only what
        the database already knew.

        The timestamps are optional and are Unix seconds.  Without them the
        age-based rules have no clock and stay silent, which is why
        ``Report.adapter`` reads ``corpus`` here: this is a narrower look at
        the package than :meth:`inspect` gets.
        """
        from .full_aur.analyze import analyze_package_text
        from .schema import TemporalContext

        _validate_name(package)
        _validate_text(new_pkgbuild, name="new_pkgbuild")
        if old_pkgbuild is not None:
            _validate_text(old_pkgbuild, name="old_pkgbuild")
        _validate_text(maintainer, name="maintainer", maximum=MAX_API_NAME_BYTES)
        if srcinfo is not None:
            _validate_text(srcinfo, name="srcinfo")
        self._ensure_ready()
        fact = analyze_package_text(
            pkg_name=package,
            old_pkgbuild=old_pkgbuild,
            new_pkgbuild=new_pkgbuild,
            maintainer=maintainer,
            temporal=TemporalContext(
                last_modified=last_modified,
                first_seen=first_submitted,
                previous_modified=previous_modified,
                source="caller" if last_modified is not None else "unknown",
            ),
            srcinfo=srcinfo,
        )
        return _report_from_fact(fact)

    def review(
        self,
        *,
        packages: Optional[Sequence[str]] = None,
        limit: int = 0,
        repos: Optional[Sequence[str]] = None,
        foreign: bool = False,
        all_repos: bool = False,
        all_packages: bool = False,
        on_progress: Optional[ProgressHook] = None,
        on_warning: Optional[Callable[[str], None]] = None,
        depth: Optional[int] = None,
        deps: bool = False,
    ) -> ReviewResult:
        """Review installed AUR packages: what ``trustsight review`` does.

        With no arguments this discovers installed foreign packages, works
        out which have a newer version in the AUR, and analyses those.
        Pass *packages* to review an explicit list instead and skip
        discovery entirely.

        The very first call with no local AUR metadata snapshot downloads
        one and returns ``metadata_bootstrapped=True`` with no reports:
        there was no prior snapshot to diff against, so there is no delta
        to report yet.  Call again.

        :param limit: analyse at most this many packages (0 = no limit).
        :param repos: local repositories to scan, by name.
        :param foreign: include packages ``pacman -Qm`` reports.
        :param all_repos: auto-detect local repos from ``pacman.conf``.
        :param all_packages: review every discovered package, not only the
            ones with a newer AUR version.
        :param deps: review the AUR *dependencies* of the discovered
            packages instead of the packages themselves, as
            ``review --deps`` does.  Each report then carries
            :attr:`Report.required_by`.  Honours *depth* as the number of
            dependency levels to review.
        """
        from .review import analyze_outdated_batch, dependency_entries, discover_packages

        _validate_limit(limit, name="limit", maximum=MAX_API_PACKAGES)
        if packages is not None:
            _validate_names(packages, name="packages", maximum=MAX_API_PACKAGES)
        if repos is not None:
            _validate_names(repos, name="repos", maximum=MAX_API_REPOS)

        self._ensure_ready()

        total_installed = 0
        if packages is not None:
            entries = [{"name": name, "current_version": ""} for name in packages]
        else:
            repos = list(repos or [])
            include_foreign = foreign
            if not repos and not all_repos and not foreign:
                discovery = self.config().get("discovery", {})
                repos = list(discovery.get("default_repos", []))
                include_foreign = discovery.get("include_foreign", False)
                all_repos = discovery.get("all_repos", False)
                if not repos and not all_repos and not include_foreign:
                    include_foreign = True

            discovered, total_installed = discover_packages(
                repos=repos,
                include_foreign=include_foreign,
                all_repos=all_repos,
                all_packages=all_packages,
                on_warn=on_warning,
            )
            if discovered is None:
                return ReviewResult(metadata_bootstrapped=True)
            entries = discovered

        required_by: dict[str, list[str]] = {}
        if deps:
            entries, required_by, _note = dependency_entries(
                entries, depth, self.config(), on_warning
            )
            # The dependencies are the subject now, so their own closure is
            # not walked again underneath them.
            depth = 0

        if limit:
            entries = entries[:limit]
        if not entries:
            return ReviewResult(total_installed=total_installed)

        # verbose=True keeps the underlying fact on each row, which is what
        # lets a review report carry everything an inspect report does.
        rows = analyze_outdated_batch(entries, _hook(on_progress), verbose=True,
                                      depth=depth)

        # Same field on every surface: the CLI attaches this to the row it
        # renders and serialises, so the API attaches it to the row it turns
        # into a Report.
        for row in rows:
            row["required_by"] = list(required_by.get(row.get("package"), ()))

        reports, failures = [], []
        for row in rows:
            if row.get("failed"):
                failures.append(FailedPackage(
                    package=row["package"],
                    old_version=row.get("old_version", ""),
                    new_version=row.get("new_version", ""),
                    error=row.get("error", ""),
                    error_type=row.get("error_type", ""),
                ))
            else:
                reports.append(_report_from_result(row))

        return ReviewResult(
            reports=tuple(reports),
            failures=tuple(failures),
            total_installed=total_installed,
        )

    # -- corpus ------------------------------------------------------

    def refresh_corpus(
        self,
        *,
        bootstrap: bool = False,
        resume: bool = False,
        export_path: Optional[str] = None,
        sign_key: Optional[str] = None,
    ) -> CycleReport:
        """Run one full-AUR corpus cycle: what ``trustsight full-aur`` does.

        Refreshes the AUR metadata snapshot, analyses what changed since
        the stored copy, runs the corpus-wide sweep and records the
        adoption feed. ``bootstrap=True`` permits the initial whole-AUR
        build when no snapshot exists; it takes hours. ``resume=True``
        continues an interrupted build.
        """
        from .full_aur.pipeline import run_baseline_build

        self._ensure_ready()
        return _cycle_report(run_baseline_build(
            bootstrap=bootstrap, resume=resume, export_path=export_path, sign_key=sign_key,
        ))

    def watch(
        self,
        *,
        interval: Optional[int] = None,
        cycles: int = 0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Iterator[CycleReport]:
        """Yield one ``CycleReport`` per corpus cycle, forever by default.

        This is ``trustsight full-aur --watch`` as a generator: each cycle
        is exactly what :meth:`refresh_corpus` does once, and the loop adds
        repetition plus memory.  A cluster appears in ``new_alerts`` the
        first time it is seen and is then counted, not re-announced, so a
        quiet cycle yields a report with nothing new in it rather than the
        same forty-package adoption again.

        The generator sleeps between cycles, so it blocks the calling
        thread; stop it by breaking out of the loop or closing it.  State
        is durable at every yield: each cycle saves the snapshot and the
        resume file before it returns.

        :param interval: seconds between cycles.  ``None`` uses
            ``limits.watch_interval`` (3600).  Values below
            ``limits.watch_min_interval`` (60) are clamped up: a shorter
            interval only re-downloads a snapshot the AUR has not
            regenerated yet.
        :param cycles: stop after this many cycles (0 = until the caller
            stops iterating).
        """
        if interval is not None:
            _validate_nonnegative(interval, name="interval")
        _validate_nonnegative(cycles, name="cycles")

        def _run() -> Iterator[CycleReport]:
            from .full_aur.pipeline import run_baseline_build, watch_interval_seconds

            self._ensure_ready()
            delay = watch_interval_seconds(interval)
            count = 0
            while True:
                yield _cycle_report(run_baseline_build())
                count += 1
                if cycles and count >= cycles:
                    return
                sleep(delay)

        return _run()

    def import_baseline(self, path: str | Path, *, allow_unsigned: bool = False) -> None:
        """Import a signed baseline corpus artifact.

        Unsigned artifacts are rejected unless *allow_unsigned* is set,
        which is for local builds only: an unsigned baseline is data of
        unknown provenance being written into the database that every
        subsequent novelty judgement reads.
        """
        from .full_aur.export import import_baseline

        self._ensure_ready()
        import_baseline(str(path), allow_unsigned=allow_unsigned)

    def pivot(self, indicator: str, *, type: Optional[str] = None) -> PivotResult:
        """Find every corpus package referencing *indicator*.

        The inverse of a per-package finding: given a package name, domain
        or artifact hash, which packages touch it.  Reads only stored
        corpus material, never the network.

        :param type: force the indicator type (``package``, ``domain`` or
            ``hash``) when the shape is ambiguous.
        :raises TrustSightError: the indicator type is unknown or the
            indicator could not be classified.
        """
        from .full_aur.pivot import pivot as _pivot
        from .iocs import IOC_TYPES

        _validate_text(indicator, name="indicator", maximum=MAX_API_NAME_BYTES)
        if not indicator:
            raise ValueError("indicator must not be empty")
        self._ensure_ready()
        if type is not None and type not in IOC_TYPES:
            raise TrustSightError(
                f"unknown indicator type {type!r}; expected one of "
                f"{', '.join(sorted(IOC_TYPES))}"
            )
        result = _pivot(indicator, type=type)
        if result.get("error"):
            raise TrustSightError(result["error"])
        return PivotResult(
            indicator=result["indicator"],
            type=result["type"],
            listed=result.get("listed", False),
            confidence=result.get("confidence") or "",
            matches=tuple(
                PivotMatch(
                    package=m.get("package", ""),
                    surface=m.get("surface", ""),
                    detail=m.get("detail", ""),
                )
                for m in result.get("matches", [])
            ),
            sources=tuple(result.get("sources", [])),
        )

    # -- stored state ------------------------------------------------

    def history(
        self,
        package: str,
        *,
        limit: int = 20,
        with_rules: bool = False,
    ) -> list[HistoryEntry]:
        """Past analyses of *package*, newest first.

        Returns an empty list when the package has never been analysed:
        that is a fact about this database, not an error.
        """
        from .db import get_history, get_package_id, get_triggered_rules
        from .scoring import stored_band
        from .verdict import display_version

        _validate_limit(limit, name="limit", maximum=MAX_API_HISTORY)
        self._ensure_ready()
        pkg_id = get_package_id(package)
        if pkg_id is None:
            return []

        entries = []
        for row in get_history(pkg_id, limit=limit):
            rules = tuple(get_triggered_rules(row["id"])) if with_rules else ()
            entries.append(HistoryEntry(
                timestamp=row.get("timestamp", ""),
                old_version=display_version(row.get("old_version")),
                new_version=display_version(row.get("new_version")),
                score=row.get("final_score", 0),
                risk=stored_band(row)[0],
                triggered_rules=rules,
            ))
        return entries

    def packages(self, *, limit: int = 0) -> list[TrackedPackage]:
        """Every package in the database with its latest score.

        What ``trustsight list`` shows.
        """
        from .db import get_all_packages, get_last_analysis
        from .scoring import stored_band
        from .verdict import display_version

        _validate_limit(limit, name="limit", maximum=MAX_API_PACKAGES)
        self._ensure_ready()
        rows = get_all_packages()
        if limit:
            rows = rows[:limit]

        out = []
        for pkg in rows:
            last = get_last_analysis(pkg["id"])
            score = last["final_score"] if last else None
            out.append(TrackedPackage(
                name=pkg["name"],
                version=display_version(pkg.get("current_version")),
                last_checked=pkg["last_checked"] or "",
                score=score,
                risk=stored_band(last, score)[0] if last else "",
                maintainer=pkg["current_maintainer"] or "",
            ))
        return out

    def forget(self, *packages: str) -> dict[str, dict]:
        """Delete tracked packages and all their history.

        Returns ``{package: {table: rows_deleted}}``.  A package that was
        not tracked maps to an empty dict.  This is not reversible: the
        observations it removes are what the novelty signals count.
        """
        from .db import forget_package

        self._ensure_ready()
        results: dict[str, dict] = {}
        for name in packages:
            try:
                results[name] = forget_package(name)
            except ValueError as exc:
                raise TrustSightError(str(exc)) from exc
        return results

    def prune(self, *, dry_run: bool = False) -> dict[str, dict]:
        """Forget every tracked package that no longer exists in the AUR.

        Set *dry_run* to see what would go without deleting it.

        :raises TrustSightError: the AUR RPC returned nothing, so which
            packages still exist could not be determined.  Deleting on that
            answer would forget the whole database over a network blip.
        """
        from .db import forget_prune, get_all_packages
        from .discovery import get_aur_package_info

        self._ensure_ready()
        names = [p["name"] for p in get_all_packages()]
        if not names:
            return {}
        aur_names = set(get_aur_package_info(names))
        if not aur_names:
            raise TrustSightError(
                "AUR RPC returned no data; cannot determine which packages "
                "still exist. Check your network connection and try again."
            )
        return forget_prune(aur_names, dry_run=dry_run)
